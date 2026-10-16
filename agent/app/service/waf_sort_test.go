package service

import (
	"strings"
	"testing"
	"time"

	"github.com/3panel-dev/3panel/agent/app/dto/request"
	"github.com/3panel-dev/3panel/agent/app/model"
	"github.com/3panel-dev/3panel/agent/global"
)

// 排序能力的回归测试。上一版只有 created_at 一个维度，
// 排序列直接由前端控制 —— 那是 SQL 注入面，必须锁死白名单。

func TestWAFLogOrderColumnWhitelist(t *testing.T) {
	cases := []struct {
		orderBy string
		wantCol string
	}{
		{"", "created_at"}, // 缺省
		{"created_at", "created_at"},
		{"ip", "ip"},
		{"attack_type", "attack_type"},
		{"duration_ms", "duration_ms"},
		{"action", "action"},
		{"path", "path"},
	}
	for _, c := range cases {
		got := wafLogOrder(request.WAFLogSearch{OrderBy: c.orderBy, Order: "asc"})
		if !strings.HasPrefix(got, c.wantCol+" ") {
			t.Errorf("orderBy=%q 应排 %q，实际 %q", c.orderBy, c.wantCol, got)
		}
	}
}

func TestWAFLogOrderRejectsUnknownColumn(t *testing.T) {
	// 排序字符串会被拼进 SQL ORDER BY，未知列必须退回默认值而不是原样透传。
	// 这条是防注入的核心断言。
	attacks := []string{
		"created_at; DROP TABLE waf_logs",
		"id",
		"(SELECT 1)",
		"created_at, id",
		"1",
	}
	for _, a := range attacks {
		got := wafLogOrder(request.WAFLogSearch{OrderBy: a})
		if !strings.HasPrefix(got, "created_at ") {
			t.Errorf("orderBy=%q 必须退回 created_at，实际 %q", a, got)
		}
		if strings.Contains(got, "DROP") || strings.Contains(got, "SELECT") {
			t.Errorf("orderBy=%q 的注入片段泄漏进了 ORDER BY: %q", a, got)
		}
	}
}

func TestWAFLogOrderDirection(t *testing.T) {
	if got := wafLogOrder(request.WAFLogSearch{OrderBy: "ip", Order: "asc"}); !strings.Contains(got, " asc") {
		t.Errorf("order=asc 应生成升序，实际 %q", got)
	}
	// 方向只认 asc，其余一律 desc —— "ASC" 大写也要认，"desc;--" 必须被降级
	for _, o := range []string{"desc", "DESC", "Desc", "", "asc; --", "desc, (select 1)"} {
		got := wafLogOrder(request.WAFLogSearch{OrderBy: "ip", Order: o})
		if !strings.Contains(got, " desc") {
			t.Errorf("order=%q 应按降序处理，实际 %q", o, got)
		}
	}
	// 大写 ASC 也应识别为升序
	if got := wafLogOrder(request.WAFLogSearch{OrderBy: "ip", Order: "ASC"}); !strings.Contains(got, " asc") {
		t.Errorf("order=ASC 应识别为升序，实际 %q", got)
	}
}

// created_at 是秒级精度，同一秒插入的多条记录若没有次级排序键，
// 翻页时同一条会在两页各出现一次（用户看到"记录重复"）。
func TestWAFLogOrderHasStableTieBreaker(t *testing.T) {
	for _, col := range []string{"", "ip", "attack_type", "duration_ms"} {
		got := wafLogOrder(request.WAFLogSearch{OrderBy: col, Order: "desc"})
		if !strings.Contains(got, "id desc") {
			t.Errorf("orderBy=%q 的排序缺少 id 次级键，分页会不稳定: %q", col, got)
		}
	}
}

// 排序必须真正生效，而不是只拼对字符串。
func TestWAFSearchLogsSortByIP(t *testing.T) {
	setupWAFTestDB(t)
	base := time.Now().Add(-time.Hour)
	seed := []model.WAFLog{
		{WebsiteID: 1, AttackType: "sqli", Action: model.WAFActionDeny, IP: "3.3.3.3", CreatedAt: base},
		{WebsiteID: 1, AttackType: "xss", Action: model.WAFActionDeny, IP: "1.1.1.1", CreatedAt: base},
		{WebsiteID: 1, AttackType: "rce", Action: model.WAFActionDeny, IP: "2.2.2.2", CreatedAt: base},
	}
	if err := global.DB.Create(&seed).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}
	svc := WAFService{}

	// 三条 created_at 完全相同，只能靠次级键区分 —— 排序方向必须体现在结果里
	_, asc, err := svc.SearchLogs(request.WAFLogSearch{
		Page: 1, PageSize: 10, OrderBy: "ip", Order: "asc",
	})
	if err != nil {
		t.Fatalf("asc: %v", err)
	}
	if len(asc) != 3 {
		t.Fatalf("应有 3 条，实际 %d", len(asc))
	}
	if asc[0].IP != "1.1.1.1" || asc[2].IP != "3.3.3.3" {
		t.Errorf("升序结果错位: %s %s %s", asc[0].IP, asc[1].IP, asc[2].IP)
	}

	_, desc, err := svc.SearchLogs(request.WAFLogSearch{
		Page: 1, PageSize: 10, OrderBy: "ip", Order: "desc",
	})
	if err != nil {
		t.Fatalf("desc: %v", err)
	}
	if desc[0].IP != "3.3.3.3" || desc[2].IP != "1.1.1.1" {
		t.Errorf("降序结果错位: %s %s %s", desc[0].IP, desc[1].IP, desc[2].IP)
	}
}

func TestWAFSearchLogsSortByAttackType(t *testing.T) {
	setupWAFTestDB(t)
	base := time.Now().Add(-time.Hour)
	seed := []model.WAFLog{
		{WebsiteID: 1, AttackType: "sqli", Action: model.WAFActionDeny, IP: "1.1.1.1", CreatedAt: base},
		{WebsiteID: 1, AttackType: "xss", Action: model.WAFActionDeny, IP: "1.1.1.1", CreatedAt: base},
		{WebsiteID: 1, AttackType: "lfi", Action: model.WAFActionDeny, IP: "1.1.1.1", CreatedAt: base},
	}
	if err := global.DB.Create(&seed).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}
	_, logs, err := WAFService{}.SearchLogs(request.WAFLogSearch{
		Page: 1, PageSize: 10, OrderBy: "attack_type", Order: "asc",
	})
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	got := []string{logs[0].AttackType, logs[1].AttackType, logs[2].AttackType}
	want := []string{"lfi", "sqli", "xss"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("按攻击类型升序应得 %v，实际 %v", want, got)
		}
	}
}

// 缺省排序必须是时间倒序：这是运维查看攻击日志的默认视角。
func TestWAFSearchLogsDefaultOrderIsNewestFirst(t *testing.T) {
	setupWAFTestDB(t)
	now := time.Now()
	seed := []model.WAFLog{
		{WebsiteID: 1, AttackType: "sqli", Action: model.WAFActionDeny, IP: "1.1.1.1", Path: "/old", CreatedAt: now.Add(-2 * time.Hour)},
		{WebsiteID: 1, AttackType: "sqli", Action: model.WAFActionDeny, IP: "1.1.1.1", Path: "/new", CreatedAt: now},
	}
	if err := global.DB.Create(&seed).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}
	_, logs, err := WAFService{}.SearchLogs(request.WAFLogSearch{Page: 1, PageSize: 10})
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	if logs[0].Path != "/new" {
		t.Errorf("缺省排序应是时间倒序（最新在前），实际首条 %q", logs[0].Path)
	}
}
