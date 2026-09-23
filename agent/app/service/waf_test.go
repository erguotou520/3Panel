package service

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/3panel-dev/3panel/agent/app/dto/request"
	"github.com/3panel-dev/3panel/agent/app/model"
	"github.com/3panel-dev/3panel/agent/global"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

func setupWAFTestDB(t *testing.T) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	for _, m := range []interface{}{&model.WAFRule{}, &model.WAFCCConfig{}, &model.WAFOption{}, &model.WAFLog{}} {
		if err := db.AutoMigrate(m); err != nil {
			t.Fatalf("migrate: %v", err)
		}
	}
	global.DB = db
}

func seedWAFLogs(t *testing.T) {
	t.Helper()
	logs := []model.WAFLog{
		{WebsiteID: 1, WebsiteName: "a.com", AttackType: "sqli", Action: model.WAFActionDeny, IP: "1.1.1.1", Method: "GET", Path: "/login", UserAgent: "sqlmap", CreatedAt: time.Now().AddDate(0, 0, -2)},
		{WebsiteID: 1, WebsiteName: "a.com", AttackType: "xss", Action: model.WAFActionDeny, IP: "1.1.1.1", Method: "POST", Path: "/comment", CreatedAt: time.Now().AddDate(0, 0, -1)},
		{WebsiteID: 1, WebsiteName: "a.com", AttackType: "sqli", Action: model.WAFActionDeny, IP: "2.2.2.2", Method: "GET", Path: "/login", CreatedAt: time.Now()},
		{WebsiteID: 2, WebsiteName: "b.com", AttackType: "cc", Action: model.WAFActionDeny, IP: "3.3.3.3", Method: "GET", Path: "/", CreatedAt: time.Now()},
	}
	if err := global.DB.Create(&logs).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}
}

func TestWAFStatLogs(t *testing.T) {
	setupWAFTestDB(t)
	seedWAFLogs(t)
	svc := WAFService{}

	res, err := svc.StatLogs(request.WAFLogSearch{})
	if err != nil {
		t.Fatalf("StatLogs: %v (SQLite 下 DATE_FORMAT 会在此失败)", err)
	}
	byType := map[string]int64{}
	for _, it := range res["attackType"] {
		byType[it.Key] = it.Count
	}
	if byType["sqli"] != 2 || byType["xss"] != 1 || byType["cc"] != 1 {
		t.Fatalf("attackType wrong: %v", byType)
	}
	// Top IP：1.1.1.1 两次居首
	if len(res["topIP"]) == 0 || res["topIP"][0].Key != "1.1.1.1" || res["topIP"][0].Count != 2 {
		t.Fatalf("topIP wrong: %+v", res["topIP"])
	}
	// 趋势按天归并：至少 2 天（今天 + 昨天/前天）
	if len(res["trend"]) < 2 {
		t.Fatalf("trend wrong: %+v", res["trend"])
	}
	for i := 1; i < len(res["trend"]); i++ {
		if res["trend"][i-1].Key > res["trend"][i].Key {
			t.Fatalf("trend not sorted: %+v", res["trend"])
		}
	}
}

func TestWAFSearchLogs(t *testing.T) {
	setupWAFTestDB(t)
	seedWAFLogs(t)
	svc := WAFService{}

	total, logs, err := svc.SearchLogs(request.WAFLogSearch{WebsiteID: 1, Page: 1, PageSize: 10})
	if err != nil || total != 3 || len(logs) != 3 {
		t.Fatalf("search by website: total=%d len=%d err=%v", total, len(logs), err)
	}

	total, logs, err = svc.SearchLogs(request.WAFLogSearch{IP: "2.2.2.2", Page: 1, PageSize: 10})
	if err != nil || total != 1 || logs[0].AttackType != "sqli" {
		t.Fatalf("search by ip: %+v", logs)
	}

	total, _, err = svc.SearchLogs(request.WAFLogSearch{AttackType: "xss", Page: 1, PageSize: 10})
	if err != nil || total != 1 {
		t.Fatalf("search by attack type: total=%d", total)
	}

	total, _, err = svc.SearchLogs(request.WAFLogSearch{StartTime: time.Now().Add(-time.Hour).Unix(), Page: 1, PageSize: 10})
	if err != nil || total != 2 { // 今天的两条
		t.Fatalf("search by time range: total=%d", total)
	}
}

func TestWAFExportLogs(t *testing.T) {
	setupWAFTestDB(t)
	seedWAFLogs(t)
	svc := WAFService{}

	format, data, err := svc.ExportLogs(request.WAFLogSearch{Format: "csv"})
	if err != nil || format != "csv" {
		t.Fatalf("export csv: %v", err)
	}
	content := string(data)
	if !strings.HasPrefix(content, "time,website,attack_type,") {
		t.Fatalf("csv header wrong: %.60s", content)
	}
	if !strings.Contains(content, "a.com") || !strings.Contains(content, "sqli") {
		t.Fatalf("csv content wrong")
	}

	format, data, err = svc.ExportLogs(request.WAFLogSearch{Format: "json"})
	if err != nil || format != "json" {
		t.Fatalf("export json: %v", err)
	}
	var logs []model.WAFLog
	if err := json.Unmarshal(data, &logs); err != nil || len(logs) != 4 {
		t.Fatalf("json export decode: %v len=%d", err, len(logs))
	}
}

func TestWAFRuleCRUDAndTTL(t *testing.T) {
	setupWAFTestDB(t)
	svc := WAFService{}

	if err := svc.CreateRule(request.WAFRuleCreate{Name: "temp", Scope: model.WAFScopeGlobal, MatchType: "ip", MatchValue: "1.2.3.4", MatchOp: "exact", Action: model.WAFActionDeny, TTL: 60}); err != nil {
		t.Fatalf("create: %v", err)
	}
	rules, err := svc.ListRules(request.WAFRuleSearch{Scope: model.WAFScopeGlobal})
	if err != nil || len(rules) != 1 {
		t.Fatalf("list: %v %d", err, len(rules))
	}
	if rules[0].ExpiresAt == nil || time.Until(*rules[0].ExpiresAt) > time.Minute || time.Until(*rules[0].ExpiresAt) < time.Second {
		t.Fatalf("ttl expiry wrong: %v", rules[0].ExpiresAt)
	}

	// 更新为永久
	if err := svc.UpdateRule(request.WAFRuleUpdate{ID: rules[0].ID, Name: "perm", Priority: 10, MatchType: "ip", MatchValue: "1.2.3.4", MatchOp: "exact", Action: model.WAFActionAllow, Enabled: true, TTL: 0}); err != nil {
		t.Fatalf("update: %v", err)
	}
	rules, _ = svc.ListRules(request.WAFRuleSearch{})
	if rules[0].ExpiresAt != nil || rules[0].Action != model.WAFActionAllow {
		t.Fatalf("update ttl clear wrong: %+v", rules[0])
	}

	// 过期清理
	global.DB.Model(&model.WAFRule{}).Where("id = ?", rules[0].ID).Update("expires_at", time.Now().Add(-time.Hour))
	svc.CleanExpiredRules()
	rules, _ = svc.ListRules(request.WAFRuleSearch{})
	if len(rules) != 0 {
		t.Fatalf("expired rule not cleaned: %d", len(rules))
	}

	// 站点规则必须带 websiteId
	if err := svc.CreateRule(request.WAFRuleCreate{Name: "bad", Scope: model.WAFScopeSite, MatchType: "ip", MatchValue: "1.1.1.1", Action: model.WAFActionDeny}); err == nil {
		t.Fatalf("site rule without websiteId should fail")
	}
}

func TestWAFAddRuleFromLog(t *testing.T) {
	setupWAFTestDB(t)
	svc := WAFService{}
	if err := global.DB.Create(&model.WAFLog{WebsiteID: 1, IP: "6.6.6.6", AttackType: "sqli", Action: model.WAFActionDeny, Path: "/login"}).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}

	if err := svc.AddRuleFromLog(1, model.WAFActionAllow); err != nil {
		t.Fatalf("AddRuleFromLog: %v", err)
	}
	rules, _ := svc.ListRules(request.WAFRuleSearch{})
	if len(rules) != 1 || rules[0].MatchType != "ip" || rules[0].MatchValue != "6.6.6.6" || rules[0].Action != model.WAFActionAllow {
		t.Fatalf("rule from log wrong: %+v", rules)
	}

	// 非法 action 回退为 allow
	if err := svc.AddRuleFromLog(1, "bogus"); err != nil {
		t.Fatalf("AddRuleFromLog bogus: %v", err)
	}
	rules, _ = svc.ListRules(request.WAFRuleSearch{})
	if len(rules) != 2 || rules[1].Action != model.WAFActionAllow {
		t.Fatalf("bogus action fallback wrong: %+v", rules[1])
	}
}

func TestWAFCCConfig(t *testing.T) {
	setupWAFTestDB(t)
	svc := WAFService{}

	cc, err := svc.GetCCConfig(99)
	if err != nil || cc == nil || cc.Window != 60 || cc.Enabled {
		t.Fatalf("default cc: %+v %v", cc, err)
	}

	if err := svc.UpdateCCConfig(request.WAFCCUpdate{WebsiteID: 99, Limit: 50, Window: 30, Action: model.WAFActionChallenge, ByURI: true}); err != nil {
		t.Fatalf("update cc: %v", err)
	}
	cc, _ = svc.GetCCConfig(99)
	if cc.Limit != 50 || cc.Window != 30 || cc.Action != model.WAFActionChallenge || !cc.ByURI || !cc.Enabled {
		t.Fatalf("cc after update: %+v", cc)
	}

	// limit=0 即关闭
	if err := svc.UpdateCCConfig(request.WAFCCUpdate{WebsiteID: 99, Limit: 0, Window: 30, Action: model.WAFActionDeny}); err != nil {
		t.Fatalf("disable cc: %v", err)
	}
	cc, _ = svc.GetCCConfig(99)
	if cc.Enabled {
		t.Fatalf("cc should be disabled at limit=0")
	}
}

func TestWAFTypeCoerce(t *testing.T) {
	if toUint(float64(42)) != 42 || toUint("42") != 42 || toUint("abc") != 0 || toUint(nil) != 0 {
		t.Fatalf("toUint wrong")
	}
	if toString("x") != "x" || toString(1) != "" {
		t.Fatalf("toString wrong")
	}
	if toFloat(float64(1.5)) != 1.5 || toFloat("1.5") != 0 {
		t.Fatalf("toFloat wrong")
	}
}
