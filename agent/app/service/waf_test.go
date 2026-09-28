package service

import (
	"encoding/json"
	"errors"
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
	svc := WAFService{syncRulesFn: func() error { return nil }}

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
	svc := WAFService{syncRulesFn: func() error { return nil }}

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
	if err := global.DB.Model(&model.WAFLog{}).Where("id = ?", 1).Update("false_positive", true).Error; err != nil {
		t.Fatalf("mark fixture false positive: %v", err)
	}
	marked := true
	total, _, err = svc.SearchLogs(request.WAFLogSearch{FalsePositive: &marked, Page: 1, PageSize: 10})
	if err != nil || total != 1 {
		t.Fatalf("search false positives: total=%d err=%v", total, err)
	}
}

func TestWAFExportLogs(t *testing.T) {
	setupWAFTestDB(t)
	seedWAFLogs(t)
	svc := WAFService{syncRulesFn: func() error { return nil }}

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

func TestEnrichWAFAreasCachesLookup(t *testing.T) {
	logs := []model.WAFLog{
		{IP: "1.2.3.4"},
		{IP: "1.2.3.4"},
		{IP: "5.6.7.8", Area: "existing"},
		{},
	}
	calls := 0
	enrichWAFAreas(logs, func(ip string) (string, error) {
		calls++
		return " China Shanghai ", nil
	})
	if calls != 1 {
		t.Fatalf("lookup calls = %d, want 1", calls)
	}
	if logs[0].Area != "China Shanghai" || logs[1].Area != "China Shanghai" {
		t.Fatalf("area enrichment failed: %+v", logs)
	}
	if logs[2].Area != "existing" {
		t.Fatalf("existing area overwritten: %+v", logs[2])
	}
}

func TestWAFRuleCRUDAndTTL(t *testing.T) {
	setupWAFTestDB(t)
	svc := WAFService{syncRulesFn: func() error { return nil }}

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

func TestWAFRuleMutationReturnsSyncError(t *testing.T) {
	setupWAFTestDB(t)
	wantErr := errors.New("sync failed")
	svc := WAFService{syncRulesFn: func() error { return wantErr }}
	err := svc.CreateRule(request.WAFRuleCreate{
		Name: "deny", Scope: model.WAFScopeGlobal, MatchType: "ip",
		MatchValue: "1.2.3.4", MatchOp: "exact", Action: model.WAFActionDeny,
	})
	if !errors.Is(err, wantErr) {
		t.Fatalf("CreateRule error = %v, want %v", err, wantErr)
	}
	var count int64
	if err := global.DB.Model(&model.WAFRule{}).Count(&count).Error; err != nil || count != 0 {
		t.Fatalf("failed create must roll back DB state: count=%d err=%v", count, err)
	}
}

func TestWAFRuleUpdateAndDeleteRollbackOnSyncError(t *testing.T) {
	setupWAFTestDB(t)
	rule := model.WAFRule{Name: "original", Scope: model.WAFScopeGlobal, MatchType: "ip", MatchValue: "1.2.3.4", MatchOp: "exact", Action: model.WAFActionDeny, Enabled: true}
	if err := global.DB.Create(&rule).Error; err != nil {
		t.Fatal(err)
	}
	svc := WAFService{syncRulesFn: func() error { return errors.New("sync failed") }}
	if err := svc.UpdateRule(request.WAFRuleUpdate{ID: rule.ID, Name: "changed", MatchType: "ip", MatchValue: "5.6.7.8", MatchOp: "exact", Action: model.WAFActionAllow, Enabled: true}); err == nil {
		t.Fatal("UpdateRule should return sync error")
	}
	var got model.WAFRule
	if err := global.DB.First(&got, rule.ID).Error; err != nil || got.Name != "original" || got.Action != model.WAFActionDeny {
		t.Fatalf("failed update must restore original: %+v err=%v", got, err)
	}
	if err := svc.DeleteRule(rule.ID); err == nil {
		t.Fatal("DeleteRule should return sync error")
	}
	if err := global.DB.First(&got, rule.ID).Error; err != nil {
		t.Fatalf("failed delete must restore rule: %v", err)
	}
}

func TestWAFListWebsiteRulesIncludesGlobalAndSite(t *testing.T) {
	setupWAFTestDB(t)
	rules := []model.WAFRule{
		{Name: "global", Scope: model.WAFScopeGlobal, MatchType: "ip", MatchValue: "1.1.1.1", Action: model.WAFActionDeny, Enabled: true},
		{Name: "site-1", Scope: model.WAFScopeSite, WebsiteID: 1, MatchType: "path", MatchValue: "/admin", Action: model.WAFActionDeny, Enabled: true},
		{Name: "site-2", Scope: model.WAFScopeSite, WebsiteID: 2, MatchType: "path", MatchValue: "/private", Action: model.WAFActionDeny, Enabled: true},
	}
	if err := global.DB.Create(&rules).Error; err != nil {
		t.Fatalf("seed rules: %v", err)
	}
	svc := WAFService{syncRulesFn: func() error { return nil }}
	got, err := svc.ListRules(request.WAFRuleSearch{WebsiteID: 1})
	if err != nil || len(got) != 2 {
		t.Fatalf("ListRules = %v, %v, want global + site rule", got, err)
	}
}

func TestWAFAddRuleFromLog(t *testing.T) {
	setupWAFTestDB(t)
	svc := WAFService{syncRulesFn: func() error { return nil }}
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
	if rules[0].Scope != model.WAFScopeSite || rules[0].WebsiteID != 1 {
		t.Fatalf("rule from log must be site-scoped: %+v", rules[0])
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

func TestWAFMarkFalsePositiveCreatesTemporaryPathAllow(t *testing.T) {
	setupWAFTestDB(t)
	log := model.WAFLog{WebsiteID: 7, IP: "6.6.6.6", Path: "/checkout", AttackType: "sqli", Action: model.WAFActionDeny}
	if err := global.DB.Create(&log).Error; err != nil {
		t.Fatalf("seed log: %v", err)
	}
	svc := WAFService{syncRulesFn: func() error { return nil }}
	if err := svc.MarkFalsePositive(request.WAFFalsePositiveOp{LogID: log.ID, TTL: 3600, Remark: "known callback"}); err != nil {
		t.Fatalf("MarkFalsePositive: %v", err)
	}
	var gotLog model.WAFLog
	if err := global.DB.First(&gotLog, log.ID).Error; err != nil || !gotLog.FalsePositive || gotLog.DispositionAt == nil || gotLog.DispositionRemark != "known callback" {
		t.Fatalf("false positive disposition not saved: %+v err=%v", gotLog, err)
	}
	var rule model.WAFRule
	if err := global.DB.First(&rule).Error; err != nil {
		t.Fatalf("temporary allow missing: %v", err)
	}
	if rule.Scope != model.WAFScopeSite || rule.WebsiteID != 7 || rule.MatchType != "expr" || rule.MatchValue != `ip in "6.6.6.6" and path eq "/checkout"` || rule.Action != model.WAFActionAllow || rule.TTL != 3600 || rule.ExpiresAt == nil || rule.Source != "false_positive" {
		t.Fatalf("temporary allow wrong: %+v", rule)
	}
}

func TestWAFMarkFalsePositiveRollsBackDispositionOnSyncError(t *testing.T) {
	setupWAFTestDB(t)
	log := model.WAFLog{WebsiteID: 7, IP: "6.6.6.6", Path: "/checkout"}
	if err := global.DB.Create(&log).Error; err != nil {
		t.Fatalf("seed log: %v", err)
	}
	svc := WAFService{syncRulesFn: func() error { return errors.New("sync failed") }}
	if err := svc.MarkFalsePositive(request.WAFFalsePositiveOp{LogID: log.ID}); err == nil {
		t.Fatal("MarkFalsePositive should return sync error")
	}
	var gotLog model.WAFLog
	if err := global.DB.First(&gotLog, log.ID).Error; err != nil || gotLog.FalsePositive || gotLog.DispositionAt != nil {
		t.Fatalf("failed operation must restore disposition: %+v err=%v", gotLog, err)
	}
	var count int64
	if err := global.DB.Model(&model.WAFRule{}).Count(&count).Error; err != nil || count != 0 {
		t.Fatalf("failed operation left rules: count=%d err=%v", count, err)
	}
}

func TestWAFCCConfig(t *testing.T) {
	setupWAFTestDB(t)
	svc := WAFService{syncRulesFn: func() error { return nil }}

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
