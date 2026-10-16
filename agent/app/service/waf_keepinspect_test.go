package service

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/3panel-dev/3panel/agent/app/dto/request"
	"github.com/3panel-dev/3panel/agent/app/model"
	"github.com/3panel-dev/3panel/agent/global"
	"github.com/3panel-dev/3panel/agent/utils/waf"
)

// 白名单「加白时仍检测」（keep_inspecting）。
//
// 问题背景：白名单命中后 Lua 原本立即 return，请求彻底放行。
// 用户点「标记误报」建的也是白名单 —— 于是误报反馈等于让这段攻击
// 从此彻底不可见。万一误判的是真攻击，运营没有任何察觉途径。
//
// 现在白名单可以带 keep_inspecting：放行，但继续跑检测链，只记日志不拦截。

func TestWAFRuleCreatePersistsKeepInspecting(t *testing.T) {
	setupWAFTestDB(t)
	svc := WAFService{syncRulesFn: func() error { return nil }}
	if err := svc.CreateRule(request.WAFRuleCreate{
		Name:           "wp-admin",
		Scope:          model.WAFScopeGlobal,
		MatchType:      "path",
		MatchValue:     "/wp-admin",
		MatchOp:        "prefix",
		Action:         model.WAFActionAllow,
		KeepInspecting: true,
	}); err != nil {
		t.Fatalf("CreateRule: %v", err)
	}
	var got model.WAFRule
	if err := global.DB.First(&got).Error; err != nil {
		t.Fatalf("read back: %v", err)
	}
	if !got.KeepInspecting {
		t.Error("KeepInspecting 未落库，前端开关会显示为关闭且保存后失效")
	}
}

func TestWAFRuleCreateDefaultsKeepInspectingFalse(t *testing.T) {
	setupWAFTestDB(t)
	// 缺省必须是 false：白名单的语义是"彻底放行"，
	// 只有显式打开开关才改变行为，否则老规则升级后语义会突变。
	if err := (WAFService{syncRulesFn: func() error { return nil }}).CreateRule(request.WAFRuleCreate{
		Name:       "plain-allow",
		Scope:      model.WAFScopeGlobal,
		MatchType:  "ip",
		MatchValue: "1.2.3.4",
		MatchOp:    "exact",
		Action:     model.WAFActionAllow,
	}); err != nil {
		t.Fatalf("CreateRule: %v", err)
	}
	var got model.WAFRule
	if err := global.DB.First(&got).Error; err != nil {
		t.Fatalf("read back: %v", err)
	}
	if got.KeepInspecting {
		t.Error("未指定时 KeepInspecting 应为 false")
	}
}

func TestWAFRuleUpdateCanToggleKeepInspecting(t *testing.T) {
	setupWAFTestDB(t)
	svc := WAFService{syncRulesFn: func() error { return nil }}
	if err := svc.CreateRule(request.WAFRuleCreate{
		Name:       "togglable",
		Scope:      model.WAFScopeGlobal,
		MatchType:  "ip",
		MatchValue: "1.2.3.4",
		MatchOp:    "exact",
		Action:     model.WAFActionAllow,
	}); err != nil {
		t.Fatalf("CreateRule: %v", err)
	}
	var rule model.WAFRule
	if err := global.DB.First(&rule).Error; err != nil {
		t.Fatalf("read: %v", err)
	}
	if err := svc.UpdateRule(request.WAFRuleUpdate{
		ID:             rule.ID,
		Name:           rule.Name,
		MatchType:      rule.MatchType,
		MatchValue:     rule.MatchValue,
		MatchOp:        rule.MatchOp,
		Action:         rule.Action,
		Enabled:        true,
		KeepInspecting: true,
	}); err != nil {
		t.Fatalf("UpdateRule: %v", err)
	}
	var got model.WAFRule
	if err := global.DB.First(&got, rule.ID).Error; err != nil {
		t.Fatalf("read back: %v", err)
	}
	if !got.KeepInspecting {
		t.Error("UpdateRule 未写KeepInspecting，界面上开关拨了也不生效")
	}
}

// 核心断言：keep_inspecting 的白名单不能进 compiled 快速表。
// compiled 表只存「键 → 规则」，Lua 查表命中即 return，
// 拿不到 keep_inspecting —— 编进去等于让这个开关静默失效。
func TestWAFRuleKeepInspectingStaysOutOfCompiledTable(t *testing.T) {
	dir := t.TempDir()
	rules := []model.WAFRule{
		{
			BaseModel: model.BaseModel{ID: 1},
			Name:      "keep-inspecting", Scope: model.WAFScopeGlobal,
			MatchType: "ip", MatchValue: "1.2.3.4", MatchOp: "exact",
			Action: model.WAFActionAllow, Enabled: true, KeepInspecting: true,
		},
		{
			// 对照：普通白名单应当照常进快速表
			BaseModel: model.BaseModel{ID: 2},
			Name:      "plain-allow", Scope: model.WAFScopeGlobal,
			MatchType: "ip", MatchValue: "5.6.7.8", MatchOp: "exact",
			Action: model.WAFActionAllow, Enabled: true, KeepInspecting: false,
		},
	}
	if err := waf.ExportRules(rules, nil, nil, map[uint]bool{1: true}, dir, false); err != nil {
		t.Fatalf("ExportRules: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(waf.HostWAFDir(dir), "rules.json"))
	if err != nil {
		t.Fatalf("read rules.json: %v", err)
	}
	var doc struct {
		Global struct {
			Compiled struct {
				IP map[string]json.RawMessage `json:"ip"`
			} `json:"compiled"`
			Rules []struct {
				ID             uint `json:"id"`
				KeepInspecting bool `json:"keep_inspecting"`
			} `json:"rules"`
		} `json:"global"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if _, inCompiled := doc.Global.Compiled.IP["1.2.3.4"]; inCompiled {
		t.Error("keep_inspecting 的白名单进了 compiled 快速表 —— Lua 查表即return，开关静默失效")
	}
	if _, inCompiled := doc.Global.Compiled.IP["5.6.7.8"]; !inCompiled {
		t.Error("普通白名单应照常进 compiled 快速表（性能路径）")
	}
	// keep_inspecting 那条必须在慢路径数组里，且字段值为 true
	var found bool
	for _, r := range doc.Global.Rules {
		if r.ID == 1 {
			found = true
			if !r.KeepInspecting {
				t.Error("慢路径规则里 keep_inspecting 字段为 false，Lua 读不到该语义")
			}
		}
	}
	if !found {
		t.Error("keep_inspecting 的白规则没出现在 global_rules 里，会彻底失效")
	}
}

// 黑名单带 keep_inspecting 毫无意义（黑名单本来就是拦），
// 但也不能因此把它踢出快速表导致性能退化。
func TestWAFRuleKeepInspectingOnlyAffectsAllow(t *testing.T) {
	dir := t.TempDir()
	rules := []model.WAFRule{
		{
			BaseModel: model.BaseModel{ID: 3},
			Name:      "deny-with-flag", Scope: model.WAFScopeGlobal,
			MatchType: "ip", MatchValue: "9.9.9.9", MatchOp: "exact",
			Action: model.WAFActionDeny, Enabled: true, KeepInspecting: true,
		},
	}
	if err := waf.ExportRules(rules, nil, nil, map[uint]bool{1: true}, dir, false); err != nil {
		t.Fatalf("ExportRules: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(waf.HostWAFDir(dir), "rules.json"))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var doc struct {
		Global struct {
			Compiled struct {
				IP map[string]json.RawMessage `json:"ip"`
			} `json:"compiled"`
		} `json:"global"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, ok := doc.Global.Compiled.IP["9.9.9.9"]; !ok {
		t.Error("黑名单不应因keep_inspecting 被排除出快速表")
	}
}

// 误报反馈生成的规则必须默认开启 keep_inspecting ——
// 这是这个开关最核心的使用场景。
func TestWAFFalsePositiveRuleKeepsInspecting(t *testing.T) {
	setupWAFTestDB(t)
	svc := WAFService{syncRulesFn: func() error { return nil }}
	log := model.WAFLog{
		WebsiteID: 1, WebsiteName: "a.com", AttackType: "sqli",
		Action: model.WAFActionDeny, IP: "1.1.1.1", Method: "GET", Path: "/login",
	}
	if err := global.DB.Create(&log).Error; err != nil {
		t.Fatalf("seed log: %v", err)
	}
	if err := svc.MarkFalsePositive(request.WAFFalsePositiveOp{LogID: log.ID}); err != nil {
		t.Fatalf("MarkFalsePositive: %v", err)
	}
	var rule model.WAFRule
	if err := global.DB.Where("source = ?", "false_positive").First(&rule).Error; err != nil {
		t.Fatalf("误报规则未生成: %v", err)
	}
	if !rule.KeepInspecting {
		t.Error("误报反馈生成的规则应默认开启「加白时仍检测」，否则误报等于让攻击彻底消失")
	}
}
