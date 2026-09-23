package waf

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/3panel-dev/3panel/agent/app/model"
)

func TestExportRulesScopesAndPriority(t *testing.T) {
	dir := t.TempDir()
	expired := time.Now().Add(-time.Hour)
	rules := []model.WAFRule{
		{BaseModel: model.BaseModel{ID: 1}, Name: "g1", Scope: model.WAFScopeGlobal, Priority: 50, MatchType: "ip", MatchValue: "1.2.3.4", MatchOp: "exact", Action: model.WAFActionDeny, Enabled: true},
		{BaseModel: model.BaseModel{ID: 2}, Name: "g0", Scope: model.WAFScopeGlobal, Priority: 10, MatchType: "path", MatchValue: "/admin", MatchOp: "prefix", Action: model.WAFActionDeny, Enabled: true},
		{BaseModel: model.BaseModel{ID: 3}, Name: "s1", Scope: model.WAFScopeSite, WebsiteID: 7, Priority: 20, MatchType: "ua", MatchValue: "curl", MatchOp: "contains", Action: model.WAFActionDeny, Enabled: true, ExpiresAt: &expired},
		{BaseModel: model.BaseModel{ID: 4}, Name: "disabled", Scope: model.WAFScopeGlobal, Priority: 5, MatchType: "ip", MatchValue: "9.9.9.9", MatchOp: "exact", Action: model.WAFActionDeny, Enabled: false},
	}
	ccs := []model.WAFCCConfig{
		{WebsiteID: 7, Limit: 100, Window: 60, Action: model.WAFActionDeny, Enabled: true},
		{WebsiteID: 8, Limit: 0, Window: 60, Action: model.WAFActionDeny, Enabled: true},  // limit=0 不导出
		{WebsiteID: 9, Limit: 50, Window: 60, Action: model.WAFActionDeny, Enabled: false}, // 禁用不导出
	}
	opts := []model.WAFOption{
		{WebsiteID: 7, BotEnabled: true, AllowGoodBots: true, BlockBadBots: true, ProbeEnabled: true, ProbeMaxURIs: 60, ProbeWindow: 60, ProbeMaxRPS: 120},
		{WebsiteID: 10, BotEnabled: false, ProbeEnabled: false}, // 全关不导出
	}

	if err := ExportRules(rules, ccs, opts, dir); err != nil {
		t.Fatalf("ExportRules: %v", err)
	}

	raw, err := os.ReadFile(filepath.Join(HostWAFDir(dir), "rules.json"))
	if err != nil {
		t.Fatalf("read rules.json: %v", err)
	}
	var got exportedRules
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	// 全局名单：按 priority 升序（5, 10, 50），禁用规则仍导出（由数据面跳过）
	if len(got.Global.Rules) != 3 {
		t.Fatalf("global rules count = %d, want 3", len(got.Global.Rules))
	}
	if got.Global.Rules[0].Name != "disabled" || got.Global.Rules[1].Name != "g0" || got.Global.Rules[2].Name != "g1" {
		t.Fatalf("global rules not sorted by priority: %+v", got.Global.Rules)
	}
	// 站点名单 + CC + Bot + Probe
	site, ok := got.Sites["7"]
	if !ok {
		t.Fatalf("site 7 missing, sites=%v", got.Sites)
	}
	if len(site.Rules) != 1 || site.Rules[0].Name != "s1" {
		t.Fatalf("site rules wrong: %+v", site.Rules)
	}
	if site.CC == nil || site.CC.Limit != 100 {
		t.Fatalf("site cc wrong: %+v", site.CC)
	}
	if site.Bot == nil || !site.Bot.AllowGoodBots {
		t.Fatalf("site bot wrong: %+v", site.Bot)
	}
	if site.Probe == nil || site.Probe.MaxURIs != 60 {
		t.Fatalf("site probe wrong: %+v", site.Probe)
	}
	if _, ok := got.Sites["8"]; ok {
		t.Fatalf("site 8 (limit=0) should not be exported")
	}
	if _, ok := got.Sites["9"]; ok {
		t.Fatalf("site 9 (disabled) should not be exported")
	}
	if _, ok := got.Sites["10"]; ok {
		t.Fatalf("site 10 (all options off) should not be exported")
	}
	// 过期时间透传（数据面惰性判断）
	if site.Rules[0].ExpiresAt == nil {
		t.Fatalf("expires_at lost")
	}
}

func TestDeployLuaModules(t *testing.T) {
	dir := t.TempDir()
	files, err := LuaFiles()
	if err != nil {
		t.Fatalf("LuaFiles: %v", err)
	}
	if len(files) == 0 {
		t.Fatalf("no lua files embedded")
	}
	for name := range files {
		if name == "access.lua" {
			goto found
		}
	}
	t.Fatalf("access.lua not embedded")
found:
	if err := DeployLuaModules(files, dir); err != nil {
		t.Fatalf("DeployLuaModules: %v", err)
	}
	for name := range files {
		if _, err := os.Stat(filepath.Join(HostWAFDir(dir), name)); err != nil {
			t.Fatalf("deployed file %s missing: %v", name, err)
		}
	}
}
