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
		{BaseModel: model.BaseModel{ID: 5}, Name: "site-method", Scope: model.WAFScopeSite, WebsiteID: 7, Priority: 30, MatchType: "method", MatchValue: "DELETE", MatchOp: "exact", Action: model.WAFActionDeny, Enabled: true},
	}
	ccs := []model.WAFCCConfig{
		{WebsiteID: 7, Limit: 100, Window: 60, Action: model.WAFActionDeny, Enabled: true},
		{WebsiteID: 8, Limit: 0, Window: 60, Action: model.WAFActionDeny, Enabled: true},   // limit=0 不导出
		{WebsiteID: 9, Limit: 50, Window: 60, Action: model.WAFActionDeny, Enabled: false}, // 禁用不导出
	}
	opts := []model.WAFOption{
		{WebsiteID: 7, BotEnabled: true, AllowGoodBots: true, BlockBadBots: true, ProbeEnabled: true, ProbeMaxURIs: 60, ProbeWindow: 60, ProbeMaxRPS: 120},
		{WebsiteID: 10, BotEnabled: false, ProbeEnabled: false}, // 全关不导出
	}

	if err := ExportRules(rules, ccs, opts, map[uint]bool{7: true, 11: false}, dir); err != nil {
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

	// 可安全预编译的 exact 规则进入映射；禁用、TTL 和非 exact 规则保留在慢路径。
	if len(got.Global.Rules) != 2 {
		t.Fatalf("global residual rules count = %d, want 2", len(got.Global.Rules))
	}
	if got.Global.Rules[0].Name != "disabled" || got.Global.Rules[1].Name != "g0" {
		t.Fatalf("global rules not sorted by priority: %+v", got.Global.Rules)
	}
	if got.Global.Compiled.IP["1.2.3.4"].Name != "g1" {
		t.Fatalf("global exact IP not compiled: %+v", got.Global.Compiled.IP)
	}
	// 站点名单 + CC + Bot + Probe
	site, ok := got.Sites["7"]
	if !ok {
		t.Fatalf("site 7 missing, sites=%v", got.Sites)
	}
	if len(site.Rules) != 1 || site.Rules[0].Name != "s1" {
		t.Fatalf("site rules wrong: %+v", site.Rules)
	}
	if site.Compiled.Method["DELETE"].Name != "site-method" {
		t.Fatalf("site exact method not compiled: %+v", site.Compiled.Method)
	}
	if !site.Enabled || got.Sites["11"].Enabled {
		t.Fatalf("site enabled state wrong: site7=%v site11=%v", site.Enabled, got.Sites["11"].Enabled)
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

func TestCompiledRuleConflictUsesAllowThenPriority(t *testing.T) {
	compiled := newCompiledRuleSet()
	deny := ruleDTO{ID: 1, Name: "deny", Priority: 1, MatchType: "path", MatchValue: "/health", MatchOp: "exact", Action: model.WAFActionDeny, Enabled: true}
	allow := ruleDTO{ID: 2, Name: "allow", Priority: 99, MatchType: "path", MatchValue: "/health", MatchOp: "exact", Action: model.WAFActionAllow, Enabled: true}
	if !compiled.add(deny) || !compiled.add(allow) {
		t.Fatal("eligible exact rules were not compiled")
	}
	if got := compiled.Path["/health"]; got.Name != "allow" {
		t.Fatalf("allow must win duplicate exact key, got %+v", got)
	}

	compiled = newCompiledRuleSet()
	high := ruleDTO{ID: 3, Name: "priority-50", Priority: 50, MatchType: "ua", MatchValue: "scanner", MatchOp: "exact", Action: model.WAFActionDeny, Enabled: true}
	low := ruleDTO{ID: 4, Name: "priority-10", Priority: 10, MatchType: "ua", MatchValue: "scanner", MatchOp: "exact", Action: model.WAFActionDeny, Enabled: true}
	compiled.add(high)
	compiled.add(low)
	if got := compiled.UA["scanner"]; got.Name != "priority-10" {
		t.Fatalf("smaller priority must win duplicate exact key, got %+v", got)
	}
}

func TestDeployLuaModules(t *testing.T) {
	if WAFDir != "/www/waf" {
		t.Fatalf("WAFDir = %q, managed OpenResty only mounts website data at /www", WAFDir)
	}
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
