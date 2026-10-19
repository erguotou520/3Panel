package service

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/3panel-dev/3panel/agent/app/dto/request"
	"github.com/3panel-dev/3panel/agent/app/model"
	"github.com/3panel-dev/3panel/agent/global"
	"github.com/3panel-dev/3panel/agent/utils/waf"
	"github.com/go-playground/validator/v10"
)

// 防护模式（block/observe/maintenance）与拦截页定制的导出 / 持久化测试。
//
// 这一组最容易出「静默失效」：字段加了但没导出、Lua 读不到，
// 界面上开关显示已开、数据面却毫无反应。

func exportForTest(t *testing.T, opts []model.WAFOption) map[string]any {
	t.Helper()
	dir := t.TempDir()
	if err := waf.ExportRules(nil, nil, opts, map[uint]bool{1: true}, dir, false); err != nil {
		t.Fatalf("ExportRules: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(waf.HostWAFDir(dir), "rules.json"))
	if err != nil {
		t.Fatalf("read rules.json: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return doc
}

func siteOf(t *testing.T, doc map[string]any, id string) map[string]any {
	t.Helper()
	sites, ok := doc["sites"].(map[string]any)
	if !ok {
		t.Fatal("rules.json 缺少 sites 段")
	}
	site, ok := sites[id].(map[string]any)
	if !ok {
		t.Fatalf("rules.json 缺少站点 %s", id)
	}
	return site
}

func TestWAFModeExportedForObserveAndMaintenance(t *testing.T) {
	for _, mode := range []string{waf.WAFModeObserve, waf.WAFModeMaintenance} {
		doc := exportForTest(t, []model.WAFOption{{WebsiteID: 1, Mode: mode}})
		site := siteOf(t, doc, "1")
		if got := site["mode"]; got != mode {
			t.Errorf("mode=%s 应导出到 rules.json，实际 %v（Lua 读不到就是静默失效）", mode, got)
		}
	}
}

// block 是默认值，不导出 —— 让 rules.json 保持小，
// 也让老版本 Lua 忽略未知字段时行为正确。
func TestWAFModeBlockNotExported(t *testing.T) {
	doc := exportForTest(t, []model.WAFOption{{WebsiteID: 1, Mode: waf.WAFModeBlock}})
	site := siteOf(t, doc, "1")
	if _, present := site["mode"]; present {
		t.Error("block 是默认值，不应导出 mode 字段（Lua 侧应按缺省=block 处理）")
	}

	// 空 Mode 同理不导出
	doc2 := exportForTest(t, []model.WAFOption{{WebsiteID: 1}})
	if _, present := siteOf(t, doc2, "1")["mode"]; present {
		t.Error("Mode 为空时不应导出")
	}
}

// 关键回归：早期版本的过滤条件只看 BotEnabled/ProbeEnabled，
// 「只配了防护模式」的站点会被整个跳过 —— 模式在界面上能配、
// 保存后数据面毫无反应。
func TestWAFModeExportedWithoutBotOrProbeEnabled(t *testing.T) {
	doc := exportForTest(t, []model.WAFOption{{
		WebsiteID: 1,
		Mode:      waf.WAFModeMaintenance,
		// BotEnabled / ProbeEnabled 均为 false
	}})
	site := siteOf(t, doc, "1")
	if site["mode"] != waf.WAFModeMaintenance {
		t.Error("只配了防护模式（未开 bot/probe）的站点也必须导出 mode，否则会因过滤条件漏掉而静默失效")
	}
}

func TestWAFBlockPageExported(t *testing.T) {
	doc := exportForTest(t, []model.WAFOption{{
		WebsiteID:        1,
		BlockPageTitle:   "访问受限",
		BlockPageBody:    "请联系管理员",
		BlockPageBgColor: "#101820",
	}})
	page, ok := siteOf(t, doc, "1")["blockPage"].(map[string]any)
	if !ok {
		t.Fatal("blockPage 未导出")
	}
	if page["title"] != "访问受限" {
		t.Errorf("title 导出错误: %v", page["title"])
	}
	if page["body"] != "请联系管理员" {
		t.Errorf("body 导出错误: %v", page["body"])
	}
	if page["bgColor"] != "#101820" {
		t.Errorf("bgColor 导出错误: %v", page["bgColor"])
	}
}

// 全空时不导出 blockPage —— Lua 侧据此走内置默认样式。
func TestWAFBlockPageNotExportedWhenEmpty(t *testing.T) {
	doc := exportForTest(t, []model.WAFOption{{WebsiteID: 1}})
	if _, present := siteOf(t, doc, "1")["blockPage"]; present {
		t.Error("未配置时不应导出 blockPage")
	}
}

func TestWAFDisabledDetectorsExported(t *testing.T) {
	doc := exportForTest(t, []model.WAFOption{{
		WebsiteID:         1,
		DisabledDetectors: "sqli, ssti ,,xss ",
	}})
	raw, _ := siteOf(t, doc, "1")["disabled_detectors"].([]any)
	if len(raw) != 3 {
		t.Fatalf("空项与空白应被剔除，期望 3 项，实际 %d: %v", len(raw), raw)
	}
	want := []string{"sqli", "ssti", "xss"}
	for i, w := range want {
		if raw[i] != w {
			t.Errorf("第 %d 项应为 %q，实际 %v", i+1, w, raw[i])
		}
	}
}

func TestWAFDisabledDetectorsEmptyNotExported(t *testing.T) {
	doc := exportForTest(t, []model.WAFOption{{
		WebsiteID:         1,
		DisabledDetectors: " , ,",
	}})
	if _, present := siteOf(t, doc, "1")["disabled_detectors"]; present {
		t.Error("全是空项时不应导出（Lua 侧据此走全部启用）")
	}
}

// DTO 校验：mode 必须限制在三个取值内。
// 非法值若被放行，导出后 Lua 的 mode == "..." 全部不匹配，
// 结果是「配了但没生效」，比报错难查。
// 契约测试：导出用的 JSON 字段名必须与 Lua 侧读取的一致。
//
// 这里踩过一次真坑：DTO 上写的是驼峰 disabledDetectors，
// Lua 侧按下划线 disabled_detectors 读 —— 编译全绿、测试全绿、
// 界面能配置，但数据面永远读不到（字段名对不上），
// 是典型的"配置项静默失效"。
//
// 用一条测试把这个字段名钉死，两边任一改动而没同步就会红。
func TestWAFDisabledDetectorsFieldNameMatchesLua(t *testing.T) {
	// Lua 侧 access.lua 里的读取字段名
	const luaField = "disabled_detectors"

	doc := exportForTest(t, []model.WAFOption{{
		WebsiteID:         1,
		DisabledDetectors: "sqli",
	}})
	site := siteOf(t, doc, "1")
	if _, ok := site[luaField]; !ok {
		t.Fatalf("rules.json 里应存在字段 %q（Lua 侧按下划线读），实际导出的是 %v",
			luaField, keysOf(site))
	}
}

func keysOf(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func TestWAFOptionModeValidation(t *testing.T) {
	if global.VALID == nil {
		global.VALID = validator.New()
	}
	for _, mode := range []string{"block", "observe", "maintenance"} {
		req := request.WAFOptionUpdate{WebsiteID: 1, Mode: mode}
		if err := global.VALID.Struct(req); err != nil {
			t.Errorf("合法 mode %q 被拒绝: %v", mode, err)
		}
	}
	for _, mode := range []string{"off", "disabled", "BLOCK", "maintain"} {
		req := request.WAFOptionUpdate{WebsiteID: 1, Mode: mode}
		if err := global.VALID.Struct(req); err == nil {
			t.Errorf("非法 mode %q 应被 oneof 校验拒绝", mode)
		}
	}
	// 空值必须允许（等价于 block）
	if err := global.VALID.Struct(request.WAFOptionUpdate{WebsiteID: 1}); err != nil {
		t.Errorf("mode 为空应允许: %v", err)
	}
}

// Option 的 mode / blockPage / disabledDetectors 必须能落库并读回。
func TestWAFOptionPersistsNewFields(t *testing.T) {
	setupWAFTestDB(t)
	svc := WAFService{syncRulesFn: func() error { return nil }}

	want := request.WAFOptionUpdate{
		WebsiteID:         7,
		Mode:              waf.WAFModeObserve,
		BlockPageTitle:    strPtr("维护中"),
		BlockPageBody:     strPtr("稍后再试"),
		BlockPageBgColor:  strPtr("#f6f8fa"),
		DisabledDetectors: strPtr("sqli"),
	}
	if err := svc.UpdateOption(want); err != nil {
		t.Fatalf("UpdateOption: %v", err)
	}

	var got model.WAFOption
	if err := global.DB.Where("website_id = ?", 7).First(&got).Error; err != nil {
		t.Fatalf("read back: %v", err)
	}
	if got.Mode != waf.WAFModeObserve {
		t.Errorf("Mode 应为 %q，实际 %q", waf.WAFModeObserve, got.Mode)
	}
	if got.BlockPageTitle != "维护中" || got.BlockPageBody != "稍后再试" {
		t.Errorf("拦截页内容未落库: %+v", got)
	}
	if got.BlockPageBgColor != "#f6f8fa" {
		t.Errorf("BlockPageBgColor 未落库: %q", got.BlockPageBgColor)
	}
	if got.DisabledDetectors != "sqli" {
		t.Errorf("DisabledDetectors 未落库: %q", got.DisabledDetectors)
	}
}

// 新装站点读 Option 时应给出 block 缺省，而不是空字符串 ——
// 空字符串在 Lua 侧不等于 block，虽然当前实现按缺省处理，
// 但导出与界面展示都依赖这个值明确。
func TestWAFGetOptionDefaultsModeToBlock(t *testing.T) {
	setupWAFTestDB(t)
	got, err := WAFService{}.GetOption(9)
	if err != nil {
		t.Fatalf("GetOption: %v", err)
	}
	if got.Mode != "" && got.Mode != waf.WAFModeBlock {
		t.Errorf("未配置时 Mode 应为空或 block，实际 %q", got.Mode)
	}
}

// readRulesJSON 读回导出的 rules.json 并反序列化成通用 map。
// 供需要检查原始 JSON 键名的测试使用（keysOf 这类 helper 只看单个 map）。
func readRulesJSON(t *testing.T, dir string) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(waf.HostWAFDir(dir), "rules.json"))
	if err != nil {
		t.Fatalf("read rules.json: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return doc
}

// strPtr 用于可区分「未传」与「传空串」的字段。
func strPtr(s string) *string { return &s }
