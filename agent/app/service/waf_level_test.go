package service

import (
	"testing"

	"github.com/3panel-dev/3panel/agent/app/dto/request"
	"github.com/3panel-dev/3panel/agent/app/model"
)

// 强度分档必须落到 rules.json，否则界面配了数据面看不到。
func TestWAFLevelsExported(t *testing.T) {
	site := siteOf(t, exportForTest(t, []model.WAFOption{{
		WebsiteID:     1,
		SemanticLevel: "high",
		BotLevel:      "high",
		BotEnabled:    true,
	}}), "1")

	if got := site["semantic_level"]; got != "high" {
		t.Errorf("semantic_level 应为 high，实际 %v", got)
	}
	bot, ok := site["bot"].(map[string]any)
	if !ok {
		t.Fatalf("bot 配置缺失：%v", site)
	}
	if got := bot["level"]; got != "high" {
		t.Errorf("bot.level 应为 high，实际 %v", got)
	}
}

// balanced 是默认值，不导出 —— rules.json 保持小，
// 且老版本 Lua 遇到未知字段直接忽略。
func TestWAFLevelsDefaultNotExported(t *testing.T) {
	for _, tc := range []struct{ name, semantic, bot string }{
		{"空值", "", ""},
		{"balanced", "balanced", "balanced"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			site := siteOf(t, exportForTest(t, []model.WAFOption{{
				WebsiteID:     1,
				SemanticLevel: tc.semantic,
				BotLevel:      tc.bot,
				BotEnabled:    true,
			}}), "1")
			if got, ok := site["semantic_level"]; ok {
				t.Errorf("默认强度不应导出 semantic_level，实际 %v", got)
			}
			if bot, ok := site["bot"].(map[string]any); ok {
				if got, ok := bot["level"]; ok {
					t.Errorf("默认强度不应导出 bot.level，实际 %v", got)
				}
			}
		})
	}
}

// 只配了强度、没开 bot/probe 的站点也必须导出。
// 这是 exporter 过滤条件的回归：早期加 Mode/BlockPage 时漏了这一步，
// 导致"界面上能配、保存后数据面毫无反应"。
func TestWAFLevelsExportedWithoutBotOrProbe(t *testing.T) {
	site := siteOf(t, exportForTest(t, []model.WAFOption{{
		WebsiteID:     1,
		SemanticLevel: "off",
		// 未开 bot / probe，也没配拦截页
	}}), "1")
	if got := site["semantic_level"]; got != "off" {
		t.Errorf("只配强度的站点也应导出 semantic_level=off，实际 %v", got)
	}
}

// 字段名契约：导出的 JSON 键必须与 Lua 侧读取的一致。
// 踩过一次真坑 —— DTO 写驼峰、Lua 读下划线，编译与测试全绿但数据面读不到。
func TestWAFLevelFieldNamesMatchLua(t *testing.T) {
	// Lua 侧 access.lua / semantic.lua 读取的字段名
	const (
		luaSemanticField = "semantic_level"
		luaBotLevelField = "level"
	)

	site := siteOf(t, exportForTest(t, []model.WAFOption{{
		WebsiteID:     1,
		SemanticLevel: "observe",
		BotLevel:      "observe",
		BotEnabled:    true,
	}}), "1")

	if _, ok := site[luaSemanticField]; !ok {
		t.Fatalf("rules.json 应含 %q（Lua 侧按下划线读），实际键：%v",
			luaSemanticField, keysOf(site))
	}
	bot, ok := site["bot"].(map[string]any)
	if !ok {
		t.Fatalf("bot 配置缺失：%v", site)
	}
	if _, ok := bot[luaBotLevelField]; !ok {
		t.Fatalf("bot 配置应含 %q，实际键：%v", luaBotLevelField, keysOf(bot))
	}
}

// DTO 校验：非法档位必须被拒。
// 放过去的话 Lua 侧会归一到 balanced —— 用户选了"高强度"实际跑的是默认档，
// 且没有任何提示。
func TestWAFLevelValidation(t *testing.T) {
	for _, lv := range []string{"off", "observe", "balanced", "high"} {
		req := request.WAFOptionUpdate{WebsiteID: 1, SemanticLevel: lv, BotLevel: lv}
		if err := validateReq(&req); err != nil {
			t.Errorf("合法档位 %q 应通过校验，实际 %v", lv, err)
		}
	}
	// 空串是 omitempty，表示"不修改"，必须放行
	req := request.WAFOptionUpdate{WebsiteID: 1, SemanticLevel: ""}
	if err := validateReq(&req); err != nil {
		t.Errorf("空档位（不修改）应放行，实际 %v", err)
	}
	for _, lv := range []string{"OFF", "High", "block", "none", "high ", "off,"} {
		req := request.WAFOptionUpdate{WebsiteID: 1, SemanticLevel: lv}
		if err := validateReq(&req); err == nil {
			t.Errorf("非法档位 %q 应被拒绝", lv)
		}
	}
}

// UpdateOption 必须真正持久化强度，且空值保持原有
// （前端只提交部分字段时不能把没带的字段清掉）。
func TestWAFLevelPersisted(t *testing.T) {
	setupWAFTestDB(t)
	svc := WAFService{syncRulesFn: func() error { return nil }}

	if err := svc.UpdateOption(request.WAFOptionUpdate{
		WebsiteID:     1,
		SemanticLevel: "high",
		BotLevel:      "off",
	}); err != nil {
		t.Fatalf("首次保存: %v", err)
	}

	opt, err := svc.GetOption(1)
	if err != nil {
		t.Fatalf("读取: %v", err)
	}
	if opt.SemanticLevel != "high" || opt.BotLevel != "off" {
		t.Errorf("强度未持久化：semantic=%q bot=%q", opt.SemanticLevel, opt.BotLevel)
	}

	// 只改一项，另一项必须保持
	if err := svc.UpdateOption(request.WAFOptionUpdate{
		WebsiteID:     1,
		SemanticLevel: "observe",
	}); err != nil {
		t.Fatalf("二次保存: %v", err)
	}
	opt, err = svc.GetOption(1)
	if err != nil {
		t.Fatalf("二次读取: %v", err)
	}
	if opt.SemanticLevel != "observe" {
		t.Errorf("semantic 应为 observe，实际 %q", opt.SemanticLevel)
	}
	if opt.BotLevel != "off" {
		t.Errorf("未提交的 bot 强度应保持 off，实际 %q（被清空了）", opt.BotLevel)
	}
}
