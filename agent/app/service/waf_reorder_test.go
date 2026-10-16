package service

import (
	"errors"
	"io"
	"testing"

	"github.com/3panel-dev/3panel/agent/app/dto/request"
	"github.com/3panel-dev/3panel/agent/app/model"
	"github.com/3panel-dev/3panel/agent/global"
	"github.com/sirupsen/logrus"
)

func seedReorderRules(t *testing.T, n int) []model.WAFRule {
	t.Helper()
	rules := make([]model.WAFRule, 0, n)
	for i := 0; i < n; i++ {
		rules = append(rules, model.WAFRule{
			Name:       "rule-" + string(rune('A'+i)),
			Scope:      model.WAFScopeGlobal,
			Priority:   100 + i, // 故意乱序，证明重排真的生效
			MatchType:  "ip",
			MatchValue: "10.0.0." + string(rune('1'+i)),
			MatchOp:    "exact",
			Action:     model.WAFActionDeny,
			Enabled:    true,
		})
	}
	if err := global.DB.Create(&rules).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}
	return rules
}

func rulePriorityMap(t *testing.T, ids []uint) map[uint]int {
	t.Helper()
	out := map[uint]int{}
	for _, id := range ids {
		var r model.WAFRule
		if err := global.DB.First(&r, id).Error; err != nil {
			t.Fatalf("read rule %d: %v", id, err)
		}
		out[id] = r.Priority
	}
	return out
}

func TestWAFReorderRulesAssignsAscendingPriority(t *testing.T) {
	setupWAFTestDB(t)
	rules := seedReorderRules(t, 3)
	svc := WAFService{syncRulesFn: func() error { return nil }}

	// 反转顺序：最后一条排最前
	ids := []uint{rules[2].ID, rules[1].ID, rules[0].ID}
	if err := svc.ReorderRules(request.WAFRuleReorder{IDs: ids}); err != nil {
		t.Fatalf("ReorderRules: %v", err)
	}
	got := rulePriorityMap(t, ids)
	if got[ids[0]] >= got[ids[1]] || got[ids[1]] >= got[ids[2]] {
		t.Errorf("优先级应严格递增（越小越靠前），实际 %v", got)
	}
	if got[ids[0]] != 10 {
		t.Errorf("第一条应是最高优先级 10，实际 %d", got[ids[0]])
	}
}

func TestWAFReorderRulesUsesStepOfTen(t *testing.T) {
	setupWAFTestDB(t)
	rules := seedReorderRules(t, 3)
	svc := WAFService{syncRulesFn: func() error { return nil }}
	ids := []uint{rules[0].ID, rules[1].ID, rules[2].ID}
	if err := svc.ReorderRules(request.WAFRuleReorder{IDs: ids}); err != nil {
		t.Fatalf("ReorderRules: %v", err)
	}
	got := rulePriorityMap(t, ids)
	// 步长 10 是刻意留的：用户在中间新建规则时不必重排全部。
	for i, id := range ids {
		want := (i + 1) * 10
		if got[id] != want {
			t.Errorf("第 %d 条优先级应为 %d，实际 %d", i+1, want, got[id])
		}
	}
}

// 拖动排序不能是静默失败：不存在的 ID 必须报错，
// 否则用户以为排好了，实际部分规则没动而界面看不出差别。
func TestWAFReorderRulesRejectsUnknownID(t *testing.T) {
	setupWAFTestDB(t)
	rules := seedReorderRules(t, 2)
	svc := WAFService{syncRulesFn: func() error { return nil }}
	ids := []uint{rules[0].ID, 999999}
	if err := svc.ReorderRules(request.WAFRuleReorder{IDs: ids}); err == nil {
		t.Fatal("含不存在的 ID 时应报错")
	}
	// 失败后不应改动任何规则的优先级
	got := rulePriorityMap(t, []uint{rules[0].ID, rules[1].ID})
	if got[rules[0].ID] != rules[0].Priority || got[rules[1].ID] != rules[1].Priority {
		t.Errorf("重排失败后不应留下半更新状态: %v（原始 %d/%d）",
			got, rules[0].Priority, rules[1].Priority)
	}
}

func TestWAFReorderRulesRejectsDuplicateID(t *testing.T) {
	setupWAFTestDB(t)
	rules := seedReorderRules(t, 2)
	svc := WAFService{syncRulesFn: func() error { return nil }}
	ids := []uint{rules[0].ID, rules[0].ID}
	if err := svc.ReorderRules(request.WAFRuleReorder{IDs: ids}); err == nil {
		t.Fatal("重复 ID 应被拒绝，否则编号互相覆盖")
	}
}

func TestWAFReorderRulesRejectsEmptyList(t *testing.T) {
	setupWAFTestDB(t)
	svc := WAFService{syncRulesFn: func() error { return nil }}
	if err := svc.ReorderRules(request.WAFRuleReorder{IDs: []uint{}}); err == nil {
		t.Fatal("空列表应被拒绝")
	}
}

// 数据面同步失败时必须回滚优先级 —— 优先级直接决定名单生效顺序，
// 留一半旧一半新就是防护行为不确定。
func TestWAFReorderRulesRollsBackOnSyncError(t *testing.T) {
	setupWAFTestDB(t)
	// global.LOG 默认是 nil，而回滚路径会打错误日志 ——
	// nil 接收器上调 Errorf 直接 panic。测试里必须先初始化。
	if global.LOG == nil {
		global.LOG = logrus.New()
		global.LOG.SetOutput(io.Discard)
	}
	rules := seedReorderRules(t, 2)
	svc := WAFService{syncRulesFn: func() error { return errors.New("sync failed") }}

	ids := []uint{rules[1].ID, rules[0].ID}
	if err := svc.ReorderRules(request.WAFRuleReorder{IDs: ids}); err == nil {
		t.Fatal("数据面同步失败时应返回错误")
	}
	got := rulePriorityMap(t, ids)
	if got[rules[0].ID] != rules[0].Priority {
		t.Errorf("同步失败后规则 %d 的优先级应回滚到 %d，实际 %d",
			rules[0].ID, rules[0].Priority, got[rules[0].ID])
	}
	if got[rules[1].ID] != rules[1].Priority {
		t.Errorf("同步失败后规则 %d 的优先级应回滚到 %d，实际 %d",
			rules[1].ID, rules[1].Priority, got[rules[1].ID])
	}
}

// 部分重排是合法的：用户只拖了当前列表的一部分。
// 未包含的规则优先级保持不变。
func TestWAFReorderRulesSupportsPartialList(t *testing.T) {
	setupWAFTestDB(t)
	rules := seedReorderRules(t, 4)
	svc := WAFService{syncRulesFn: func() error { return nil }}

	ids := []uint{rules[3].ID, rules[0].ID}
	if err := svc.ReorderRules(request.WAFRuleReorder{IDs: ids}); err != nil {
		t.Fatalf("ReorderRules: %v", err)
	}
	got := rulePriorityMap(t, ids)
	if got[rules[3].ID] != 10 || got[rules[0].ID] != 20 {
		t.Errorf("部分重排的编号不对: %v", got)
	}
	// 未包含的两条保持原值
	for _, r := range rules[1:3] {
		var gotRule model.WAFRule
		if err := global.DB.First(&gotRule, r.ID).Error; err != nil {
			t.Fatalf("read: %v", err)
		}
		if gotRule.Priority != r.Priority {
			t.Errorf("未参与重排的规则 %d 优先级被改了: %d -> %d",
				r.ID, r.Priority, gotRule.Priority)
		}
	}
}

// 重排后 ListRules 的返回顺序必须与传入顺序一致 ——
// 界面是按 ListRules 结果渲染的，两者不一致等于排序没生效。
func TestWAFReorderRulesListOrderMatches(t *testing.T) {
	setupWAFTestDB(t)
	rules := seedReorderRules(t, 3)
	svc := WAFService{syncRulesFn: func() error { return nil }}

	ids := []uint{rules[2].ID, rules[0].ID, rules[1].ID}
	if err := svc.ReorderRules(request.WAFRuleReorder{IDs: ids}); err != nil {
		t.Fatalf("ReorderRules: %v", err)
	}
	list, err := svc.ListRules(request.WAFRuleSearch{Scope: model.WAFScopeGlobal})
	if err != nil {
		t.Fatalf("ListRules: %v", err)
	}
	if len(list) != 3 {
		t.Fatalf("应返回 3 条，实际 %d", len(list))
	}
	for i, want := range ids {
		if list[i].ID != want {
			t.Fatalf("列表第 %d 条应为规则 %d，实际 %d（顺序: %d,%d,%d）",
				i+1, want, list[i].ID, list[0].ID, list[1].ID, list[2].ID)
		}
	}
}
