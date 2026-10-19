package service

import (
	"testing"

	"github.com/3panel-dev/3panel/agent/app/dto/request"
	"github.com/3panel-dev/3panel/agent/app/model"
	"github.com/3panel-dev/3panel/agent/global"
)

// 「没传」与「传空串」必须是两件事。
//
// 旧实现用 string + `if req.X != ""`，于是：
//
//	· 用户把「SQL 注入」重新勾上（前端传 disabledDetectors=""）→ 被当成没改，
//	  检测器永远保持禁用；
//	· 用户清空自定义拦截页文案 → 旧文案永远清不掉。
//
// 两种都表现为「点保存没反应」，而且没有任何报错。
func TestWAFOptionCanClearFields(t *testing.T) {
	setupWAFTestDB(t)
	svc := WAFService{syncRulesFn: func() error { return nil }}

	// 先写入自定义值
	if err := svc.UpdateOption(request.WAFOptionUpdate{
		WebsiteID:          9,
		BlockPageTitle:     strPtr("自定义标题"),
		BlockPageBody:      strPtr("自定义正文"),
		BlockPageBgColor:   strPtr("#ff0000"),
		BlockPageTextColor: strPtr("#ffffff"),
		DisabledDetectors:  strPtr("sqli,xss"),
	}); err != nil {
		t.Fatalf("写入: %v", err)
	}

	// 只带空串：应把四个字段清空、检测器全部恢复
	if err := svc.UpdateOption(request.WAFOptionUpdate{
		WebsiteID:          9,
		BlockPageTitle:     strPtr(""),
		BlockPageBody:      strPtr(""),
		BlockPageBgColor:   strPtr(""),
		BlockPageTextColor: strPtr(""),
		DisabledDetectors:  strPtr(""),
	}); err != nil {
		t.Fatalf("清空: %v", err)
	}

	var got model.WAFOption
	if err := global.DB.Where("website_id = ?", 9).First(&got).Error; err != nil {
		t.Fatalf("读回: %v", err)
	}
	if got.BlockPageTitle != "" || got.BlockPageBody != "" ||
		got.BlockPageBgColor != "" || got.BlockPageTextColor != "" {
		t.Errorf("拦截页字段未被清空: %+v", got)
	}
	if got.DisabledDetectors != "" {
		t.Errorf("检测器未被全部恢复，仍为 %q", got.DisabledDetectors)
	}
}

// 只传部分字段（nil）时，其余字段必须保持原值 —— 这是指针方案的另一个方向：
// 不能为了修「清空」把「局部更新」弄坏。
func TestWAFOptionPartialUpdateKeepsOthers(t *testing.T) {
	setupWAFTestDB(t)
	svc := WAFService{syncRulesFn: func() error { return nil }}

	if err := svc.UpdateOption(request.WAFOptionUpdate{
		WebsiteID:         11,
		Mode:              "observe",
		BlockPageTitle:    strPtr("保留我"),
		DisabledDetectors: strPtr("sqli"),
	}); err != nil {
		t.Fatalf("首次写入: %v", err)
	}
	// 只改 bot 开关（其它字段不传 = nil）
	if err := svc.UpdateOption(request.WAFOptionUpdate{WebsiteID: 11, BotEnabled: true}); err != nil {
		t.Fatalf("局部更新: %v", err)
	}

	var got model.WAFOption
	if err := global.DB.Where("website_id = ?", 11).First(&got).Error; err != nil {
		t.Fatalf("读回: %v", err)
	}
	if got.BlockPageTitle != "保留我" {
		t.Errorf("未传的 BlockPageTitle 被清空了: %q", got.BlockPageTitle)
	}
	if got.DisabledDetectors != "sqli" {
		t.Errorf("未传的 DisabledDetectors 被清空了: %q", got.DisabledDetectors)
	}
	if got.Mode != "observe" {
		t.Errorf("未传的 Mode 被清空了: %q", got.Mode)
	}
	if !got.BotEnabled {
		t.Error("BotEnabled 应被更新为 true")
	}
}
