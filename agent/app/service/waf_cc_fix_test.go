package service

import (
	"strings"
	"testing"

	"github.com/3panel-dev/3panel/agent/app/dto/request"
	"github.com/3panel-dev/3panel/agent/app/model"
	"github.com/3panel-dev/3panel/agent/global"
)

// TestWAFCCFixDefaults 覆盖 2026-11-04 修复的 CC 默认值/显式开关语义：
//   - 新站点默认 limit=100、window=60、disabled（打开开关即可直接生效，
//     不会再出现「开关开着但 limit=0 导致数据面整层跳过」）；
//   - 开启但 limit<=0 必须明确报错，而不是静默降级成关闭；
//   - 关闭时 enabled 必须真的落库为 false（旧 model 的 gorm default:true
//     会在首次 INSERT 时把零值改写成 true，造成「界面关闭、实际开启」）。
func TestWAFCCFixDefaults(t *testing.T) {
	setupWAFTestDB(t)
	svc := WAFService{syncRulesFn: func() error { return nil }}

	cc, err := svc.GetCCConfig(100)
	if err != nil || cc == nil {
		t.Fatalf("default cc: %+v %v", cc, err)
	}
	if cc.Limit != 100 || cc.Window != 60 || cc.Enabled {
		t.Fatalf("default cc must be limit=100/window=60/disabled, got %+v", cc)
	}

	// 开启但没有有效上限：必须报错且不落库
	if err := svc.UpdateCCConfig(request.WAFCCUpdate{WebsiteID: 100, Enabled: true, Limit: 0, Window: 60, Action: model.WAFActionDeny}); err == nil {
		t.Fatal("enabled CC with limit<=0 must be rejected")
	} else if !strings.Contains(err.Error(), "CC 上限必须大于 0") {
		t.Fatalf("unexpected error: %v", err)
	}
	var persisted model.WAFCCConfig
	if err := global.DB.Where("website_id = ?", 100).First(&persisted).Error; err == nil {
		t.Fatal("rejected CC update must not be persisted")
	}

	// 首次保存为「关闭」：必须落库 false，不能被 gorm default:true 改写
	if err := svc.UpdateCCConfig(request.WAFCCUpdate{WebsiteID: 100, Enabled: false, Limit: 100, Window: 60, Action: model.WAFActionDeny}); err != nil {
		t.Fatalf("save disabled cc: %v", err)
	}
	cc, _ = svc.GetCCConfig(100)
	if cc.Enabled {
		t.Fatalf("first save with Enabled=false must persist false, got %+v", cc)
	}

	// 显式开启后正常生效
	if err := svc.UpdateCCConfig(request.WAFCCUpdate{WebsiteID: 100, Enabled: true, Limit: 200, Window: 30, Action: model.WAFActionDeny}); err != nil {
		t.Fatalf("enable cc: %v", err)
	}
	cc, _ = svc.GetCCConfig(100)
	if !cc.Enabled || cc.Limit != 200 || cc.Window != 30 {
		t.Fatalf("enabled cc wrong: %+v", cc)
	}
}
