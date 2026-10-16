package service

import (
	"testing"

	"github.com/3panel-dev/3panel/agent/app/dto/request"
	"github.com/3panel-dev/3panel/agent/app/model"
	"github.com/3panel-dev/3panel/agent/constant"
	"github.com/3panel-dev/3panel/agent/global"
	"github.com/go-playground/validator/v10"
)

// WAF webhook 的渠道取值必须与 webhook_sender.BuildWebhookPayload 的
// switch 分支、以及 constant 里的常量完全一致。
//
// 背景：DTO 的 validate tag 曾写成小写 "wecom dingtalk feishu"，而常量是
// 驼峰 "weCom dingTalk feiShu"。前端按常量传驼峰值会被 oneof 校验直接拒绝，
// 表现为「界面能填、保存就报参数错误」，而面板里又没有这个配置界面，
// 于是这个功能从上线起就没人能用过。
//
// 下面这组用例把「DTO tag 接受的取值」与「constant 的常量」绑在一起，
// 任何人改其中一边而不改另一边都会红。

func TestWAFWebhookMethodTagAcceptsConstantValues(t *testing.T) {
	for _, method := range []string{
		constant.WeCom,
		constant.DingTalk,
		constant.FeiShu,
		constant.Custom,
	} {
		req := request.WAFWebhookUpdate{Enable: true, Method: method, URL: "https://example.com/hook"}
		if err := validateReq(&req); err != nil {
			t.Errorf("渠道 %q 被 DTO 校验拒绝，但它是 constant 里定义的合法渠道: %v", method, err)
		}
	}
}

func TestWAFWebhookMethodTagRejectsUnknownValue(t *testing.T) {
	req := request.WAFWebhookUpdate{Enable: true, Method: "not-a-channel", URL: "https://example.com/hook"}
	if err := validateReq(&req); err == nil {
		t.Error("未知渠道值应被 oneof 校验拒绝，否则 BuildWebhookPayload 会静默走 default 分支")
	}
}

func TestWAFWebhookUpdateRequiresURLWhenEnabled(t *testing.T) {
	// 开着通知但没填地址 = 每条拦截事件都往空 URL 发，goroutine 白跑且用户收不到。
	// 这条约束必须落在 DTO 上，前端也要跟着置灰保存按钮。
	req := request.WAFWebhookUpdate{Enable: true, Method: constant.Custom, URL: ""}
	if err := validateReq(&req); err == nil {
		t.Error("启用通知时 URL 为空应被拒绝，否则 pushWebhooks 每条事件都会失败")
	}
}

// 关掉通知时不该强制填 URL —— 用户可能先关掉再慢慢配。
func TestWAFWebhookUpdateAllowsEmptyURLWhenDisabled(t *testing.T) {
	req := request.WAFWebhookUpdate{Enable: false, Method: constant.Custom, URL: ""}
	if err := validateReq(&req); err != nil {
		t.Errorf("通知关闭状态下 URL 为空应允许: %v", err)
	}
}

// 设置项必须能往返：读回来的值与写进去的一致，
// 否则界面上保存成功、刷新后回到旧值。
func TestWAFWebhookSettingRoundTrip(t *testing.T) {
	setupWAFTestDB(t)
	if err := global.DB.AutoMigrate(&model.Setting{}); err != nil {
		t.Fatalf("migrate setting: %v", err)
	}
	svc := WAFService{}

	want := request.WAFWebhookUpdate{
		Enable: true,
		Method: constant.FeiShu,
		URL:    "https://open.feishu.cn/open-apis/bot/v2/hook/abc",
	}
	if err := svc.UpdateWebhookSetting(want); err != nil {
		t.Fatalf("UpdateWebhookSetting: %v", err)
	}

	got, err := svc.GetWebhookSetting()
	if err != nil {
		t.Fatalf("GetWebhookSetting: %v", err)
	}
	if got["enable"] != true {
		t.Errorf("enable 应为 true，实际 %v", got["enable"])
	}
	if got["method"] != constant.FeiShu {
		t.Errorf("method 应为 %q，实际 %v", constant.FeiShu, got["method"])
	}
	if got["url"] != want.URL {
		t.Errorf("url 应为 %q，实际 %v", want.URL, got["url"])
	}
}

// 默认值：从未配置过时必须给出可用的 custom，而不是空 method ——
// 空 method 会让 BuildWebhookPayload 走 default 分支返回错误。
func TestWAFWebhookSettingDefaults(t *testing.T) {
	setupWAFTestDB(t)
	if err := global.DB.AutoMigrate(&model.Setting{}); err != nil {
		t.Fatalf("migrate setting: %v", err)
	}
	got, err := WAFService{}.GetWebhookSetting()
	if err != nil {
		t.Fatalf("GetWebhookSetting: %v", err)
	}
	if got["enable"] != false {
		t.Errorf("未配置时 enable 应默认 false，实际 %v", got["enable"])
	}
	if got["method"] != constant.Custom {
		t.Errorf("未配置时 method 应默认 %q，实际 %v", constant.Custom, got["method"])
	}
}

// validateReq 复现 helper.CheckBindAndValidate 里那一步 DTO 校验。
// 服务层单测不经过 gin，所以直接用全局校验器实例，
// 保证测的就是线上真正跑的那套 tag 规则。
func validateReq(req interface{}) error {
	if global.VALID == nil {
		global.VALID = validator.New()
	}
	return global.VALID.Struct(req)
}
