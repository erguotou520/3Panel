package webhook_sender

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/3panel-dev/3panel/agent/constant"
)

// 上游拒绝时必须把 errcode/errmsg 带出来。
//
// 钉钉的关键词不匹配（310000）、签名校验失败，企微的机器人被移出群，
// 最终都表现在这一个响应体里。只回一句「provider rejected response」的话，
// 用户看到的就是「配了通知但一条也收不到」，且没有任何可自查的线索 ——
// 现场就是这么卡住的：手工 curl 一次才看到「关键词不匹配」。
func TestSendWebhookSurfacesProviderError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"errcode":310000,"errmsg":"keywords not in content"}`))
	}))
	defer srv.Close()

	payload, err := BuildWebhookPayload(constant.DingTalk, "title", "text")
	if err != nil {
		t.Fatalf("build payload: %v", err)
	}
	err = SendWebhookRequest(constant.DingTalk, srv.URL, payload, nil)
	if err == nil {
		t.Fatal("errcode != 0 时必须返回错误")
	}
	if !strings.Contains(err.Error(), "310000") {
		t.Errorf("错误信息应包含 errcode，实际 %q", err.Error())
	}
	if !strings.Contains(err.Error(), "keywords not in content") {
		t.Errorf("错误信息应包含上游 errmsg，实际 %q", err.Error())
	}
}

// errcode=0 表示发送成功，不能被当成失败。
func TestSendWebhookAcceptsOkResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"errcode":0,"errmsg":"ok"}`))
	}))
	defer srv.Close()

	payload, _ := BuildWebhookPayload(constant.DingTalk, "title", "text")
	if err := SendWebhookRequest(constant.DingTalk, srv.URL, payload, nil); err != nil {
		t.Fatalf("errcode=0 应视为成功，实际 %v", err)
	}
}

// 飞书用的是 code/msg，报错同样要带出来。
func TestSendWebhookSurfacesFeishuError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"code":19021,"msg":"sign match fail"}`))
	}))
	defer srv.Close()

	payload, _ := BuildWebhookPayload(constant.FeiShu, "title", "text")
	err := SendWebhookRequest(constant.FeiShu, srv.URL, payload, nil)
	if err == nil || !strings.Contains(err.Error(), "sign match fail") {
		t.Fatalf("应带出飞书 msg，实际 %v", err)
	}
}
