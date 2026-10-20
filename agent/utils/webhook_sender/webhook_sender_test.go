package webhook_sender

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

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

	payload, err := BuildWebhookPayload(constant.DingTalk, "title", "text", "")
	if err != nil {
		t.Fatalf("build payload: %v", err)
	}
	err = SendWithOptions(Options{Method: constant.DingTalk, URL: srv.URL}, payload, nil)
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

	payload, _ := BuildWebhookPayload(constant.DingTalk, "title", "text", "")
	if err := SendWithOptions(Options{Method: constant.DingTalk, URL: srv.URL}, payload, nil); err != nil {
		t.Fatalf("errcode=0 应视为成功，实际 %v", err)
	}
}

// 飞书用的是 code/msg，报错同样要带出来。
func TestSendWebhookSurfacesFeishuError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"code":19021,"msg":"sign match fail"}`))
	}))
	defer srv.Close()

	payload, _ := BuildWebhookPayload(constant.FeiShu, "title", "text", "")
	err := SendWithOptions(Options{Method: constant.FeiShu, URL: srv.URL}, payload, nil)
	if err == nil || !strings.Contains(err.Error(), "sign match fail") {
		t.Fatalf("应带出飞书 msg，实际 %v", err)
	}
}

// 加签的待签名串与签名算法按钉钉文档固定为
// HMAC-SHA256(key=secret, data=timestamp+"\n"+secret) → base64。
// 这里用一条独立算好的标准向量锁住算法 —— 改错任何一处（key/data 用反、
// 漏掉换行、base64 变 hex）都会让这条用例变红。
func TestSignDingTalkURLMatchesKnownVector(t *testing.T) {
	const secret = "SECtest"
	const tsMillis = int64(1700000000123)
	fixed := time.UnixMilli(tsMillis)

	signed, err := SignDingTalkURL("https://oapi.dingtalk.com/robot/send?access_token=abc", secret, fixed)
	if err != nil {
		t.Fatalf("sign url: %v", err)
	}
	// 标准向量由 python hmac 独立计算：
	//   hmac-sha256(key=b"SECtest", msg=b"1700000000123\nSECtest") → base64
	// 注意 query 编码后 base64 的 = 会变成 %3D，比较要放在解析后的 query 上做。
	const wantSign = "lrMq5E54T40t3FfGVjxdvoqIbXlWY6mzkZYiVoI6emk="
	parsed, err := url.Parse(signed)
	if err != nil {
		t.Fatalf("parse signed url: %v", err)
	}
	q := parsed.Query()
	if q.Get("timestamp") != "1700000000123" {
		t.Errorf("timestamp 错误: %s", signed)
	}
	if q.Get("sign") != wantSign {
		t.Errorf("签名与标准向量不符: got %q want %q", q.Get("sign"), wantSign)
	}
	// access_token 必须保留：query 里已有参数时不能拼出第二个 ? 把它吃掉。
	if !strings.Contains(signed, "access_token=abc") {
		t.Errorf("access_token 丢失: %s", signed)
	}
	// base64 的 + / = 必须被 RFC3986 转义，空格会把签名废掉。
	if strings.Contains(signed, "+") {
		t.Errorf("base64 未做 URL 转义: %s", signed)
	}
}

// 加签只支持钉钉：渠道选错要在发请求之前就报错，而不是等上游拒。
func TestSendWithOptionsRejectsSignForNonDingTalk(t *testing.T) {
	err := SendWithOptions(
		Options{Method: constant.WeCom, URL: "https://example.com", AuthType: AuthSign, Secret: "SECx"},
		map[string]any{"msgtype": "text"}, nil,
	)
	if err == nil || !strings.Contains(err.Error(), "dingTalk") {
		t.Fatalf("企微+加签应前置报错，实际 %v", err)
	}
}

// 加签缺密钥同样要前置报错（ Secrets 可能从没设置过）。
func TestSendWithOptionsRejectsSignWithoutSecret(t *testing.T) {
	err := SendWithOptions(
		Options{Method: constant.DingTalk, URL: "https://example.com", AuthType: AuthSign},
		map[string]any{"msgtype": "text"}, nil,
	)
	if err == nil || !strings.Contains(err.Error(), "secret") {
		t.Fatalf("加签缺密钥应前置报错，实际 %v", err)
	}
}

// 关键词拼在正文最前面 —— 钉钉/企微的「自定义关键词」只认正文原文，
// 塞在自定义字段里不算数。
func TestBuildPayloadPrefixesKeyword(t *testing.T) {
	payload, err := BuildWebhookPayload(constant.DingTalk, "title", "body", "WAF")
	if err != nil {
		t.Fatalf("build payload: %v", err)
	}
	content := payload.(map[string]any)["text"].(map[string]any)["content"].(string)
	// 关键词在正文（body）最前；整条 content 的格式是 "title\n关键词\n正文"。
	if !strings.Contains(content, "\nWAF\nbody") {
		t.Errorf("关键词应拼在正文最前，实际 %q", content)
	}
}

// 切到「加签」后旧关键词不能再污染正文：
// KeywordPrefix 只在 authType=keyword 时返回值。
func TestKeywordPrefixOnlyAppliesToKeywordAuth(t *testing.T) {
	o := Options{AuthType: AuthKeyword, Keyword: " WAF "}
	if got := o.KeywordPrefix(); got != "WAF" {
		t.Errorf("keyword 模式应返回去空白后的关键词，实际 %q", got)
	}
	o.AuthType = AuthSign
	if got := o.KeywordPrefix(); got != "" {
		t.Errorf("sign 模式不应再带关键词，实际 %q", got)
	}
	o.AuthType = AuthNone
	if got := o.KeywordPrefix(); got != "" {
		t.Errorf("none 模式不应带关键词，实际 %q", got)
	}
}

// 端到端：加签模式下发给测试服务器的请求应带 timestamp/sign 且不带关键词。
func TestSendWithOptionsSignsRequest(t *testing.T) {
	var gotQuery string
	var gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		buf, _ := io.ReadAll(r.Body)
		gotBody = string(buf)
		_, _ = w.Write([]byte(`{"errcode":0,"errmsg":"ok"}`))
	}))
	defer srv.Close()

	opts := Options{Method: constant.DingTalk, URL: srv.URL, AuthType: AuthSign, Secret: "SECtest", Keyword: "WAF"}
	payload, _ := BuildWebhookPayload(opts.Method, "t", "body", opts.KeywordPrefix())
	if err := SendWithOptions(opts, payload, nil); err != nil {
		t.Fatalf("send: %v", err)
	}
	if !strings.Contains(gotQuery, "timestamp=") || !strings.Contains(gotQuery, "sign=") {
		t.Errorf("请求缺少加签参数: %s", gotQuery)
	}
	if strings.Contains(gotBody, "WAF") {
		t.Errorf("加签模式正文不应包含关键词，实际 %s", gotBody)
	}
}
