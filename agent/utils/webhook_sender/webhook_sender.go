package webhook_sender

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/3panel-dev/3panel/agent/constant"
)

// 认证方式。取值同时出现在三个地方，改一处必须改另外两处：
//
//	· 本包的 Auth* 常量
//	· request.WAFWebhookUpdate.AuthType 的 oneof 校验
//	· 前端 api/modules/waf.ts 的 WAFWebhookAuthType
const (
	// AuthNone 不做认证（上游关掉了安全设置）。
	AuthNone = "none"
	// AuthKeyword 把关键词拼进消息正文，供上游做「自定义关键词」校验。
	AuthKeyword = "keyword"
	// AuthSign 对 timestamp+secret 做 HMAC-SHA256 加签，签名放在 query 里。
	// 目前只有钉钉的群机器人用这套；企微/飞书都不支持。
	AuthSign = "sign"
)

// Options 描述一次外发要用到的全部参数。
//
// 之所以把它收成一个结构体而不是继续加函数参数：认证方式、关键词、密钥
// 三者是与消息内容无关的传输层配置，散成 5 个参数后每次加一种认证都要改
// 所有调用点，而且很容易把 keyword 和 secret 传反（两者都是 string）。
type Options struct {
	Method   string
	URL      string
	AuthType string
	Keyword  string
	Secret   string
}

// KeywordPrefix 返回应当拼进正文的关键词。
//
// 只有认证方式选了 keyword 才生效：用户从「关键词」切到「加签」后，
// 旧关键词不该继续污染每一条消息（它在正文里会多出一行无意义的token）。
func (o Options) KeywordPrefix() string {
	if o.AuthType == AuthKeyword {
		return strings.TrimSpace(o.Keyword)
	}
	return ""
}

// signContent 按钉钉的约定拼接待签名串，并返回签名。
//
// 钉钉的算法是 HMAC-SHA256(key=secret, data=timestamp+"\n"+secret)，
// 再 base64。注意 key 和 data 里都含 secret，少一处就再也对不上，
// 而且上游只会回一句「sign not match」，无从定位。
func signContent(secret string, timestampMs int64) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(strconv.FormatInt(timestampMs, 10) + "\n" + secret))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

// SignDingTalkURL 在 webhook 地址上追加 timestamp 与 sign 两个 query 参数。
//
// 保留原有参数（access_token 就在 query 里），不能用「字符串拼 ?」的写法：
// 地址里已经有 ? 时再拼一个问号，access_token 会被吃掉。
func SignDingTalkURL(rawURL, secret string, now time.Time) (string, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("parse webhook url failed: %w", err)
	}
	ts := now.UnixMilli()
	q := parsed.Query()
	q.Set("timestamp", strconv.FormatInt(ts, 10))
	q.Set("sign", signContent(secret, ts))
	// Query().Encode() 会按 RFC 3986 转义 base64 里的 + / =，
	// 手拼则会把 + 变成空格，上游必然校验失败。
	parsed.RawQuery = q.Encode()
	return parsed.String(), nil
}

func NormalizeToText(s string) string {
	r := strings.NewReplacer(
		"\r\n", "\n",
		"\r", "\n",
		"<br/>", "\n",
		"<br />", "\n",
		"<br>", "\n",
		"</p>", "\n",
		"<p>", "",
		"</div>", "\n",
		"<div>", "",
		"&nbsp;", " ",
	)
	return r.Replace(s)
}

// BuildWebhookPayload 组装各家的消息体。
//
// keyword 非空时拼在正文最前面：钉钉/企微的「自定义关键词」校验只认消息
// 正文里出现的原文，塞到 title 之类自定义字段里不算数。放在最前面还有
// 一个好处 —— 关键词被截断时仍然完整（正文尾部是攻击详情，可能很长）。
func BuildWebhookPayload(method string, title string, text string, keyword string) (any, error) {
	body := text
	if prefix := strings.TrimSpace(keyword); prefix != "" {
		body = prefix + "\n" + text
	}
	switch method {
	case constant.WeCom:
		return map[string]any{
			"msgtype": "markdown",
			"markdown": map[string]any{
				"content": fmt.Sprintf("**%s**\n%s", title, body),
			},
		}, nil
	case constant.DingTalk:
		return map[string]any{
			"msgtype": "text",
			"text": map[string]any{
				"content": fmt.Sprintf("%s\n%s", title, body),
			},
		}, nil
	case constant.FeiShu:
		return map[string]any{
			"msg_type": "text",
			"content": map[string]any{
				"text": fmt.Sprintf("%s\n%s", title, body),
			},
		}, nil
	case constant.Custom:
		return map[string]any{
			"title":   title,
			"message": body,
			"type":    "3panel_alert",
			"ts":      time.Now().Unix(),
		}, nil
	default:
		return nil, fmt.Errorf("unsupported webhook method: %s", method)
	}
}

// SendWithOptions 发送一条消息，按 opts 的认证方式准备 URL 与正文。
//
// 把「认证」和「消息内容」分开之后，加一种认证方式不需要动调用方；
// 之前的实现只能传 (method, url, payload)，关键词与加签都无处安放。
func SendWithOptions(opts Options, payload any, transport *http.Transport) error {
	target := opts.URL
	switch opts.AuthType {
	case "", AuthNone:
	case AuthKeyword:
		// 关键词体现在正文里，由 BuildWebhookPayload 拼好；这里不做事。
	case AuthSign:
		if opts.Method != constant.DingTalk {
			return fmt.Errorf("webhook sign is only supported by dingTalk, got %q", opts.Method)
		}
		if opts.Secret == "" {
			return fmt.Errorf("webhook sign secret is empty")
		}
		signed, err := SignDingTalkURL(target, opts.Secret, time.Now())
		if err != nil {
			return err
		}
		target = signed
	default:
		return fmt.Errorf("unsupported webhook auth type: %s", opts.AuthType)
	}
	return sendWebhookRequest(opts.Method, target, payload, transport)
}

func sendWebhookRequest(method string, url string, payload any, transport *http.Transport) error {
	if url == "" {
		return fmt.Errorf("send webhook request failed: url is empty")
	}
	if payload == nil {
		return fmt.Errorf("send webhook request failed: payload is nil")
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal webhook payload failed")
	}
	client := &http.Client{Timeout: RequestTimeout}
	if transport != nil {
		client.Transport = transport
	}
	ctx, cancel := context.WithTimeout(context.Background(), RequestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create webhook request failed")
	}
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("webhook request failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("webhook response status code: %d", resp.StatusCode)
	}
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read webhook response failed")
	}
	switch method {
	case constant.WeCom, constant.DingTalk:
		var result struct {
			Errcode int    `json:"errcode"`
			Errmsg  string `json:"errmsg"`
		}
		if err := json.Unmarshal(respBody, &result); err != nil {
			return nil
		}
		if result.Errcode != 0 {
			// 带上上游的 errcode/errmsg：钉钉的关键词不匹配、签名校验失败、
			// 企微的机器人被移出群，都会走到这里。只回一句「rejected」的话，
			// 用户在界面上看到的就是「通知发不出去」，无从自查。
			return fmt.Errorf("webhook provider rejected response: errcode=%d, errmsg=%s",
				result.Errcode, strings.TrimSpace(result.Errmsg))
		}
	case constant.FeiShu:
		var result struct {
			StatusCode int    `json:"StatusCode"`
			Code       int    `json:"code"`
			Msg        string `json:"msg"`
		}
		if err := json.Unmarshal(respBody, &result); err != nil {
			return nil
		}
		if result.StatusCode != 0 || result.Code != 0 {
			return fmt.Errorf("webhook provider rejected response: code=%d, msg=%s",
				result.Code, strings.TrimSpace(result.Msg))
		}
	}
	return nil
}
