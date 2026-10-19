package webhook_sender

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/3panel-dev/3panel/agent/constant"
)

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

func BuildWebhookPayload(method string, title string, text string) (any, error) {
	switch method {
	case constant.WeCom:
		return map[string]any{
			"msgtype": "markdown",
			"markdown": map[string]any{
				"content": fmt.Sprintf("**%s**\n%s", title, text),
			},
		}, nil
	case constant.DingTalk:
		return map[string]any{
			"msgtype": "text",
			"text": map[string]any{
				"content": fmt.Sprintf("%s\n%s", title, text),
			},
		}, nil
	case constant.FeiShu:
		return map[string]any{
			"msg_type": "text",
			"content": map[string]any{
				"text": fmt.Sprintf("%s\n%s", title, text),
			},
		}, nil
	case constant.Custom:
		return map[string]any{
			"title":   title,
			"message": text,
			"type":    "3panel_alert",
			"ts":      time.Now().Unix(),
		}, nil
	default:
		return nil, fmt.Errorf("unsupported webhook method: %s", method)
	}
}

func SendWebhookRequest(method string, url string, payload any, transport *http.Transport) error {
	return sendLegacyWebhookRequest(method, url, payload, transport)
}

func sendLegacyWebhookRequest(method string, url string, payload any, transport *http.Transport) error {
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
