package service

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/3panel-dev/3panel/agent/app/model"
	"github.com/3panel-dev/3panel/agent/global"
)

// WAFReportEvent 是一次拦截事件的上报载荷。
//
// 隐私边界：不含 header / cookie / 请求体。只带检测引擎判定命中的
// 那一个参数值（Payload），以及定位问题必需的 URL 与攻击类型。
// 用户 IP 不由面板填写 —— Worker 强制校验上报 IP 等于请求来源 IP，
// 避免被伪造后用来推别人进全局名单。
type WAFReportEvent struct {
	AttackType string `json:"attackType"`
	URL        string `json:"url"`
	Payload    string `json:"payload"`
	Method     string `json:"method"`
	UA         string `json:"ua"`
	Website    string `json:"website"`
}

var reportClient = &http.Client{Timeout: 10 * time.Second}

// postReport 向社区 Worker 上报一条拦截事件。
// 失败只记日志：上报是可选的旁路，不能影响拦截主流程。
func postReport(reportURL, panelID string, ev WAFReportEvent) error {
	body, err := json.Marshal(map[string]string{
		"panelId":    panelID,
		"attackType": ev.AttackType,
		"url":        ev.URL,
		"payload":    ev.Payload,
		"method":     ev.Method,
		"ua":         ev.UA,
		"website":    ev.Website,
	})
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, reportURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "3panel-waf-iplist/2")
	resp, err := reportClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("report http %d", resp.StatusCode)
	}
	return nil
}

// ensurePanelID 生成并持久化本实例的稳定标识。
//
// 它是上报去重的维度：若每次上报都换 ID，单个实例就能伪装成多个独立
// 实例把某个 IP 刷上升格阈值。因此只在首次生成随机值，之后一律从 DB 读回。
func ensurePanelID() string {
	var s model.WAFIPListSetting
	if global.DB.First(&s).Error == nil && s.PanelID != "" {
		return s.PanelID
	}
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err != nil {
		// 熵源不可用时退回时间戳。仅此时会退化，
		// 正常路径不会走到。
		sum := sha256.Sum256([]byte(fmt.Sprintf("panel-%d", time.Now().UnixNano())))
		copy(buf[:], sum[:16])
	}
	id := hex.EncodeToString(buf[:])
	if s.ID != 0 {
		// 已有记录则只更新该字段，避免覆盖用户刚保存的配置。
		global.DB.Model(&s).Update("panel_id", id)
	} else {
		s.PanelID = id
		global.DB.Save(&s)
	}
	return id
}
