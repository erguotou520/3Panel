package service

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/rand"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/3panel-dev/3panel/agent/app/model"
	"github.com/3panel-dev/3panel/agent/global"
	"github.com/3panel-dev/3panel/agent/utils/waf/iplistsync"
)

const (
	// 订阅刷新的最小间隔。低于 2 小时没有意义：CI 每天只跑两次，
	// 再频繁也拉不到新内容，只会白跑网络。
	minIPListInterval = 2
	// 首次拉取的抖动上限。全部实例在同一秒打 CI 会形成尖峰，
	// 也不利于源站的限流策略。
	initialJitter = 90 * time.Minute
)

var (
	ipListOnce    sync.Once
	ipListNextRun time.Time
	ipListClient  *iplistsync.Client
)

// wafIPListClient 返回进程内单例的订阅客户端。
func wafIPListClient() (*iplistsync.Client, error) {
	confDir, err := wafHostConfDir()
	if err != nil {
		return nil, err
	}
	ipListOnce.Do(func() {
		ipListClient = iplistsync.NewClient(
			filepath.Join(confDir, "waf"), nil,
		)
	})
	return ipListClient, nil
}

func (w WAFService) getIPListSetting() model.WAFIPListSetting {
	var s model.WAFIPListSetting
	if global.DB.First(&s).Error != nil {
		return model.WAFIPListSetting{ID: 1, Enabled: false, AutoUpdate: true, IntervalHours: 12}
	}
	if s.IntervalHours < minIPListInterval {
		s.IntervalHours = minIPListInterval
	}
	if s.PanelID == "" {
		s.PanelID = ensurePanelID()
	}
	return s
}

// UpdateIPListSetting 保存订阅配置。
func (w WAFService) UpdateIPListSetting(req model.WAFIPListSetting) error {
	if req.IntervalHours < minIPListInterval {
		req.IntervalHours = minIPListInterval
	}
	if req.ReportURL != "" && !strings.HasPrefix(req.ReportURL, "https://") {
		return fmt.Errorf("上报地址必须以 https:// 开头")
	}
	s := w.getIPListSetting()
	s.Enabled = req.Enabled
	s.AutoUpdate = req.AutoUpdate
	s.IntervalHours = req.IntervalHours
	s.ReportEnabled = req.ReportEnabled
	s.ReportURL = req.ReportURL
	// PanelID 是本实例的稳定哈希，只在首次生成后固化：
	// 上报端用它做去重，若每次都变则单个实例能伪装成多个。
	if s.PanelID == "" {
		s.PanelID = ensurePanelID()
	}
	if err := global.DB.Save(&s).Error; err != nil {
		return err
	}
	ipListNextRun = time.Time{}
	return nil
}

// GetIPListStatus 返回订阅状态供前端展示。
func (w WAFService) GetIPListStatus() (map[string]interface{}, error) {
	s := w.getIPListSetting()
	out := map[string]interface{}{
		"enabled":       s.Enabled,
		"autoUpdate":    s.AutoUpdate,
		"intervalHours": s.IntervalHours,
		"reportEnabled": s.ReportEnabled,
		"reportUrl":     s.ReportURL,
	}
	c, err := wafIPListClient()
	if err != nil {
		return out, nil
	}
	st, err := c.Status()
	if err != nil {
		out["installed"] = false
		return out, nil
	}
	out["installed"] = true
	out["sha256"] = st.SHA256
	out["generatedAt"] = st.GeneratedAt
	out["countV4"] = st.CountV4
	out["countV6"] = st.CountV6
	out["size"] = st.Size
	out["source"] = st.Source
	// 制品生成时间超过 2 天即视为过期，提醒用户检查镜像可达性。
	out["stale"] = time.Since(parseGeneratedAt(st.GeneratedAt)) > 48*time.Hour
	return out, nil
}

// SyncIPList 立即拉取一次订阅。供 API 手动触发与 cron 共用。
func (w WAFService) SyncIPList() (map[string]interface{}, error) {
	s := w.getIPListSetting()
	c, err := wafIPListClient()
	if err != nil {
		return nil, err
	}
	changed, source, err := c.Update()
	result := map[string]interface{}{"changed": changed, "source": source}
	if err != nil {
		// 拉取失败不是致命错误：本地旧数据继续生效，
		// 这里只把错误带回前端展示，不中断 cron。
		result["error"] = err.Error()
		global.LOG.Warnf("waf iplist update failed: %v", err)
	}
	st, serr := c.Status()
	if serr == nil {
		result["sha256"] = st.SHA256
		result["countV4"] = st.CountV4
		result["generatedAt"] = st.GeneratedAt
		result["source"] = st.Source
	}
	_ = s
	return result, nil
}

// SyncIPListIfDue 由 cron 每分钟调用，按配置决定是否真的拉取。
// 首次启用时加随机抖动，避免所有实例同时打 CI。
func (w WAFService) SyncIPListIfDue() {
	s := w.getIPListSetting()
	if !s.Enabled || !s.AutoUpdate {
		ipListNextRun = time.Time{}
		return
	}
	now := time.Now()
	if ipListNextRun.IsZero() {
		ipListNextRun = now.Add(time.Duration(rand.Int63n(int64(initialJitter))))
		return
	}
	if now.Before(ipListNextRun) {
		return
	}
	ipListNextRun = now.Add(time.Duration(s.IntervalHours) * time.Hour)

	c, err := wafIPListClient()
	if err != nil {
		return
	}
	changed, _, err := c.Update()
	if err != nil {
		global.LOG.Warnf("waf iplist scheduled update failed: %v", err)
		return
	}
	if changed {
		global.LOG.Infof("waf iplist updated")
	}
}

func parseGeneratedAt(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Now()
	}
	return t
}

// ==================== 上报 ====================

// ReportEvent 上报一次拦截事件到社区 Worker。
// 隐私：只发送检测引擎判定命中的那一个参数值，不带 header/cookie/body。
func (w WAFService) ReportEvent(ev WAFReportEvent) error {
	s := w.getIPListSetting()
	if !s.ReportEnabled || s.ReportURL == "" {
		return nil
	}
	return postReport(s.ReportURL, s.PanelID, ev)
}

// pushReports 把本轮入库的拦截事件上报到社区 Worker。
//
// 隐私边界：只发送 URL、攻击类型、UA 与命中参数，不发送
// requestBody / query / cookie / 任何请求头。这些字段可能被
// sanitize_log_value 处理过，但保守起见这里根本不取。
//
// 只上报 action=deny 的事件：log/challenge 是观察不是拦截，
// 上报它们会污染「这个 IP 确实在攻击」的判断。
func (w WAFService) pushReports(logs []model.WAFLog) {
	setting := w.getIPListSetting()
	if !setting.ReportEnabled || setting.ReportURL == "" {
		return
	}
	// 上报是旁路：即使全量失败也不能拖慢日志入库，
	// 也不该让一条 HTTP 失败刷满日志。
	var batch []model.WAFLog
	for _, l := range logs {
		if l.Action == model.WAFActionDeny && l.IP != "" {
			batch = append(batch, l)
		}
	}
	if len(batch) == 0 {
		return
	}
	// 单轮最多上报若干条：一次日志轮转可能积累上千条，
	// 全发会拖垮 Worker 配额，也会让上报请求长期占用。
	const maxReportPerRound = 50
	if len(batch) > maxReportPerRound {
		batch = batch[:maxReportPerRound]
	}
	go func(items []model.WAFLog) {
		for _, l := range items {
			ev := WAFReportEvent{
				IP:         l.IP, // 攻击源 IP：WAF 日志的 remote_addr
				AttackType: l.AttackType,
				URL:        l.Path,
				Payload:    l.Detail,
				Method:     l.Method,
				UA:         l.UserAgent,
				Website:    wafSiteHash(l.WebsiteName),
			}
			if err := w.ReportEvent(ev); err != nil {
				// 只记一次汇总，避免刷屏
				global.LOG.Debugf("[waf] report event failed: %v", err)
				return
			}
		}
	}(batch)
}

// wafSiteHash 把站点标识转成短哈希。
// 上报里不出现真实域名：那是可被反查的运营信息。
func wafSiteHash(name string) string {
	if name == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(name))
	return hex.EncodeToString(sum[:4])
}
