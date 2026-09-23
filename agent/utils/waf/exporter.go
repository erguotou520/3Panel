// Package waf 提供 WAF 数据面产物管理：Lua 模块部署、名单导出
// 注意：本包不得反向依赖 service（service 会引用本包，避免循环）
package waf

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/3panel-dev/3panel/agent/app/model"
)

const (
	// WAFDir OpenResty 容器内 WAF 资源根目录（容器内路径固定）
	WAFDir = "/usr/local/openresty/nginx/conf/waf"
)

// HostWAFDir 宿主机 WAF 资源目录：<openresty 安装目录>/conf/waf（挂载给容器 conf 目录）
// hostOpenrestyConfDir 由 service 层根据 openresty 应用安装路径解析后传入
func HostWAFDir(hostOpenrestyConfDir string) string {
	return filepath.Join(hostOpenrestyConfDir, "waf")
}

// DeployLuaModules 将内置 Lua 模块写入宿主机 WAF 目录（挂载给 OpenResty 容器）
func DeployLuaModules(luaFiles map[string][]byte, hostConfDir string) error {
	dir := HostWAFDir(hostConfDir)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	for name, content := range luaFiles {
		if err := os.WriteFile(filepath.Join(dir, name), content, 0644); err != nil {
			return err
		}
	}
	return nil
}

type ruleDTO struct {
	ID         uint       `json:"id"`
	Name       string     `json:"name"`
	Priority   int        `json:"priority"`
	MatchType  string     `json:"match_type"`
	MatchValue string     `json:"match_value"`
	MatchOp    string     `json:"match_op"`
	Action     string     `json:"action"`
	Enabled    bool       `json:"enabled"`
	ExpiresAt  *time.Time `json:"expires_at"`
}

type ccDTO struct {
	Limit  int    `json:"limit"`
	Window int    `json:"window"`
	Action string `json:"action"`
	ByURI  bool   `json:"byUri"`
}

type botDTO struct {
	Enabled       bool `json:"enabled"`
	AllowGoodBots bool `json:"allowGoodBots"`
	BlockBadBots  bool `json:"blockBadBots"`
}

type probeDTO struct {
	Enabled bool `json:"enabled"`
	MaxURIs int  `json:"maxURIs"`
	Window  int  `json:"window"`
	MaxRPS  int  `json:"maxRPS"`
}

type siteEntry struct {
	Rules []ruleDTO  `json:"rules"`
	CC    *ccDTO     `json:"cc,omitempty"`
	Bot   *botDTO    `json:"bot,omitempty"`
	Probe *probeDTO  `json:"probe,omitempty"`
}

type exportedRules struct {
	Global struct {
		Rules []ruleDTO `json:"rules"`
	} `json:"global"`
	Sites map[string]siteEntry `json:"sites"`
}

// ExportRules 将 DB 中的名单与 CC/机器人/探测配置导出为数据面 rules.json（全局 + 站点两层）
func ExportRules(rules []model.WAFRule, ccConfigs []model.WAFCCConfig, options []model.WAFOption, hostConfDir string) error {
	data := exportedRules{Sites: map[string]siteEntry{}}

	sort.Slice(rules, func(i, j int) bool { return rules[i].Priority < rules[j].Priority })
	for _, r := range rules {
		dto := ruleDTO{
			ID: r.ID, Name: r.Name, Priority: r.Priority,
			MatchType: r.MatchType, MatchValue: r.MatchValue, MatchOp: r.MatchOp,
			Action: r.Action, Enabled: r.Enabled, ExpiresAt: r.ExpiresAt,
		}
		if r.Scope == model.WAFScopeSite && r.WebsiteID != 0 {
			key := fmt.Sprintf("%d", r.WebsiteID)
			site := data.Sites[key]
			site.Rules = append(site.Rules, dto)
			data.Sites[key] = site
		} else {
			data.Global.Rules = append(data.Global.Rules, dto)
		}
	}
	for _, cc := range ccConfigs {
		if !cc.Enabled || cc.Limit <= 0 || cc.WebsiteID == 0 {
			continue
		}
		key := fmt.Sprintf("%d", cc.WebsiteID)
		site := data.Sites[key]
		site.CC = &ccDTO{Limit: cc.Limit, Window: cc.Window, Action: cc.Action, ByURI: cc.ByURI}
		data.Sites[key] = site
	}
	for _, opt := range options {
		if opt.WebsiteID == 0 || (!opt.BotEnabled && !opt.ProbeEnabled) {
			continue
		}
		key := fmt.Sprintf("%d", opt.WebsiteID)
		site := data.Sites[key]
		if opt.BotEnabled {
			site.Bot = &botDTO{Enabled: true, AllowGoodBots: opt.AllowGoodBots, BlockBadBots: opt.BlockBadBots}
		}
		if opt.ProbeEnabled {
			site.Probe = &probeDTO{Enabled: true, MaxURIs: opt.ProbeMaxURIs, Window: opt.ProbeWindow, MaxRPS: opt.ProbeMaxRPS}
		}
		data.Sites[key] = site
	}

	content, err := json.Marshal(data)
	if err != nil {
		return err
	}
	dir := HostWAFDir(hostConfDir)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "rules.json"), content, 0644)
}
