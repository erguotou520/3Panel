// Package waf 提供 WAF 数据面产物管理：Lua 模块部署、名单导出
// 注意：本包不得反向依赖 service（service 会引用本包，避免循环）
package waf

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/3panel-dev/3panel/agent/app/model"
)

const (
	// WAFDir OpenResty 容器内 WAF 资源根目录。3Panel 的 website data
	// directory is mounted at /www; the OpenResty conf parent is not mounted.
	WAFDir = "/www/waf"
)

// HostWAFDir returns the WAF directory below the host website-data directory,
// which is mounted to /www inside the managed OpenResty container.
func HostWAFDir(hostWebsiteDir string) string {
	return filepath.Join(hostWebsiteDir, "waf")
}

// DeployLuaModules 将内置 Lua 模块写入宿主机 WAF 目录（挂载给 OpenResty 容器）
func DeployLuaModules(luaFiles map[string][]byte, hostWebsiteDir string) error {
	dir := HostWAFDir(hostWebsiteDir)
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
	Enabled  bool            `json:"enabled"`
	Rules    []ruleDTO       `json:"rules"`
	Compiled compiledRuleSet `json:"compiled"`
	CC       *ccDTO          `json:"cc,omitempty"`
	Bot      *botDTO         `json:"bot,omitempty"`
	Probe    *probeDTO       `json:"probe,omitempty"`
}

type exportedRules struct {
	Global struct {
		Rules    []ruleDTO       `json:"rules"`
		Compiled compiledRuleSet `json:"compiled"`
	} `json:"global"`
	Sites map[string]siteEntry `json:"sites"`
}

type compiledRuleSet struct {
	IP      map[string]ruleDTO `json:"ip,omitempty"`
	Path    map[string]ruleDTO `json:"path,omitempty"`
	Method  map[string]ruleDTO `json:"method,omitempty"`
	UA      map[string]ruleDTO `json:"ua,omitempty"`
	Referer map[string]ruleDTO `json:"referer,omitempty"`
	Cookie  map[string]ruleDTO `json:"cookie,omitempty"`
}

func newCompiledRuleSet() compiledRuleSet {
	return compiledRuleSet{
		IP: map[string]ruleDTO{}, Path: map[string]ruleDTO{}, Method: map[string]ruleDTO{},
		UA: map[string]ruleDTO{}, Referer: map[string]ruleDTO{}, Cookie: map[string]ruleDTO{},
	}
}

func preferCompiled(current, candidate ruleDTO) ruleDTO {
	if current.ID == 0 || (candidate.Action == model.WAFActionAllow && current.Action != model.WAFActionAllow) {
		return candidate
	}
	if (candidate.Action == model.WAFActionAllow) == (current.Action == model.WAFActionAllow) && candidate.Priority < current.Priority {
		return candidate
	}
	return current
}

func (c *compiledRuleSet) add(rule ruleDTO) bool {
	if !rule.Enabled || rule.ExpiresAt != nil || rule.MatchOp != "exact" {
		return false
	}
	var target map[string]ruleDTO
	switch rule.MatchType {
	case "ip":
		if net.ParseIP(rule.MatchValue) == nil {
			return false
		}
		target = c.IP
	case "path":
		target = c.Path
	case "method":
		target = c.Method
	case "ua":
		target = c.UA
	case "referer":
		target = c.Referer
	case "cookie":
		target = c.Cookie
	default:
		return false
	}
	target[rule.MatchValue] = preferCompiled(target[rule.MatchValue], rule)
	return true
}

// ExportRules 将 DB 中的名单与 CC/机器人/探测配置导出为数据面 rules.json（全局 + 站点两层）
func ExportRules(rules []model.WAFRule, ccConfigs []model.WAFCCConfig, options []model.WAFOption, enabledSites map[uint]bool, hostWebsiteDir string) error {
	data := exportedRules{Sites: map[string]siteEntry{}}
	data.Global.Compiled = newCompiledRuleSet()
	for websiteID, enabled := range enabledSites {
		key := fmt.Sprintf("%d", websiteID)
		data.Sites[key] = siteEntry{Enabled: enabled, Compiled: newCompiledRuleSet()}
	}

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
			if site.Compiled.IP == nil {
				site.Compiled = newCompiledRuleSet()
			}
			if !site.Compiled.add(dto) {
				site.Rules = append(site.Rules, dto)
			}
			data.Sites[key] = site
		} else {
			if !data.Global.Compiled.add(dto) {
				data.Global.Rules = append(data.Global.Rules, dto)
			}
		}
	}
	for _, cc := range ccConfigs {
		if !cc.Enabled || cc.Limit <= 0 || cc.WebsiteID == 0 {
			continue
		}
		key := fmt.Sprintf("%d", cc.WebsiteID)
		site := data.Sites[key]
		if site.Compiled.IP == nil {
			site.Compiled = newCompiledRuleSet()
		}
		site.CC = &ccDTO{Limit: cc.Limit, Window: cc.Window, Action: cc.Action, ByURI: cc.ByURI}
		data.Sites[key] = site
	}
	for _, opt := range options {
		if opt.WebsiteID == 0 || (!opt.BotEnabled && !opt.ProbeEnabled) {
			continue
		}
		key := fmt.Sprintf("%d", opt.WebsiteID)
		site := data.Sites[key]
		if site.Compiled.IP == nil {
			site.Compiled = newCompiledRuleSet()
		}
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
	dir := HostWAFDir(hostWebsiteDir)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	target := filepath.Join(dir, "rules.json")
	tmp, err := os.CreateTemp(dir, "rules-*.json.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0644); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(content); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, target)
}
