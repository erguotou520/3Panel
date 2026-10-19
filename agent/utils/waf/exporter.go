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
	"strings"
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
	// KeepInspecting：白名单「加白时仍检测」。仅 action=allow 时被 Lua 读取。
	KeepInspecting bool `json:"keep_inspecting"`
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
	// Level 强度分档：off / observe / balanced / high。
	// off/observe 在 Lua 侧 bot.check 里判定；
	// high = 平衡档 + 把「空 User-Agent」当可疑（扫描器可配成不发 UA）。
	Level string `json:"level,omitempty"`
}

type probeDTO struct {
	Enabled bool `json:"enabled"`
	MaxURIs int  `json:"maxURIs"`
	Window  int  `json:"window"`
	MaxRPS  int  `json:"maxRPS"`
}

type siteEntry struct {
	Enabled  bool            `json:"enabled"`
	Mode     string          `json:"mode,omitempty"`
	Rules    []ruleDTO       `json:"rules"`
	Compiled compiledRuleSet `json:"compiled"`
	CC       *ccDTO          `json:"cc,omitempty"`
	Bot      *botDTO         `json:"bot,omitempty"`
	Probe    *probeDTO       `json:"probe,omitempty"`
	// BlockPage 站点级拦截页定制；nil 表示用内置默认样式。
	BlockPage *blockPageDTO `json:"blockPage,omitempty"`
	// DisabledDetectors 是被关闭的语义检测器名集合（Lua 侧转成 set 便于 O(1) 判断）。
	DisabledDetectors []string `json:"disabled_detectors,omitempty"`
	// IPGroups 是本站级 IP 组：name -> CIDR 列表。
	IPGroups map[string][]string `json:"ip_groups,omitempty"`
	// SemanticLevel 语义层强度分档：off / observe / balanced / high。
	// balanced 是默认值，省略时 Lua 按 balanced 处理。
	// high = 绕过 has_attack_candidate 快速筛（召回更高、CPU 开销更大）。
	SemanticLevel string `json:"semantic_level,omitempty"`
}

// blockPageDTO 是拦截页的可配置部分。
// 只支持纯文本 + 两个颜色值，不接受 HTML 片段 —— 这个页面会展示给
// 所有访问者（包括攻击者），让配置者可注入脚本等于给站点开一个 XSS 入口。
type blockPageDTO struct {
	Title     string `json:"title,omitempty"`
	Body      string `json:"body,omitempty"`
	BgColor   string `json:"bgColor,omitempty"`
	TextColor string `json:"textColor,omitempty"`
}

type exportedRules struct {
	Global struct {
		Rules    []ruleDTO       `json:"rules"`
		Compiled compiledRuleSet `json:"compiled"`
		// IPListEnabled 为订阅黑名单总开关。数据面据此决定是否查名单 ——
		// 关闭后必须完全跳过，否则「关闭」只是界面上的一个摆设。
		IPListEnabled bool `json:"ipListEnabled"`
		// IPGroups 是全局 IP 组：name -> CIDR 列表。
		// 站点级组在 siteEntry.ip_groups 里，同名时本站覆盖全局。
		IPGroups map[string][]string `json:"ip_groups,omitempty"`
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
	// 「加白仍检测」的白名单不能进快速表：compiled 表只存 (键 → 规则)，
	// Lua 侧查表命中即 return，拿不到 keep_inspecting 这个语义。
	// 漏掉这一条会让开关「保存成功但完全无效」—— 最典型的静默失效。
	if rule.Action == model.WAFActionAllow && rule.KeepInspecting {
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
// ipGroups 用可变参数追加在末尾，而不是加进固定签名 ——
// 现有 7 处调用（含测试）不必改，少一处改错的机会。
func ExportRules(rules []model.WAFRule, ccConfigs []model.WAFCCConfig, options []model.WAFOption, enabledSites map[uint]bool, hostWebsiteDir string, iplistEnabled bool, ipGroups ...[]model.WAFIPGroup) error {
	data := exportedRules{Sites: map[string]siteEntry{}}
	data.Global.Compiled = newCompiledRuleSet()
	data.Global.IPListEnabled = iplistEnabled
	for websiteID, enabled := range enabledSites {
		key := fmt.Sprintf("%d", websiteID)
		data.Sites[key] = siteEntry{Enabled: enabled, Compiled: newCompiledRuleSet()}
	}

	// IP 组：只导出启用的。禁用组若还导出，Lua 侧查到就会命中，
	// 「关闭」就成了摆设 —— 与 iplistEnabled 同样的处理思路。
	if len(ipGroups) > 0 {
		for _, g := range ipGroups[0] {
			if !g.Enabled || g.Name == "" {
				continue
			}
			cidrs := splitNonEmptyLines(g.CIDRs)
			if len(cidrs) == 0 {
				continue
			}
			if g.Scope == model.WAFScopeSite {
				key := fmt.Sprintf("%d", g.WebsiteID)
				site, ok := data.Sites[key]
				if !ok {
					continue
				}
				if site.IPGroups == nil {
					site.IPGroups = map[string][]string{}
				}
				site.IPGroups[g.Name] = cidrs
				data.Sites[key] = site
			} else {
				if data.Global.IPGroups == nil {
					data.Global.IPGroups = map[string][]string{}
				}
				data.Global.IPGroups[g.Name] = cidrs
			}
		}
	}

	sort.Slice(rules, func(i, j int) bool { return rules[i].Priority < rules[j].Priority })
	for _, r := range rules {
		dto := ruleDTO{
			ID: r.ID, Name: r.Name, Priority: r.Priority,
			MatchType: r.MatchType, MatchValue: r.MatchValue, MatchOp: r.MatchOp,
			Action: r.Action, Enabled: r.Enabled, ExpiresAt: r.ExpiresAt,
			KeepInspecting: r.KeepInspecting,
		}
		if r.Scope == model.WAFScopeSite && r.WebsiteID != 0 {
			key := fmt.Sprintf("%d", r.WebsiteID)
			site, ok := data.Sites[key]
			// 站点不存在时不能凭空建条目：site 是零值，Enabled=false，
			// 回写后这个站点会被 Lua 的 site_enabled() 判成关闭 ——
			// 一条属于未知站点的规则反而把该站点的 WAF 关掉了。
			if !ok {
				continue
			}
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
		site, ok := data.Sites[key]
		if !ok {
			continue
		}
		if site.Compiled.IP == nil {
			site.Compiled = newCompiledRuleSet()
		}
		site.CC = &ccDTO{Limit: cc.Limit, Window: cc.Window, Action: cc.Action, ByURI: cc.ByURI}
		data.Sites[key] = site
	}
	for _, opt := range options {
		// Mode / BlockPage / DisabledDetectors 也在这条路径导出，
		// 所以过滤条件必须把它们算进来 —— 只看 BotEnabled/ProbeEnabled
		// 会让「只配了防护模式」的站点整个被跳过，模式静默失效。
		hasCustomPage := opt.BlockPageTitle != "" || opt.BlockPageBody != "" ||
			opt.BlockPageBgColor != "" || opt.BlockPageTextColor != ""
		// hasLevel 表示「配了非默认强度」。必须进过滤条件 ——
		// 否则只调了强度、没开 bot/probe 的站点会被整个跳过，
		// 界面上能配、保存后数据面毫无反应（静默失效）。
		hasLevel := (opt.SemanticLevel != "" && opt.SemanticLevel != WAFLevelBalanced) ||
			(opt.BotLevel != "" && opt.BotLevel != WAFLevelBalanced)
		if opt.WebsiteID == 0 ||
			(!opt.BotEnabled && !opt.ProbeEnabled && !hasCustomPage && !hasLevel &&
				opt.Mode == "" && opt.DisabledDetectors == "") {
			continue
		}
		key := fmt.Sprintf("%d", opt.WebsiteID)
		site, ok := data.Sites[key]
		if !ok {
			continue
		}
		if site.Compiled.IP == nil {
			site.Compiled = newCompiledRuleSet()
		}
		if opt.BotEnabled {
			// Level 只导出非默认值：空与 balanced 行为相同。
			level := ""
			if opt.BotLevel != "" && opt.BotLevel != WAFLevelBalanced {
				level = opt.BotLevel
			}
			site.Bot = &botDTO{
				Enabled:       true,
				AllowGoodBots: opt.AllowGoodBots,
				BlockBadBots:  opt.BlockBadBots,
				Level:         level,
			}
		}
		if opt.ProbeEnabled {
			site.Probe = &probeDTO{Enabled: true, MaxURIs: opt.ProbeMaxURIs, Window: opt.ProbeWindow, MaxRPS: opt.ProbeMaxRPS}
		}
		// Mode 只导出非默认值：空与 block 行为相同，
		// 不导出能让 rules.json 保持小一点，也便于老版本 Lua 忽略未知字段。
		if opt.Mode != "" && opt.Mode != WAFModeBlock {
			site.Mode = opt.Mode
		}
		if hasCustomPage {
			site.BlockPage = &blockPageDTO{
				Title:     opt.BlockPageTitle,
				Body:      opt.BlockPageBody,
				BgColor:   opt.BlockPageBgColor,
				TextColor: opt.BlockPageTextColor,
			}
		}
		if opt.DisabledDetectors != "" {
			site.DisabledDetectors = splitAndTrim(opt.DisabledDetectors)
		}
		// 强度分档同样只导出非默认值（balanced）。理由同 Mode：
		// rules.json 保持小，且老版本 Lua 遇到未知字段直接忽略。
		if opt.SemanticLevel != "" && opt.SemanticLevel != WAFLevelBalanced {
			site.SemanticLevel = opt.SemanticLevel
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

// WAF 站点防护模式取值。必须与 Lua 侧 access.lua 判定用的字面量一致。
const (
	// WAFModeBlock 防护：命中即拦截并记录。
	WAFModeBlock = "block"
	// WAFModeObserve 观察：命中只记录日志，一律不拦截。
	WAFModeObserve = "observe"
	// WAFModeMaintenance 维护：所有请求返回维护页。
	WAFModeMaintenance = "maintenance"
)

// 保护强度分档。必须与 Lua 侧 semantic.lua / bot.lua 判定的字面量一致。
const (
	// WAFLevelOff 该层整体不生效。
	WAFLevelOff = "off"
	// WAFLevelObserve 照常检测，命中只记日志不拦截。
	WAFLevelObserve = "observe"
	// WAFLevelBalanced 平衡防护（默认）。
	WAFLevelBalanced = "balanced"
	// WAFLevelHigh 高强度。语义层 = 绕过快速筛；bot 层 = 额外把空 UA 当可疑。
	WAFLevelHigh = "high"
)

// splitNonEmptyLines 把换行分隔的文本拆成去掉空白的切片（跳空行）。
// IP 组的 CIDRs 就是这种格式 —— 存库时用换行分隔，导出时拆回来。
func splitNonEmptyLines(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	parts := strings.Split(strings.ReplaceAll(raw, "\r\n", "\n"), "\n")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if v := strings.TrimSpace(p); v != "" {
			out = append(out, v)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// splitAndTrim 把逗号分隔的列表拆成去掉空白的切片。
// 空字符串返回 nil —— JSON 里 omitempty 会直接省掉该字段，
// Lua 侧据此走「全部启用」的默认路径。
func splitAndTrim(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if v := strings.TrimSpace(p); v != "" {
			out = append(out, v)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
