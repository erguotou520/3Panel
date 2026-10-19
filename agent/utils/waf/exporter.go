// Package waf 提供 WAF 数据面产物管理：Lua 模块部署、名单导出
// 注意：本包不得反向依赖 service（service 会引用本包，避免循环）
package waf

import (
	"bytes"
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
	_, err := deployLuaModules(luaFiles, hostWebsiteDir, false)
	return err
}

// DeployLuaModulesIfChanged 与 DeployLuaModules 相同，但内容未变的文件跳过写入，
// 并返回是否真的有文件被更新。
//
// 供周期性检查使用：升级 agent 后已启用 WAF 的站点不会重新走「首次开启」流程，
// 需要主动把新 Lua 推下去；而每分钟无条件重写 20 个文件纯属浪费。
// 返回值让调用方决定要不要 reload —— Lua 模块进的是 package.loaded 缓存，
// 只改文件不 reload，worker 仍跑旧代码。
func DeployLuaModulesIfChanged(luaFiles map[string][]byte, hostWebsiteDir string) (bool, error) {
	return deployLuaModules(luaFiles, hostWebsiteDir, true)
}

func deployLuaModules(luaFiles map[string][]byte, hostWebsiteDir string, skipUnchanged bool) (bool, error) {
	dir := HostWAFDir(hostWebsiteDir)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return false, err
	}
	changed := false
	for name, content := range luaFiles {
		dest := filepath.Join(dir, name)
		if skipUnchanged {
			if old, err := os.ReadFile(dest); err == nil && bytes.Equal(old, content) {
				continue
			}
		}
		if err := os.WriteFile(dest, content, 0644); err != nil {
			return changed, err
		}
		changed = true
	}
	return changed, nil
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
	// Geo 地理规则的解析结果。nil 表示本次没有 geo 规则，数据面不必加载。
	Geo   *geoExportDTO        `json:"geo,omitempty"`
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
func ExportRules(rules []model.WAFRule, ccConfigs []model.WAFCCConfig, options []model.WAFOption, enabledSites map[uint]bool, hostWebsiteDir string, iplistEnabled bool, opts ...ExportOptions) error {
	data := exportedRules{Sites: map[string]siteEntry{}}
	data.Global.Compiled = newCompiledRuleSet()
	data.Global.IPListEnabled = iplistEnabled
	for websiteID, enabled := range enabledSites {
		key := fmt.Sprintf("%d", websiteID)
		data.Sites[key] = siteEntry{Enabled: enabled, Compiled: newCompiledRuleSet()}
	}

	// IP 组：只导出启用的。禁用组若还导出，Lua 侧查到就会命中，
	// 「关闭」就成了摆设 —— 与 iplistEnabled 同样的处理思路。
	var exportOpts ExportOptions
	if len(opts) > 0 {
		exportOpts = opts[0]
	}
	for _, g := range exportOpts.IPGroups {
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

	// 地理规则：只解析**被启用规则引用到的**国家码。
	// 把全世界都写进来会让 rules.json 膨胀到几 MB，
	// 而绝大多数站点只关心自己那一两个国家。
	geoCodes := collectGeoCodes(rules)
	if len(geoCodes) > 0 && exportOpts.Geo.MMDBPath != "" {
		countries, err := ResolveCountryCIDRs(exportOpts.Geo.MMDBPath, geoCodes, true)
		if err != nil {
			// 解析失败不能让整个导出失败 —— 其它规则还得同步。
			// 但不静默吞掉：记日志，并且把 geo 标为不可用，
			// 前端会提示"这些规则当前不生效"。
			logGeoResolveFailure(err)
			data.Geo = &geoExportDTO{Available: false}
		} else if countries == nil {
			// mmdb 不存在：同上，标记不可用而不是当作"没有国家数据"。
			data.Geo = &geoExportDTO{Available: false}
		} else {
			dto := &geoExportDTO{Available: true, Countries: countries}
			for _, code := range geoCodes {
				if len(countries[code]) == 0 {
					dto.Empty = append(dto.Empty, code)
				}
			}
			sort.Strings(dto.Empty)
			data.Geo = dto
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

// ExportOptions 是导出的可选输入。用单一结构体而不是两个可变参数：
// Go 不允许同一函数有多个 ...T，而这些都属于"不是每次都要传"的配置。
//
// 之所以要显式传 mmdb 路径而不是在 exporter 里读全局变量：
// utils/waf 是被 service 层调用的纯工具包，让它依赖 global
// 会把配置来源硬编码进来，测试也没法换成临时文件。
type ExportOptions struct {
	// IPGroups 是要导出的 IP 组（含禁用的，导出时按 Enabled 过滤）。
	IPGroups []model.WAFIPGroup
	// Geo 是地理规则导出配置。
	Geo GeoExport
}

// GeoExport 控制地理规则的导出。
type GeoExport struct {
	// MMDBPath 是 GeoIP.mmdb 的路径。空字符串 = 本次不解析 geo。
	MMDBPath string
}

// geoExportDTO 是 country code -> CIDR 列表的解析结果。
//
// 为什么是"解析成 CIDR"而不是在数据面查库：匹配发生在 Lua/OpenResty 侧，
// Go 不在请求路径上。展开成 CIDR 后 Lua 复用已有的 in_cidr 判定。
type geoExportDTO struct {
	// Available 表示 mmdb 是否可用。false 时所有 geo 规则都不命中，
	// 前端要据此提示用户「地理数据缺失，这些规则当前不生效」——
	// 不能静默失效：用户会以为拦住了，实际全部放行。
	Available bool `json:"available"`
	// Countries 是 country code -> CIDR 列表。
	// 值为空数组表示「库里没有这个国家的数据」，与「没有该键」区分开。
	Countries map[string][]string `json:"countries,omitempty"`
	// Empty 是库里查不到数据的国家码，便于前端一次性提示。
	Empty []string `json:"empty,omitempty"`
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
