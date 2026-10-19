package service

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/3panel-dev/3panel/agent/app/dto/request"
	"github.com/3panel-dev/3panel/agent/app/model"
	"github.com/3panel-dev/3panel/agent/app/repo"
	"github.com/3panel-dev/3panel/agent/global"
	"github.com/3panel-dev/3panel/agent/utils/files"
	"github.com/3panel-dev/3panel/agent/utils/geo"
	"github.com/3panel-dev/3panel/agent/utils/nginx"
	"github.com/3panel-dev/3panel/agent/utils/nginx/parser"
	wafutils "github.com/3panel-dev/3panel/agent/utils/waf"
	"github.com/3panel-dev/3panel/agent/utils/webhook_sender"
	"gorm.io/gorm"
)

type WAFService struct {
	syncRulesFn func() error
}

func NewIWAFService() IWAFService {
	return &WAFService{}
}

type IWAFService interface {
	SetWebsiteWAF(websiteID uint, enable bool) error
	ListRules(req request.WAFRuleSearch) ([]model.WAFRule, error)
	CreateRule(req request.WAFRuleCreate) error
	UpdateRule(req request.WAFRuleUpdate) error
	DeleteRule(id uint) error
	// ReorderRules 按目标顺序重排优先级（黑白名单拖动排序）。
	ReorderRules(req request.WAFRuleReorder) error
	ListIPGroups(websiteID uint) ([]model.WAFIPGroup, error)
	CreateIPGroup(req request.WAFIPGroupCreate) error
	UpdateIPGroup(req request.WAFIPGroupUpdate) error
	DeleteIPGroup(id uint) error
	GetCCConfig(websiteID uint) (*model.WAFCCConfig, error)
	UpdateCCConfig(req request.WAFCCUpdate) error
	GetOption(websiteID uint) (*model.WAFOption, error)
	UpdateOption(req request.WAFOptionUpdate) error
	GetWebhookSetting() (map[string]interface{}, error)
	UpdateWebhookSetting(req request.WAFWebhookUpdate) error
	SearchLogs(req request.WAFLogSearch) (int64, []model.WAFLog, error)
	StatLogs(req request.WAFLogSearch) (map[string][]WAFStatItem, error)
	ExportLogs(req request.WAFLogSearch) (string, []byte, error)
	AddRuleFromLog(logID uint, action string) error
	MarkFalsePositive(req request.WAFFalsePositiveOp) error
	CleanExpiredRules()
	CleanExpiredLogs()
	IngestLogs()
	SyncIPListIfDue()
	GetIPListStatus() (map[string]interface{}, error)
	UpdateIPListSetting(req model.WAFIPListSetting) error
	SyncIPList() (map[string]interface{}, error)
	ReportEvent(ev WAFReportEvent) error
	SyncReports()
}

// wafHostConfDir resolves the host website-data directory mounted at /www in
// the managed OpenResty container.
func wafHostConfDir() (string, error) {
	if global.Dir.DataDir == "" {
		return "", fmt.Errorf("3panel data directory is empty")
	}
	return path.Join(global.Dir.DataDir, "www"), nil
}

// ==================== 站点开关 ====================

// SetWebsiteWAF 开启/关闭站点 WAF：注入 nginx 指令 + 更新 DB + 同步名单产物
func (w WAFService) SetWebsiteWAF(websiteID uint, enable bool) error {
	var website model.Website
	var err error
	website, err = websiteRepo.GetFirst(repo.WithByID(websiteID))
	if err != nil {
		return err
	}
	// 首次开启时安装 Lua 入口；之后的启停只热更新 rules.json，避免因单站点
	// 状态变化 reload 整个 OpenResty。关闭时保留无操作的 access 入口。
	if enable {
		confDir, err := wafHostConfDir()
		if err != nil {
			return err
		}
		luaFiles, err := wafutils.LuaFiles()
		if err != nil {
			return err
		}
		if err := wafutils.DeployLuaModules(luaFiles, confDir); err != nil {
			return err
		}
		if err := wafEnsureHTTPConfig(); err != nil {
			return err
		}
		if err := wafInjectServer(&website, true); err != nil {
			return err
		}
	}
	previous := website.WafEnabled
	website.WafEnabled = enable
	if err := global.DB.Save(&website).Error; err != nil {
		return err
	}
	if err := w.syncDataPlane(); err != nil {
		website.WafEnabled = previous
		if rollbackErr := global.DB.Save(&website).Error; rollbackErr != nil {
			return fmt.Errorf("sync WAF data plane: %w; rollback website state: %v", err, rollbackErr)
		}
		_ = w.syncDataPlane()
		return err
	}
	return nil
}

// wafEnsureHTTPConfig 确保 openresty nginx.conf 的 http 块声明 waf 共享内存字典（幂等）
//
// 这里刻意不注入 lua_package_path：镜像自带的 1pwaf/data/conf/waf.conf 已经声明过该
// 指令，同一 http 块里再来一条会让 nginx -t 以 "lua_package_path directive is
// duplicate" 失败，于是开启 WAF 直接报错。模块目录改由 entry.lua 依据自身路径拼进
// package.path，既避开冲突也不依赖 include 顺序。
func wafEnsureHTTPConfig() error {
	nginxInstall, err := getAppInstallByKey("openresty")
	if err != nil {
		return err
	}
	mainConfPath := path.Join(nginxInstall.GetPath(), "conf", "nginx.conf")
	content, err := os.ReadFile(mainConfPath)
	if err != nil {
		return err
	}
	rootConfig, err := parser.NewStringParser(string(content)).Parse()
	if err != nil {
		return err
	}
	httpBlock := rootConfig.FindHttp()
	if httpBlock == nil {
		return fmt.Errorf("http block not found in nginx.conf")
	}
	// CC 计数与挑战所需的共享内存字典。不能用“是否存在任意共享字典”代替 waf_dict 检查。
	for _, directive := range httpBlock.FindDirectives("lua_shared_dict") {
		params := directive.GetParameters()
		if len(params) > 0 && params[0] == "waf_dict" {
			return nil
		}
	}
	httpBlock.UpdateDirective("lua_shared_dict", []string{"waf_dict", "32m"})
	rootConfig.FilePath = mainConfPath
	if err := nginx.WriteConfig(rootConfig, nginx.IndentedStyle); err != nil {
		return err
	}
	return nginxCheckAndReload(string(content), mainConfPath, nginxInstall.ContainerName)
}

// wafInjectServer 在站点 server 块注入/移除 WAF 指令
func wafInjectServer(website *model.Website, enable bool) error {
	nginxFull, err := getNginxFull(website)
	if err != nil {
		return err
	}
	config := nginxFull.SiteConfig
	serverBlock := config.Config.FindServers()[0]

	accessConf := fmt.Sprintf("%s/entry.lua", wafutils.WAFDir)
	legacyAccessConf := fmt.Sprintf("%s/access.lua", wafutils.WAFDir)
	rulesFile := fmt.Sprintf("%s/rules.json", wafutils.WAFDir)
	logFile := fmt.Sprintf("%s/waf_events.log", wafutils.WAFDir)
	if enable {
		hasAccess := false
		for _, directive := range serverBlock.FindDirectives("access_by_lua_file") {
			params := directive.GetParameters()
			if len(params) > 0 && params[0] == accessConf {
				hasAccess = true
				break
			}
		}
		requiredSets := map[string]bool{
			"$waf_site_id": false, "$waf_rules_path": false,
			"$waf_log_path": false, "$waf_challenge_secret": false,
		}
		for _, directive := range serverBlock.FindDirectives("set") {
			params := directive.GetParameters()
			if len(params) >= 2 {
				if _, required := requiredSets[params[0]]; required && params[1] != "" {
					requiredSets[params[0]] = true
				}
			}
		}
		complete := hasAccess
		for _, present := range requiredSets {
			complete = complete && present
		}
		if complete {
			return nil
		}
	}

	if enable {
		secret := make([]byte, 32)
		if _, err := rand.Read(secret); err != nil {
			return err
		}
		serverBlock.UpdateDirective("set", []string{"$waf_site_id", fmt.Sprintf("%d", website.ID)})
		serverBlock.UpdateDirective("set", []string{"$waf_rules_path", rulesFile})
		serverBlock.UpdateDirective("set", []string{"$waf_log_path", logFile})
		serverBlock.UpdateDirective("set", []string{"$waf_challenge_secret", base64.RawURLEncoding.EncodeToString(secret)})
		serverBlock.UpdateDirective("access_by_lua_file", []string{accessConf})
		serverBlock.RemoveDirective("access_by_lua_file", []string{legacyAccessConf})
	} else {
		serverBlock.RemoveDirective("access_by_lua_file", []string{accessConf})
		serverBlock.RemoveDirective("access_by_lua_file", []string{legacyAccessConf})
		serverBlock.RemoveDirective("set", []string{"$waf_site_id", fmt.Sprintf("%d", website.ID)})
		serverBlock.RemoveDirective("set", []string{"$waf_rules_path", rulesFile})
		serverBlock.RemoveDirective("set", []string{"$waf_log_path", logFile})
		serverBlock.RemoveDirective("set", []string{"$waf_challenge_secret"})
	}

	if err := nginx.WriteConfig(config.Config, nginx.IndentedStyle); err != nil {
		return err
	}
	return nginxCheckAndReload(config.OldContent, config.FilePath, nginxFull.Install.ContainerName)
}

// ==================== 名单 CRUD ====================

// SyncRules 导出名单 + CC 配置到数据面 rules.json
func (w WAFService) SyncRules() error {
	confDir, err := wafHostConfDir()
	if err != nil {
		return err
	}
	var rules []model.WAFRule
	if err := global.DB.Where("enabled = ?", true).Order("priority asc").Find(&rules).Error; err != nil {
		return err
	}
	// CC 不在 DB 层过滤 enabled：ExportRules 里本来就有 `!cc.Enabled` 判断。
	// 提前过滤会让「禁用」在数据面上表现成「记录不存在」，一旦规则被跳过就再也无法
	// 区分"显式关闭"与"未配置"，排查时看不到任何线索。
	var ccs []model.WAFCCConfig
	if err := global.DB.Find(&ccs).Error; err != nil {
		return err
	}
	var options []model.WAFOption
	if err := global.DB.Find(&options).Error; err != nil {
		return err
	}
	var websites []model.Website
	if err := global.DB.Select("id", "waf_enabled").Find(&websites).Error; err != nil {
		return err
	}
	enabledSites := make(map[uint]bool, len(websites))
	for _, website := range websites {
		enabledSites[website.ID] = website.WafEnabled
	}
	// 订阅黑名单开关随规则一起下发：数据面读到 false 就不再查名单。
	ipSetting := w.getIPListSetting()
	// IP 组也要随每次同步下发：规则本身不携带组内容，
	// 数据面按 match_value 里的组名去 rules.json 的 ip_groups 里查。
	var ipGroups []model.WAFIPGroup
	if err := global.DB.Find(&ipGroups).Error; err != nil {
		return err
	}
	return wafutils.ExportRules(rules, ccs, options, enabledSites, confDir, ipSetting.Enabled, ipGroups)
}

func (w WAFService) loadAllRules() []model.WAFRule {
	var rules []model.WAFRule
	_ = global.DB.Where("enabled = ?", true).Order("priority asc").Find(&rules).Error
	return rules
}

func (w WAFService) syncDataPlane() error {
	if w.syncRulesFn != nil {
		return w.syncRulesFn()
	}
	return w.SyncRules()
}

// ==================== CC 配置 ====================

func (w WAFService) GetCCConfig(websiteID uint) (*model.WAFCCConfig, error) {
	var cc model.WAFCCConfig
	err := global.DB.Where("website_id = ?", websiteID).First(&cc).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return &model.WAFCCConfig{WebsiteID: websiteID, Window: 60, Action: model.WAFActionDeny, Enabled: false}, nil
		}
		return nil, err
	}
	return &cc, nil
}

func (w WAFService) UpdateCCConfig(req request.WAFCCUpdate) error {
	var cc model.WAFCCConfig
	err := global.DB.Where("website_id = ?", req.WebsiteID).First(&cc).Error
	wasNew := errors.Is(err, gorm.ErrRecordNotFound)
	original := cc
	if err != nil {
		if !wasNew {
			return err
		}
		cc = model.WAFCCConfig{WebsiteID: req.WebsiteID}
	}
	cc.Limit = req.Limit
	cc.Window = req.Window
	cc.Action = req.Action
	cc.ByURI = req.ByURI
	// 开关由前端显式给出。此前是从 Limit>0 派生的，导致「配好阈值先不启用」
	// 无法表达：关掉防护就得把 limit 清零，下次开启还要重新填一遍。
	cc.Enabled = req.Enabled && req.Limit > 0
	if cc.Action == "" {
		cc.Action = model.WAFActionDeny
	}
	if cc.Window <= 0 {
		cc.Window = 60
	}
	if err := global.DB.Save(&cc).Error; err != nil {
		return err
	}
	if err := w.syncDataPlane(); err != nil {
		if wasNew {
			_ = global.DB.Delete(&cc).Error
		} else {
			_ = global.DB.Save(&original).Error
		}
		_ = w.syncDataPlane()
		return err
	}
	return nil
}

func (w WAFService) ListRules(req request.WAFRuleSearch) ([]model.WAFRule, error) {
	var rules []model.WAFRule
	db := global.DB.Model(&model.WAFRule{})
	if req.Scope != "" {
		db = db.Where("scope = ?", req.Scope)
	}
	if req.WebsiteID > 0 {
		db = db.Where("scope = ? OR website_id = ?", model.WAFScopeGlobal, req.WebsiteID)
	}
	if req.Action != "" {
		db = db.Where("action = ?", req.Action)
	}
	err := db.Order("priority asc, id desc").Find(&rules).Error
	return rules, err
}

// parseCIDROrIP 接受裸 IP 或 CIDR，返回归一化后的字符串。
//
// 裸 IP 统一补成 /32 或 /128：这样下游（Lua 的 in_cidr、导出到
// rules.json 的格式）只需处理一种形态，不必到处判断有没有斜杠。
// IPv4-mapped 的 IPv6（::ffff:1.2.3.4）会先 Unmap 成 IPv4 ——
// 用户从 IPv4 网站复制地址时经常带上这层包装，不处理就匹配不上。
func parseCIDROrIP(v string) (string, error) {
	if strings.Contains(v, "/") {
		p, err := netip.ParsePrefix(v)
		if err != nil {
			return "", err
		}
		// 拒绝主机位非零的前缀：1.2.3.4/24 在语义上等于 1.2.3.0/24，
		// 但严格来说它不是合法前缀。放过去会让用户以为两条规则不同，
		// 实际匹配范围完全一样。
		if p.Masked() != p {
			return "", fmt.Errorf("prefix %s has non-zero host bits (did you mean %s?)", v, p.Masked())
		}
		return p.String(), nil
	}
	a, err := netip.ParseAddr(v)
	if err != nil {
		return "", err
	}
	a = a.Unmap()
	bits := 32
	if a.Is6() {
		bits = 128
	}
	return fmt.Sprintf("%s/%d", a.String(), bits), nil
}

// ipGroupNamePattern 限定组名为字母、数字、下划线、短横线。
//
// 不用 validator 的自定义 tag：那条路依赖 init/validator 的全局注册，
// 而真正该保证"组名合法"的地方是 service —— 这里的校验对所有
// 调用方都生效，不依赖调用链上恰好有人跑过校验。
var ipGroupNamePattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

func validateIPGroupName(name string) error {
	if !ipGroupNamePattern.MatchString(name) {
		return fmt.Errorf(
			"invalid ip group name %q: only letters, digits, underscore and dash are allowed (1-64 chars)",
			name)
	}
	return nil
}

// parseIPGroupCIDRs 把用户粘贴的文本解析成去重后的 CIDR 列表。
//
// 同时接受换行与逗号分隔 —— 用户从防火墙/云厂商控制台复制出来的
// 几乎都是逗号分隔，而从文件里贴的是换行分隔，两种都得支持。
//
// 非法条目**直接报错**而不是跳过：组里的 IP 写错了却静默丢弃，
// 用户会以为这条已经生效，实际防护范围比预期小 ——
// 这类"看起来配好了"的偏差在安全配置里比直接报错危险得多。
// 返回的错误里带上具体是第几行，便于用户定位。
func parseIPGroupCIDRs(raw string) ([]string, error) {
	const maxEntries = 4096
	fields := strings.FieldsFunc(raw, func(r rune) bool {
		return r == '\n' || r == '\r' || r == ',' || r == ';' || r == '\t' || r == ' '
	})
	seen := make(map[string]bool, len(fields))
	out := make([]string, 0, len(fields))
	for i, f := range fields {
		v := strings.TrimSpace(f)
		if v == "" {
			continue
		}
		// 必须用**归一化后**的值去重和落库，不能拿原串：
		// 用户粘贴的列表里 "1.1.1.1" 与 "1.1.1.1/32" 语义相同，
		// 按原串去重会当成两条，组内容平白膨胀，且导出后 Lua 侧
		// 看到的是两种形态。
		norm, err := parseCIDROrIP(v)
		if err != nil {
			return nil, fmt.Errorf("invalid IP/CIDR %q at entry %d: %w", v, i+1, err)
		}
		if !seen[norm] {
			seen[norm] = true
			out = append(out, norm)
		}
	}
	if len(out) > maxEntries {
		return nil, fmt.Errorf("ip group too large: %d entries (max %d)", len(out), maxEntries)
	}
	return out, nil
}

// ListIPGroups 返回对指定站点生效的 IP 组（本站 + 全局）。
func (w WAFService) ListIPGroups(websiteID uint) ([]model.WAFIPGroup, error) {
	var groups []model.WAFIPGroup
	err := global.DB.
		Where("scope = ? OR website_id = ?", model.WAFScopeGlobal, websiteID).
		Order("scope asc, name asc").
		Find(&groups).Error
	return groups, err
}

func (w WAFService) CreateIPGroup(req request.WAFIPGroupCreate) error {
	if err := validateIPGroupName(req.Name); err != nil {
		return err
	}
	cidrs, err := parseIPGroupCIDRs(req.CIDRs)
	if err != nil {
		return err
	}
	if len(cidrs) == 0 {
		return fmt.Errorf("ip group must contain at least one IP/CIDR")
	}
	g := model.WAFIPGroup{
		Name: req.Name, Scope: req.Scope, WebsiteID: req.WebsiteID,
		Enabled: req.Enabled, Remark: req.Remark,
		CIDRs: strings.Join(cidrs, "\n"),
	}
	// 唯一索引在 (name, scope)，但 website_id 不在其中 ——
	// 同名同 scope 的两个站点组会撞唯一键。这里提前给出可读错误。
	if err := global.DB.Create(&g).Error; err != nil {
		return fmt.Errorf("create ip group %q: %w", req.Name, err)
	}
	return w.syncDataPlane()
}

func (w WAFService) UpdateIPGroup(req request.WAFIPGroupUpdate) error {
	var g model.WAFIPGroup
	if err := global.DB.First(&g, req.ID).Error; err != nil {
		return err
	}
	if req.Name != "" {
		if err := validateIPGroupName(req.Name); err != nil {
			return err
		}
		g.Name = req.Name
	}
	if req.Scope != "" {
		g.Scope = req.Scope
	}
	if req.WebsiteID > 0 {
		g.WebsiteID = req.WebsiteID
	}
	g.Enabled = req.Enabled
	g.Remark = req.Remark
	if req.CIDRs != "" {
		cidrs, err := parseIPGroupCIDRs(req.CIDRs)
		if err != nil {
			return err
		}
		if len(cidrs) == 0 {
			return fmt.Errorf("ip group must contain at least one IP/CIDR")
		}
		g.CIDRs = strings.Join(cidrs, "\n")
	}
	if err := global.DB.Save(&g).Error; err != nil {
		return err
	}
	return w.syncDataPlane()
}

func (w WAFService) DeleteIPGroup(id uint) error {
	if err := global.DB.Delete(&model.WAFIPGroup{}, id).Error; err != nil {
		return err
	}
	return w.syncDataPlane()
}

func (w WAFService) CreateRule(req request.WAFRuleCreate) error {
	return w.createRule(req, "manual")
}

func (w WAFService) createRule(req request.WAFRuleCreate, source string) error {
	if req.Scope == model.WAFScopeSite && req.WebsiteID == 0 {
		return fmt.Errorf("site rule requires websiteId")
	}
	var expiresAt *time.Time
	if req.TTL > 0 {
		t := time.Now().Add(time.Duration(req.TTL) * time.Second)
		expiresAt = &t
	}
	rule := model.WAFRule{
		Name: req.Name, Scope: req.Scope, WebsiteID: req.WebsiteID,
		Priority: req.Priority, MatchType: req.MatchType, MatchValue: req.MatchValue,
		MatchOp: req.MatchOp, Action: req.Action, TTL: req.TTL,
		ExpiresAt: expiresAt, Enabled: true,
		Source: source, Remark: req.Remark,
		KeepInspecting: req.KeepInspecting,
	}
	if err := global.DB.Create(&rule).Error; err != nil {
		return err
	}
	if err := w.syncDataPlane(); err != nil {
		_ = global.DB.Delete(&rule).Error
		_ = w.syncDataPlane()
		return err
	}
	return nil
}

func (w WAFService) UpdateRule(req request.WAFRuleUpdate) error {
	var rule model.WAFRule
	if err := global.DB.First(&rule, req.ID).Error; err != nil {
		return err
	}
	original := rule
	rule.Name = req.Name
	rule.Priority = req.Priority
	rule.MatchType = req.MatchType
	rule.MatchValue = req.MatchValue
	rule.MatchOp = req.MatchOp
	rule.Action = req.Action
	rule.Enabled = req.Enabled
	rule.Remark = req.Remark
	rule.KeepInspecting = req.KeepInspecting
	if req.TTL > 0 {
		rule.TTL = req.TTL
		t := time.Now().Add(time.Duration(req.TTL) * time.Second)
		rule.ExpiresAt = &t
	} else {
		rule.TTL = 0
		rule.ExpiresAt = nil
	}
	if err := global.DB.Save(&rule).Error; err != nil {
		return err
	}
	if err := w.syncDataPlane(); err != nil {
		_ = global.DB.Save(&original).Error
		_ = w.syncDataPlane()
		return err
	}
	return nil
}

// ReorderRules 按给定顺序重排黑白名单优先级。
//
// 前端传的是「拖完之后看到的完整顺序」，这里按下标重新编号：
// 第一条 priority=1，第二条 2，以此类推。
// 用固定步长 10 而不是连续数字，是给后续在中间插入留出空间 ——
// 用户在列表里新建一条规则时不必重排全部。
func (w WAFService) ReorderRules(req request.WAFRuleReorder) error {
	if len(req.IDs) == 0 {
		return fmt.Errorf("reorder requires at least one rule id")
	}
	// 同一批里出现重复 ID 会让编号互相覆盖，先拒掉。
	seen := make(map[uint]bool, len(req.IDs))
	for _, id := range req.IDs {
		if id == 0 {
			return fmt.Errorf("reorder contains zero id")
		}
		if seen[id] {
			return fmt.Errorf("duplicate rule id in reorder: %d", id)
		}
		seen[id] = true
	}

	var originals []model.WAFRule
	if err := global.DB.Where("id IN ?", req.IDs).Find(&originals).Error; err != nil {
		return err
	}
	// 传了不存在的 ID 直接报错：静默忽略会让用户以为排序生效了，
	// 实际部分规则没动，而列表里看不出差别。
	if len(originals) != len(req.IDs) {
		found := make(map[uint]bool, len(originals))
		for _, r := range originals {
			found[r.ID] = true
		}
		var missing []uint
		for _, id := range req.IDs {
			if !found[id] {
				missing = append(missing, id)
			}
		}
		return fmt.Errorf("reorder references unknown rule ids: %v", missing)
	}

	backup := make(map[uint]int, len(originals))
	for _, r := range originals {
		backup[r.ID] = r.Priority
	}

	// 事务：中途失败要能整体回滚，否则规则优先级会处于半更新状态，
	// 而优先级直接决定名单的生效顺序，出错就是防护行为不确定。
	err := global.DB.Transaction(func(tx *gorm.DB) error {
		for i, id := range req.IDs {
			priority := (i + 1) * 10
			if err := tx.Model(&model.WAFRule{}).Where("id = ?", id).
				Update("priority", priority).Error; err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		// 事务失败时 gorm 已自动 Rollback，DB 里就是原值，不需要再手工回滚。
		//
		// 曾经在这里多写一层手工回滚，副作用比看起来大：若事务是因
		// SQLITE_BUSY 失败的，回滚后再发 N 条 UPDATE 会抢同一把写锁、
		// 立刻再失败一遍，N 条错误日志把真正的根因（锁竞争）淹没。
		// 而那段注释写的「此时数据已经不可信」也是错的 —— 事务已回滚，
		// 数据恰恰是可信的，误导后续维护者以为事务不可靠。
		return err
	}

	if err := w.syncDataPlane(); err != nil {
		// 这里才需要手工回滚：事务已提交，DB 里是新值，
		// 但数据面（rules.json）还是旧的 —— 优先级与实际生效顺序不一致。
		for id, priority := range backup {
			if rbErr := global.DB.Model(&model.WAFRule{}).Where("id = ?", id).
				Update("priority", priority).Error; rbErr != nil {
				// 回滚失败必须留下痕迹：此时 DB 是新值、数据面是旧值，
				// 名单生效顺序处于不确定状态，需要人工介入。
				global.LOG.Errorf("[waf] reorder rollback failed for rule %d: %v", id, rbErr)
			}
		}
		if rbErr := w.syncDataPlane(); rbErr != nil {
			global.LOG.Errorf("[waf] reorder re-sync after rollback failed: %v", rbErr)
		}
		return err
	}
	return nil
}

func (w WAFService) DeleteRule(id uint) error {
	var original model.WAFRule
	if err := global.DB.First(&original, id).Error; err != nil {
		return err
	}
	if err := global.DB.Delete(&original).Error; err != nil {
		return err
	}
	if err := w.syncDataPlane(); err != nil {
		_ = global.DB.Create(&original).Error
		_ = w.syncDataPlane()
		return err
	}
	return nil
}

// ==================== 机器人 / 探测策略 ====================

func (w WAFService) GetOption(websiteID uint) (*model.WAFOption, error) {
	var opt model.WAFOption
	err := global.DB.Where("website_id = ?", websiteID).First(&opt).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return &model.WAFOption{WebsiteID: websiteID, AllowGoodBots: true, BlockBadBots: true, ProbeMaxURIs: 60, ProbeWindow: 60, ProbeMaxRPS: 120}, nil
		}
		return nil, err
	}
	return &opt, nil
}

func (w WAFService) UpdateOption(req request.WAFOptionUpdate) error {
	var opt model.WAFOption
	err := global.DB.Where("website_id = ?", req.WebsiteID).First(&opt).Error
	wasNew := errors.Is(err, gorm.ErrRecordNotFound)
	original := opt
	if err != nil {
		if !wasNew {
			return err
		}
		opt = model.WAFOption{WebsiteID: req.WebsiteID, AllowGoodBots: true, BlockBadBots: true, ProbeMaxURIs: 60, ProbeWindow: 60, ProbeMaxRPS: 120}
	}
	opt.BotEnabled = req.BotEnabled
	opt.AllowGoodBots = req.AllowGoodBots
	opt.BlockBadBots = req.BlockBadBots
	opt.ProbeEnabled = req.ProbeEnabled
	if req.ProbeMaxURIs > 0 {
		opt.ProbeMaxURIs = req.ProbeMaxURIs
	}
	if req.ProbeWindow > 0 {
		opt.ProbeWindow = req.ProbeWindow
	}
	if req.ProbeMaxRPS > 0 {
		opt.ProbeMaxRPS = req.ProbeMaxRPS
	}
	// Mode / 拦截页 / 检测器开关：空值保持原有。
	// 刻意不用 `= req.X` 直接赋值 —— 前端只提交部分字段时（老版本前端、
	// 或某个调用方只想改 bot 开关），直接赋值会把没带的字段清空。
	if req.Mode != "" {
		opt.Mode = req.Mode
	}
	if req.BlockPageTitle != "" {
		opt.BlockPageTitle = req.BlockPageTitle
	}
	if req.BlockPageBody != "" {
		opt.BlockPageBody = req.BlockPageBody
	}
	if req.BlockPageBgColor != "" {
		opt.BlockPageBgColor = req.BlockPageBgColor
	}
	if req.BlockPageTextColor != "" {
		opt.BlockPageTextColor = req.BlockPageTextColor
	}
	if req.DisabledDetectors != "" {
		opt.DisabledDetectors = req.DisabledDetectors
	}
	if req.SemanticLevel != "" {
		opt.SemanticLevel = req.SemanticLevel
	}
	if req.BotLevel != "" {
		opt.BotLevel = req.BotLevel
	}
	if err := global.DB.Save(&opt).Error; err != nil {
		return err
	}
	if err := w.syncDataPlane(); err != nil {
		if wasNew {
			_ = global.DB.Delete(&opt).Error
		} else {
			_ = global.DB.Save(&original).Error
		}
		_ = w.syncDataPlane()
		return err
	}
	return nil
}

// ==================== Webhook 外发设置 ====================

func (w WAFService) GetWebhookSetting() (map[string]interface{}, error) {
	res := map[string]interface{}{
		"enable": false,
		"method": "custom",
		"url":    "",
	}
	if item, err := settingRepo.Get(settingRepo.WithByKey("WAFWebhookEnable")); err == nil {
		res["enable"] = item.Value == "true" || item.Value == "enable"
	}
	if item, err := settingRepo.Get(settingRepo.WithByKey("WAFWebhookMethod")); err == nil && item.Value != "" {
		res["method"] = item.Value
	}
	if item, err := settingRepo.Get(settingRepo.WithByKey("WAFWebhookURL")); err == nil {
		res["url"] = item.Value
	}
	return res, nil
}

func (w WAFService) UpdateWebhookSetting(req request.WAFWebhookUpdate) error {
	values := map[string]string{
		"WAFWebhookEnable": fmt.Sprintf("%v", req.Enable),
		"WAFWebhookMethod": req.Method,
		"WAFWebhookURL":    req.URL,
	}
	for key, value := range values {
		var item model.Setting
		err := global.DB.Where("key = ?", key).First(&item).Error
		if err != nil {
			if err := global.DB.Create(&model.Setting{Key: key, Value: value}).Error; err != nil {
				return err
			}
			continue
		}
		if err := global.DB.Model(&item).Update("value", value).Error; err != nil {
			return err
		}
	}
	return nil
}

// ==================== 日志 ====================

func (w WAFService) SearchLogs(req request.WAFLogSearch) (int64, []model.WAFLog, error) {
	var (
		total int64
		logs  []model.WAFLog
	)
	db := global.DB.Model(&model.WAFLog{})
	if req.WebsiteID > 0 {
		db = db.Where("website_id = ?", req.WebsiteID)
	}
	if req.AttackType != "" {
		db = db.Where("attack_type = ?", req.AttackType)
	}
	if req.IP != "" {
		db = db.Where("ip = ?", req.IP)
	}
	if req.RuleID != "" {
		db = db.Where("rule_id = ?", req.RuleID)
	}
	if req.Action != "" {
		db = db.Where("action = ?", req.Action)
	}
	if req.FalsePositive != nil {
		db = db.Where("false_positive = ?", *req.FalsePositive)
	}
	if req.StartTime > 0 {
		db = db.Where("created_at >= ?", time.Unix(req.StartTime, 0))
	}
	if req.EndTime > 0 {
		db = db.Where("created_at <= ?", time.Unix(req.EndTime, 0))
	}
	if err := db.Count(&total).Error; err != nil {
		return 0, nil, err
	}
	order := wafLogOrder(req)
	err := db.Order(order).Offset((req.Page - 1) * req.PageSize).Limit(req.PageSize).Find(&logs).Error
	return total, logs, err
}

// wafLogSortableColumns 是日志查询允许排序的列白名单。
// 白名单是必须的：Order 的字符串会被拼进 SQL ORDER BY，
// 直接透传前端传来的列名等于开放 SQL 注入面。
var wafLogSortableColumns = map[string]string{
	"":               "created_at",
	"created_at":     "created_at",
	"ip":             "ip",
	"attack_type":    "attack_type",
	"action":         "action",
	"duration_ms":    "duration_ms",
	"path":           "path",
	"website_id":     "website_id",
	"false_positive": "false_positive",
}

// wafLogOrder 组装 ORDER BY 子句。列名走白名单映射，
// 未知列一律退回 created_at；方向只认 asc/desc，其余按 desc。
// 附加 id 作为次级排序键：created_at 有秒级精度，同秒插入的多条记录
// 若不追加 tie-breaker，分页时会出现同一条记录在两页里各出现一次。
func wafLogOrder(req request.WAFLogSearch) string {
	col, ok := wafLogSortableColumns[req.OrderBy]
	if !ok {
		col = "created_at"
	}
	dir := "desc"
	if strings.EqualFold(req.Order, "asc") {
		dir = "asc"
	}
	if col == "created_at" {
		return "created_at " + dir + ", id " + dir
	}
	return col + " " + dir + ", id " + dir
}

type WAFStatItem struct {
	Key   string `json:"key"`
	Count int64  `json:"count"`
}

// StatLogs 聚合统计：攻击类型分布、Top 攻击源、时间趋势
// 时间趋势在 Go 侧按天归并，避免依赖特定数据库的日期函数（agent 使用 SQLite）
// 注意：gorm 链式条件不可复用（Group 等 clause 会泄漏到后续查询），每次查询取新链
func (w WAFService) StatLogs(req request.WAFLogSearch) (map[string][]WAFStatItem, error) {
	newBase := func() *gorm.DB {
		db := global.DB.Model(&model.WAFLog{})
		if req.WebsiteID > 0 {
			db = db.Where("website_id = ?", req.WebsiteID)
		}
		if req.StartTime > 0 {
			db = db.Where("created_at >= ?", time.Unix(req.StartTime, 0))
		}
		if req.EndTime > 0 {
			db = db.Where("created_at <= ?", time.Unix(req.EndTime, 0))
		}
		return db
	}
	// 三个维度都初始化成空切片而非 nil：无数据时 JSON 序列化成 [] 而不是 null，
	// 前端的 stat.attackType?.length 拿到的是 0 而不是抛错。
	res := map[string][]WAFStatItem{
		"attackType": {},
		"topIP":      {},
		"trend":      {},
	}
	var byType, byIP []WAFStatItem
	if err := newBase().Select("attack_type as key, count(*) as count").Where("attack_type != ''").Group("attack_type").Scan(&byType).Error; err != nil {
		return nil, err
	}
	if err := newBase().Select("ip as key, count(*) as count").Group("ip").Order("count desc").Limit(10).Scan(&byIP).Error; err != nil {
		return nil, err
	}
	if byType == nil {
		byType = []WAFStatItem{}
	}
	if byIP == nil {
		byIP = []WAFStatItem{}
	}
	byTime, err := statLogsTrend(newBase(), req)
	if err != nil {
		return nil, err
	}
	res["attackType"] = byType
	res["topIP"] = byIP
	res["trend"] = byTime
	return res, nil
}

// ExportLogs 导出日志（json/csv）
func (w WAFService) ExportLogs(req request.WAFLogSearch) (string, []byte, error) {
	req.Page, req.PageSize = 1, 10000
	_, logs, err := w.SearchLogs(req)
	if err != nil {
		return "", nil, err
	}
	if req.Format == "csv" {
		var sb strings.Builder
		sb.WriteString("time,website,attack_type,action,rule,ip,area,method,path,user_agent,detail,false_positive,disposition_remark\n")
		for _, l := range logs {
			row := []string{l.CreatedAt.Format(time.RFC3339), l.WebsiteName, l.AttackType, l.Action, l.RuleName, l.IP, l.Area, l.Method, l.Path, l.UserAgent, l.Detail, strconv.FormatBool(l.FalsePositive), l.DispositionRemark}
			for i, c := range row {
				if i > 0 {
					sb.WriteString(",")
				}
				sb.WriteString(`"` + strings.ReplaceAll(c, `"`, `""`) + `"`)
			}
			sb.WriteString("\n")
		}
		return "csv", []byte(sb.String()), nil
	}
	content, err := json.Marshal(logs)
	return "json", content, err
}

// AddRuleFromLog 日志页一键加白
func (w WAFService) AddRuleFromLog(logID uint, action string) error {
	var l model.WAFLog
	if err := global.DB.First(&l, logID).Error; err != nil {
		return err
	}
	if action != model.WAFActionAllow && action != model.WAFActionDeny && action != model.WAFActionLog {
		action = model.WAFActionAllow
	}
	return w.CreateRule(request.WAFRuleCreate{
		Name:       fmt.Sprintf("from-log-%d", l.ID),
		Scope:      model.WAFScopeSite,
		WebsiteID:  l.WebsiteID,
		MatchType:  "ip",
		MatchValue: l.IP,
		MatchOp:    "exact",
		Action:     action,
		Priority:   10,
		Remark:     fmt.Sprintf("path=%s attack=%s", l.Path, l.AttackType),
	})
}

func (w WAFService) MarkFalsePositive(req request.WAFFalsePositiveOp) error {
	var log model.WAFLog
	if err := global.DB.First(&log, req.LogID).Error; err != nil {
		return err
	}
	ttl := req.TTL
	if ttl == 0 {
		ttl = 24 * 60 * 60
	}
	if ttl < 60 || ttl > 30*24*60*60 {
		return fmt.Errorf("false positive allow TTL must be between 60 and 2592000 seconds")
	}
	matchType, matchValue := "", ""
	quotedIP, ipOK := quoteWAFExprValue(log.IP)
	quotedPath, pathOK := quoteWAFExprValue(log.Path)
	if log.IP != "" && log.Path != "" && ipOK && pathOK {
		matchType = "expr"
		matchValue = "ip in " + quotedIP + " and path eq " + quotedPath
	} else if log.IP != "" {
		matchType, matchValue = "ip", log.IP
	} else if log.Path != "" {
		matchType, matchValue = "path", log.Path
	}
	if matchValue == "" {
		return fmt.Errorf("log has no path or IP for temporary allow rule")
	}
	originalFalsePositive, originalRemark, originalAt := log.FalsePositive, log.DispositionRemark, log.DispositionAt
	now := time.Now()
	log.FalsePositive = true
	log.DispositionRemark = req.Remark
	log.DispositionAt = &now
	if err := global.DB.Save(&log).Error; err != nil {
		return err
	}
	remark := fmt.Sprintf("false positive log %d", log.ID)
	if req.Remark != "" {
		remark += ": " + req.Remark
	}
	if err := w.createRule(request.WAFRuleCreate{
		Name:       fmt.Sprintf("false-positive-%d", log.ID),
		Scope:      model.WAFScopeSite,
		WebsiteID:  log.WebsiteID,
		Priority:   10,
		MatchType:  matchType,
		MatchValue: matchValue,
		MatchOp:    "exact",
		Action:     model.WAFActionAllow,
		TTL:        ttl,
		Remark:     remark,
		// 误报反馈默认开启「加白时仍检测」：
		// 用户点这一下是为了"别再拦我"，不是"别再让我看见"。
		// 默认彻底放行的话，这条攻击后续就彻底消失在视野里 ——
		// 万一误报的是真攻击，运营无从察觉。
		KeepInspecting: true,
	}, "false_positive"); err != nil {
		log.FalsePositive, log.DispositionRemark, log.DispositionAt = originalFalsePositive, originalRemark, originalAt
		_ = global.DB.Save(&log).Error
		return err
	}
	// 误报样本一并入上报队列。
	//
	// 这是质量最高的候选信号：用户亲自确认「这个请求不该被拦」，
	// 比自动收集的 deny 事件准确得多。用于上游反馈与规则调优，
	// 任何上报都只是候选，不会因此改动本机的拦截行为。
	if log.Layer == "subscription" {
		// 订阅黑名单命中不是误报报告的内容：该 IP 是被公开源标记的，
		// 用户觉得误报说明上游数据有偏差，应反馈给上游而不是当攻击样本上报。
		global.LOG.Debugf("[waf] skip false-positive report for subscription block: log %d", log.ID)
	} else {
		enqueueReports([]WAFReportEvent{{
			IP:            log.IP,
			AttackType:    log.AttackType,
			URL:           log.Path,
			Payload:       log.Detail,
			Method:        log.Method,
			UA:            log.UserAgent,
			Website:       wafSiteHash(log.WebsiteName),
			FalsePositive: true,
		}})
	}
	return nil
}

func quoteWAFExprValue(value string) (string, bool) {
	if !strings.Contains(value, `"`) {
		return `"` + value + `"`, true
	}
	if !strings.Contains(value, `'`) {
		return `'` + value + `'`, true
	}
	return "", false
}

// CleanExpiredRules 定时清理过期名单
func (w WAFService) CleanExpiredRules() {
	result := global.DB.Where("expires_at IS NOT NULL AND expires_at < ?", time.Now()).Delete(&model.WAFRule{})
	if result.Error != nil {
		global.LOG.Errorf("[waf] clean expired rules failed: %v", result.Error)
		return
	}
	if result.RowsAffected > 0 {
		if err := w.syncDataPlane(); err != nil {
			global.LOG.Errorf("[waf] sync rules after expiry cleanup failed: %v", err)
		}
	}
}

// CleanExpiredLogs 按保留天数清理日志（默认 30 天）
func (w WAFService) CleanExpiredLogs() {
	days := 30
	if item, err := settingRepo.Get(settingRepo.WithByKey("WAFLogRetentionDays")); err == nil && item.Value != "" {
		if n, err := strconv.Atoi(item.Value); err == nil && n > 0 {
			days = n
		}
	}
	if err := global.DB.Where("created_at < ?", time.Now().AddDate(0, 0, -days)).Delete(&model.WAFLog{}).Error; err != nil {
		global.LOG.Errorf("[waf] clean expired logs failed: %v", err)
	}
}

// IngestLogs 从数据面缓冲文件批量入库并轮转
func (w WAFService) IngestLogs() {
	fileOp := files.NewFileOp()
	confDir, err := wafHostConfDir()
	if err != nil {
		return
	}
	logPath := path.Join(wafutils.HostWAFDir(confDir), "waf_events.log")
	if !fileOp.Stat(logPath) {
		return
	}
	// 先改名再读取，避免读取与清空之间新写入的事件丢失
	tmpPath := logPath + ".collecting"
	if err := os.Rename(logPath, tmpPath); err != nil {
		global.LOG.Errorf("[waf] rotate log buffer failed: %v", err)
		return
	}
	content, err := fileOp.GetContent(tmpPath)
	if err != nil || len(content) == 0 {
		_ = os.Remove(tmpPath)
		return
	}
	var logs []model.WAFLog
	for _, line := range strings.Split(string(content), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var raw map[string]interface{}
		if err := json.Unmarshal([]byte(line), &raw); err != nil {
			continue
		}
		log := model.WAFLog{}
		log.WebsiteID = toUint(raw["websiteId"])
		log.WebsiteName = toString(raw["websiteName"])
		log.RuleID = toString(raw["ruleId"])
		log.RuleName = toString(raw["ruleName"])
		log.Layer = toString(raw["layer"])
		log.AttackType = toString(raw["attackType"])
		log.Action = toString(raw["action"])
		log.IP = toString(raw["ip"])
		log.Method = toString(raw["method"])
		log.Path = toString(raw["path"])
		log.Query = toString(raw["query"])
		log.UserAgent = toString(raw["userAgent"])
		log.Detail = toString(raw["detail"])
		log.RequestBody = toString(raw["requestBody"])
		log.DurationMs = toFloat(raw["durationMs"])
		if ts, ok := raw["time"].(float64); ok {
			log.CreatedAt = time.Unix(int64(ts), 0)
		}
		logs = append(logs, log)
	}
	if reader, geoErr := geo.NewGeo(); geoErr == nil {
		enrichWAFAreas(logs, func(ip string) (string, error) {
			return geo.GetIPLocation(reader, ip, "zh")
		})
		_ = reader.Close()
	}
	if len(logs) > 0 {
		if err := global.DB.CreateInBatches(logs, 100).Error; err != nil {
			global.LOG.Errorf("[waf] ingest logs failed: %v", err)
			return
		}
		w.pushWebhooks(logs)
		w.pushReports(logs)
	}
	// 处理完删除轮转文件
	_ = os.Remove(tmpPath)
}

func enrichWAFAreas(logs []model.WAFLog, lookup func(string) (string, error)) {
	if lookup == nil {
		return
	}
	cache := make(map[string]string)
	for i := range logs {
		if logs[i].IP == "" || logs[i].Area != "" {
			continue
		}
		if area, ok := cache[logs[i].IP]; ok {
			logs[i].Area = area
			continue
		}
		area, err := lookup(logs[i].IP)
		if err != nil {
			continue
		}
		area = strings.TrimSpace(area)
		cache[logs[i].IP] = area
		logs[i].Area = area
	}
}

// wafWebhookSetting 读取外发设置（enable, method, url）
func wafWebhookSetting() (bool, string, string) {
	enable, method, url := false, "", ""
	if item, err := settingRepo.Get(settingRepo.WithByKey("WAFWebhookEnable")); err == nil {
		enable = item.Value == "true" || item.Value == "enable"
	}
	if item, err := settingRepo.Get(settingRepo.WithByKey("WAFWebhookMethod")); err == nil {
		method = item.Value
	}
	if item, err := settingRepo.Get(settingRepo.WithByKey("WAFWebhookURL")); err == nil {
		url = item.Value
	}
	return enable && url != "", method, url
}

// pushWebhooks 将本轮拦截事件外发到配置的 Webhook（企业微信/钉钉/飞书/自定义）
// 发送失败仅记日志，不影响入库与请求
func (w WAFService) pushWebhooks(logs []model.WAFLog) {
	enable, method, url := wafWebhookSetting()
	if !enable {
		return
	}
	go func() {
		for _, l := range logs {
			if l.Action != model.WAFActionDeny {
				continue
			}
			text := fmt.Sprintf("site: %s\nattack: %s\nip: %s\n%s %s\ndetail: %s",
				l.WebsiteName, l.AttackType, l.IP, l.Method, l.Path, l.Detail)
			payload, err := webhook_sender.BuildWebhookPayload(method, "[3panel WAF] 拦截事件", text)
			if err != nil {
				global.LOG.Errorf("[waf] build webhook payload failed: %v", err)
				return
			}
			if err := webhook_sender.SendWebhookRequest(method, url, payload, nil); err != nil {
				global.LOG.Errorf("[waf] send webhook failed: %v", err)
				return
			}
		}
	}()
}

var wafNumRe = regexp.MustCompile(`^[0-9]+$`)

func toUint(v interface{}) uint {
	if f, ok := v.(float64); ok {
		return uint(f)
	}
	if s, ok := v.(string); ok && wafNumRe.MatchString(s) {
		n, _ := strconv.Atoi(s)
		return uint(n)
	}
	return 0
}

func toString(v interface{}) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func toFloat(v interface{}) float64 {
	if f, ok := v.(float64); ok {
		return f
	}
	return 0
}

// statLogsTrend 按时间桶聚合趋势。
//
// 历史实现是把时间范围内的每一行日志 Select 到 Go 内存里再按天计数，
// 注释理由是「避免依赖特定数据库的日期函数」。代价是查询量随日志量线性增长：
// 一个月的高流量站点能轻松到百万行，直接把 agent 进程撑爆。
//
// 现在改成在 SQL 侧分组：日志表已有 created_at 索引，分组只扫索引不扫表体。
// 日期格式化用 SQLite 与 MySQL 都支持的 strftime（agent 固定跑 SQLite）。
func statLogsTrend(base *gorm.DB, req request.WAFLogSearch) ([]WAFStatItem, error) {
	format := "%Y-%m-%d"
	if req.TrendGranularity == "hour" {
		format = "%Y-%m-%d %H"
	}
	var rows []WAFStatItem
	// 注意 gorm 的链式条件不可复用：Group 会写进 statement，
	// 所以这里直接用传进来的 base（调用方每次都新建），不缓存。
	err := base.
		Select("strftime('" + format + "', created_at) as key, count(*) as count").
		Group("strftime('" + format + "', created_at)").
		Order("key asc").
		Scan(&rows).Error
	if err != nil {
		return nil, err
	}
	if rows == nil {
		rows = []WAFStatItem{}
	}
	return rows, nil
}
