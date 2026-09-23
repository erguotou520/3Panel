package service

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/3panel-dev/3panel/agent/app/dto/request"
	"github.com/3panel-dev/3panel/agent/app/model"
	"github.com/3panel-dev/3panel/agent/app/repo"
	"github.com/3panel-dev/3panel/agent/global"
	"github.com/3panel-dev/3panel/agent/utils/files"
	wafutils "github.com/3panel-dev/3panel/agent/utils/waf"
	"github.com/3panel-dev/3panel/agent/utils/webhook_sender"
	"github.com/3panel-dev/3panel/agent/utils/nginx"
	"github.com/3panel-dev/3panel/agent/utils/nginx/parser"
	"gorm.io/gorm"
)

type WAFService struct {
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
	CleanExpiredRules()
	CleanExpiredLogs()
	IngestLogs()
}

// wafHostConfDir 解析 openresty 宿主机 conf 目录（WAF 资源挂载点）
func wafHostConfDir() (string, error) {
	nginxInstall, err := getAppInstallByKey("openresty")
	if err != nil {
		return "", err
	}
	return path.Join(nginxInstall.GetPath(), "conf"), nil
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
	// 部署 Lua 模块与 http 级配置（幂等）
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
	if err := wafInjectServer(&website, enable); err != nil {
		return err
	}
	website.WafEnabled = enable
	if err := global.DB.Save(&website).Error; err != nil {
		return err
	}
	if enable {
		_ = w.SyncRules()
	}
	return nil
}

// wafEnsureHTTPConfig 确保 openresty nginx.conf 的 http 块有 lua_package_path（幂等）
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
	packagePath := fmt.Sprintf("%s/?.lua;", wafutils.WAFDir)
	// CC 计数与挑战所需的共享内存字典
	if len(httpBlock.FindDirectives("lua_shared_dict")) == 0 {
		httpBlock.UpdateDirective("lua_shared_dict", []string{"waf_dict", "32m"})
	}
	if len(httpBlock.FindDirectives("lua_package_path")) == 0 {
		httpBlock.UpdateDirective("lua_package_path", []string{packagePath})
	} else {
		return nil
	}
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

	accessConf := fmt.Sprintf("%s/access.lua", wafutils.WAFDir)
	confDir, err := wafHostConfDir()
	if err != nil {
		return err
	}
	rulesFile := fmt.Sprintf("%s/rules.json", wafutils.HostWAFDir(confDir))
	logFile := fmt.Sprintf("%s/waf_events.log", wafutils.HostWAFDir(confDir))

	if enable {
		serverBlock.UpdateDirective("set", []string{"$waf_site_id", fmt.Sprintf("%d", website.ID)})
		serverBlock.UpdateDirective("set", []string{"$waf_rules_path", rulesFile})
		serverBlock.UpdateDirective("set", []string{"$waf_log_path", logFile})
		serverBlock.UpdateDirective("access_by_lua_file", []string{accessConf})
	} else {
		serverBlock.RemoveDirective("access_by_lua_file", []string{accessConf})
		serverBlock.RemoveDirective("set", []string{"$waf_site_id", fmt.Sprintf("%d", website.ID)})
		serverBlock.RemoveDirective("set", []string{"$waf_rules_path", rulesFile})
		serverBlock.RemoveDirective("set", []string{"$waf_log_path", logFile})
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
	var ccs []model.WAFCCConfig
	if err := global.DB.Where("enabled = ?", true).Find(&ccs).Error; err != nil {
		return err
	}
	var options []model.WAFOption
	if err := global.DB.Find(&options).Error; err != nil {
		return err
	}
	return wafutils.ExportRules(rules, ccs, options, confDir)
}

func (w WAFService) loadAllRules() []model.WAFRule {
	var rules []model.WAFRule
	_ = global.DB.Where("enabled = ?", true).Order("priority asc").Find(&rules).Error
	return rules
}

func (w WAFService) syncRules() {
	if err := w.SyncRules(); err != nil {
		global.LOG.Errorf("[waf] export rules failed: %v", err)
	}
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
	if err != nil {
		cc = model.WAFCCConfig{WebsiteID: req.WebsiteID}
	}
	cc.Limit = req.Limit
	cc.Window = req.Window
	cc.Action = req.Action
	cc.ByURI = req.ByURI
	cc.Enabled = req.Limit > 0
	if cc.Action == "" {
		cc.Action = model.WAFActionDeny
	}
	if cc.Window <= 0 {
		cc.Window = 60
	}
	if err := global.DB.Save(&cc).Error; err != nil {
		return err
	}
	w.syncRules()
	return nil
}

func (w WAFService) ListRules(req request.WAFRuleSearch) ([]model.WAFRule, error) {
	var rules []model.WAFRule
	db := global.DB.Model(&model.WAFRule{})
	if req.Scope != "" {
		db = db.Where("scope = ?", req.Scope)
	}
	if req.WebsiteID > 0 {
		db = db.Where("website_id = ?", req.WebsiteID)
	}
	if req.Action != "" {
		db = db.Where("action = ?", req.Action)
	}
	err := db.Order("priority asc, id desc").Find(&rules).Error
	return rules, err
}

func (w WAFService) CreateRule(req request.WAFRuleCreate) error {
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
		Source: "manual", Remark: req.Remark,
	}
	if err := global.DB.Create(&rule).Error; err != nil {
		return err
	}
	w.syncRules()
	return nil
}

func (w WAFService) UpdateRule(req request.WAFRuleUpdate) error {
	var rule model.WAFRule
	if err := global.DB.First(&rule, req.ID).Error; err != nil {
		return err
	}
	rule.Name = req.Name
	rule.Priority = req.Priority
	rule.MatchType = req.MatchType
	rule.MatchValue = req.MatchValue
	rule.MatchOp = req.MatchOp
	rule.Action = req.Action
	rule.Enabled = req.Enabled
	rule.Remark = req.Remark
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
	w.syncRules()
	return nil
}

func (w WAFService) DeleteRule(id uint) error {
	if err := global.DB.Delete(&model.WAFRule{}, id).Error; err != nil {
		return err
	}
	w.syncRules()
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
	if err != nil {
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
	if err := global.DB.Save(&opt).Error; err != nil {
		return err
	}
	w.syncRules()
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
	if req.StartTime > 0 {
		db = db.Where("created_at >= ?", time.Unix(req.StartTime, 0))
	}
	if req.EndTime > 0 {
		db = db.Where("created_at <= ?", time.Unix(req.EndTime, 0))
	}
	if err := db.Count(&total).Error; err != nil {
		return 0, nil, err
	}
	order := "created_at desc"
	if req.Order == "asc" {
		order = "created_at asc"
	}
	err := db.Order(order).Offset((req.Page - 1) * req.PageSize).Limit(req.PageSize).Find(&logs).Error
	return total, logs, err
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
	res := map[string][]WAFStatItem{}
	var byType, byIP []WAFStatItem
	if err := newBase().Select("attack_type as key, count(*) as count").Where("attack_type != ''").Group("attack_type").Scan(&byType).Error; err != nil {
		return nil, err
	}
	if err := newBase().Select("ip as key, count(*) as count").Group("ip").Order("count desc").Limit(10).Scan(&byIP).Error; err != nil {
		return nil, err
	}
	var rows []model.WAFLog
	if err := newBase().Select("created_at").Scan(&rows).Error; err != nil {
		return nil, err
	}
	trendMap := map[string]int64{}
	for _, r := range rows {
		day := r.CreatedAt.Format("2006-01-02")
		trendMap[day]++
	}
	byTime := make([]WAFStatItem, 0, len(trendMap))
	for day, count := range trendMap {
		byTime = append(byTime, WAFStatItem{Key: day, Count: count})
	}
	sort.Slice(byTime, func(i, j int) bool { return byTime[i].Key < byTime[j].Key })
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
		sb.WriteString("time,website,attack_type,action,rule,ip,method,path,user_agent,detail\n")
		for _, l := range logs {
			row := []string{l.CreatedAt.Format(time.RFC3339), l.WebsiteName, l.AttackType, l.Action, l.RuleName, l.IP, l.Method, l.Path, l.UserAgent, l.Detail}
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
		Scope:      model.WAFScopeGlobal,
		MatchType:  "ip",
		MatchValue: l.IP,
		MatchOp:    "exact",
		Action:     action,
		Priority:   10,
		Remark:     fmt.Sprintf("path=%s attack=%s", l.Path, l.AttackType),
	})
}

// CleanExpiredRules 定时清理过期名单
func (w WAFService) CleanExpiredRules() {
	if err := global.DB.Where("expires_at IS NOT NULL AND expires_at < ?", time.Now()).Delete(&model.WAFRule{}).Error; err != nil {
		global.LOG.Errorf("[waf] clean expired rules failed: %v", err)
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
	if len(logs) > 0 {
		if err := global.DB.CreateInBatches(logs, 100).Error; err != nil {
			global.LOG.Errorf("[waf] ingest logs failed: %v", err)
			return
		}
		w.pushWebhooks(logs)
	}
	// 处理完删除轮转文件
	_ = os.Remove(tmpPath)
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
