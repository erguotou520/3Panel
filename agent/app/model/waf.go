package model

import "time"

const (
	WAFScopeGlobal = "global"
	WAFScopeSite   = "site"

	WAFActionAllow     = "allow"
	WAFActionDeny      = "deny"
	WAFActionLog       = "log"
	WAFActionChallenge = "challenge"
)

// WAFRule 名单规则（黑/白名单），scope=global 全局生效，scope=site 仅对关联站点生效
type WAFRule struct {
	BaseModel
	Name       string     `gorm:"varchar(128);not null" json:"name"`
	Scope      string     `gorm:"varchar(16);not null;default:global" json:"scope"`
	WebsiteID  uint       `json:"websiteId"`
	Priority   int        `gorm:"default:100" json:"priority"`
	MatchType  string     `gorm:"varchar(32);not null" json:"matchType"`
	MatchValue string     `gorm:"type:text;not null" json:"matchValue"`
	MatchOp    string     `gorm:"varchar(16);default:exact" json:"matchOp"`
	Action     string     `gorm:"varchar(16);not null" json:"action"`
	TTL        int        `json:"ttl"`
	ExpiresAt  *time.Time `json:"expiresAt"`
	Enabled    bool       `gorm:"default:true" json:"enabled"`
	Source     string     `gorm:"varchar(32);default:manual" json:"source"`
	Remark     string     `json:"remark"`
	// KeepInspecting 是白名单的「加白时仍检测」开关，仅对 action=allow 有意义。
	//
	// 默认 false：白名单命中即彻底放行，这是绝大多数场景想要的语义
	//（用户加白就是为了让某个 IP/路径别再被拦）。
	//
	// 置true 后白名单不再终止请求，而是"放行但继续跑后续检测"——
	// 命中攻击规则时**只记日志不拦截**。用于误报排查：
	// 既想让访问正常通过，又想看到"如果规则更严会命中什么"。
	// 误报反馈流程（MarkFalsePositive）默认开启它，
	// 这样"误报"不会变成"攻击彻底看不见"。
	KeepInspecting bool `gorm:"default:false" json:"keepInspecting"`
}

func (w WAFRule) TableName() string {
	return "waf_rules"
}

// WAFCCConfig 站点级 CC 防护配置（每站点一条）
type WAFCCConfig struct {
	BaseModel
	WebsiteID uint   `gorm:"uniqueIndex" json:"websiteId"`
	Limit     int    `json:"limit"`                                  // 窗口内最大请求数，0 = 关闭
	Window    int    `gorm:"default:60" json:"window"`               // 窗口秒数
	Action    string `gorm:"varchar(16);default:deny" json:"action"` // deny | challenge | log
	ByURI     bool   `gorm:"default:false" json:"byUri"`             // 按 IP+URI 维度计数
	Enabled   bool   `gorm:"default:true" json:"enabled"`
}

func (w WAFCCConfig) TableName() string {
	return "waf_cc_configs"
}

// WAFOption 站点级 WAF 策略选项（机器人识别 / 扫描探测阈值）
type WAFOption struct {
	BaseModel
	WebsiteID     uint `gorm:"uniqueIndex" json:"websiteId"`
	BotEnabled    bool `gorm:"default:false" json:"botEnabled"`
	AllowGoodBots bool `gorm:"default:true" json:"allowGoodBots"`
	BlockBadBots  bool `gorm:"default:true" json:"blockBadBots"`
	ProbeEnabled  bool `gorm:"default:false" json:"probeEnabled"`
	ProbeMaxURIs  int  `gorm:"default:60" json:"probeMaxURIs"`
	ProbeWindow   int  `gorm:"default:60" json:"probeWindow"`
	ProbeMaxRPS   int  `gorm:"default:120" json:"probeMaxRPS"`

	// Mode 是站点级防护模式：
	//   block      —— 防护：命中即拦截并记录（默认）
	//   observe    —— 观察：命中只记录日志，一律不拦截。用于新规则上线前的观察期，
	//                 或误伤排查时确认「如果开着会拦多少」。
	//   maintenance —— 维护：所有请求返回维护页，任何人都无法访问应用。
	//                 与 enabled=false 的区别：enabled=false 是「WAF 不介入，请求正常通过」，
	//                 maintenance 是「WAF 主动挡住全部流量」，后者是运维改配置期间的典型需求。
	//
	// 注意 Mode 独立于 Enabled：enabled=false 时 WAF 整个旁路，
	// 此时 Mode 不生效（数据面在 site.enabled == false 时就 return 了）。
	Mode string `gorm:"varchar(16);default:block" json:"mode"`

	// BlockPage 是拦截页定制。留空则用内置默认样式。
	// 只存文本，不存 HTML 片段 —— 让用户填任意 HTML 意味着面板自己可能被注入
	// 脚本（这个页面对所有访问者展示，含攻击者）。需要更自由的排版时应走模板。
	BlockPageTitle     string `gorm:"type:text" json:"blockPageTitle"`
	BlockPageBody      string `gorm:"type:text" json:"blockPageBody"`
	BlockPageBgColor   string `gorm:"varchar(32)" json:"blockPageBgColor"`
	BlockPageTextColor string `gorm:"varchar(32)" json:"blockPageTextColor"`

	// DisabledDetectors 是被关闭的语义检测器名列表（逗号分隔），
	// 取值见 semantic.lua 的 _M.attack_types。
	// 空 = 全部启用。用来临时关掉误伤率高的某一类检测。
	DisabledDetectors string `gorm:"type:text" json:"disabledDetectors"`
}

func (w WAFOption) TableName() string {
	return "waf_options"
}

// WAFLog WAF 命中/拦截日志
type WAFLog struct {
	BaseModel
	WebsiteID         uint       `gorm:"index" json:"websiteId"`
	WebsiteName       string     `json:"websiteName"`
	RuleID            string     `gorm:"varchar(64)" json:"ruleId"`
	RuleName          string     `gorm:"varchar(128)" json:"ruleName"`
	Layer             string     `gorm:"varchar(32)" json:"layer"`
	AttackType        string     `gorm:"varchar(32);index" json:"attackType"`
	Action            string     `gorm:"varchar(16)" json:"action"`
	IP                string     `gorm:"varchar(64);index" json:"ip"`
	Area              string     `gorm:"varchar(128)" json:"area"`
	Method            string     `gorm:"varchar(16)" json:"method"`
	Path              string     `gorm:"type:text" json:"path"`
	Query             string     `gorm:"type:text" json:"query"`
	UserAgent         string     `gorm:"type:text" json:"userAgent"`
	Detail            string     `gorm:"type:text" json:"detail"`
	RequestBody       string     `gorm:"type:text" json:"requestBody"`
	DurationMs        float64    `json:"durationMs"`
	FalsePositive     bool       `gorm:"default:false;index" json:"falsePositive"`
	DispositionRemark string     `gorm:"type:text" json:"dispositionRemark"`
	DispositionAt     *time.Time `json:"dispositionAt"`
	CreatedAt         time.Time  `gorm:"index" json:"createdAt"`
}

func (w WAFLog) TableName() string {
	return "waf_logs"
}

// WAFIPListSetting 是全局 IP 黑名单订阅与攻击上报配置（单例，ID 恒为 1）。
type WAFIPListSetting struct {
	ID         uint `gorm:"primarykey" json:"id"`
	Enabled    bool `json:"enabled" gorm:"not null;default:false"`
	AutoUpdate bool `json:"autoUpdate" gorm:"not null;default:true"`
	// IntervalHours 为自动更新间隔，最小 2 小时（CI 每天只跑两次）。
	IntervalHours int `json:"intervalHours" gorm:"not null;default:12"`
	// ReportEnabled 控制是否向社区 Worker 上报拦截事件，默认关闭。
	ReportEnabled bool   `json:"reportEnabled" gorm:"not null;default:false"`
	ReportURL     string `json:"reportUrl" gorm:"type:varchar(512)"`
	// PanelID 是本实例的稳定哈希，只在首次生成后固化。
	// 上报端用它做去重，若每次都变则单个实例能伪装成多个。
	PanelID string `json:"-" gorm:"type:varchar(64)"`
}

func (WAFIPListSetting) TableName() string { return "waf_iplist_settings" }
