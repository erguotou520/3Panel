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
}

func (w WAFRule) TableName() string {
	return "waf_rules"
}

// WAFCCConfig 站点级 CC 防护配置（每站点一条）
type WAFCCConfig struct {
	BaseModel
	WebsiteID uint   `gorm:"uniqueIndex" json:"websiteId"`
	Limit     int    `json:"limit"`               // 窗口内最大请求数，0 = 关闭
	Window    int    `gorm:"default:60" json:"window"` // 窗口秒数
	Action    string `gorm:"varchar(16);default:deny" json:"action"`  // deny | challenge | log
	ByURI     bool   `gorm:"default:false" json:"byUri"` // 按 IP+URI 维度计数
	Enabled   bool   `gorm:"default:true" json:"enabled"`
}

func (w WAFCCConfig) TableName() string {
	return "waf_cc_configs"
}

// WAFOption 站点级 WAF 策略选项（机器人识别 / 扫描探测阈值）
type WAFOption struct {
	BaseModel
	WebsiteID     uint  `gorm:"uniqueIndex" json:"websiteId"`
	BotEnabled    bool  `gorm:"default:false" json:"botEnabled"`
	AllowGoodBots bool  `gorm:"default:true" json:"allowGoodBots"`
	BlockBadBots  bool  `gorm:"default:true" json:"blockBadBots"`
	ProbeEnabled  bool  `gorm:"default:false" json:"probeEnabled"`
	ProbeMaxURIs  int   `gorm:"default:60" json:"probeMaxURIs"`
	ProbeWindow   int   `gorm:"default:60" json:"probeWindow"`
	ProbeMaxRPS   int   `gorm:"default:120" json:"probeMaxRPS"`
}

func (w WAFOption) TableName() string {
	return "waf_options"
}

// WAFLog WAF 命中/拦截日志
type WAFLog struct {
	BaseModel
	WebsiteID   uint      `gorm:"index" json:"websiteId"`
	WebsiteName string    `json:"websiteName"`
	RuleID      string    `gorm:"varchar(64)" json:"ruleId"`
	RuleName    string    `gorm:"varchar(128)" json:"ruleName"`
	Layer       string    `gorm:"varchar(32)" json:"layer"`
	AttackType  string    `gorm:"varchar(32);index" json:"attackType"`
	Action      string    `gorm:"varchar(16)" json:"action"`
	IP          string    `gorm:"varchar(64);index" json:"ip"`
	Method      string    `gorm:"varchar(16)" json:"method"`
	Path        string    `gorm:"type:text" json:"path"`
	Query       string    `gorm:"type:text" json:"query"`
	UserAgent   string    `gorm:"type:text" json:"userAgent"`
	Detail      string    `gorm:"type:text" json:"detail"`
	RequestBody string    `gorm:"type:text" json:"requestBody"`
	DurationMs  float64   `json:"durationMs"`
	CreatedAt   time.Time `gorm:"index" json:"createdAt"`
}

func (w WAFLog) TableName() string {
	return "waf_logs"
}
