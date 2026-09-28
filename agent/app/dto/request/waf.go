package request

type WAFRuleSearch struct {
	Scope     string `json:"scope"`
	WebsiteID uint   `json:"websiteId"`
	Action    string `json:"action"`
}

type WAFRuleCreate struct {
	Name       string `json:"name" validate:"required"`
	Scope      string `json:"scope" validate:"required,oneof=global site"`
	WebsiteID  uint   `json:"websiteId"`
	Priority   int    `json:"priority"`
	MatchType  string `json:"matchType" validate:"required,oneof=ip cidr path ua referer header cookie method expr"`
	MatchValue string `json:"matchValue" validate:"required"`
	MatchOp    string `json:"matchOp" validate:"omitempty,oneof=exact contains prefix suffix wildcard regex"`
	Action     string `json:"action" validate:"required,oneof=allow deny challenge log"`
	TTL        int    `json:"ttl"`
	Remark     string `json:"remark"`
}

type WAFRuleUpdate struct {
	ID         uint   `json:"id" validate:"required"`
	Name       string `json:"name" validate:"required"`
	Priority   int    `json:"priority"`
	MatchType  string `json:"matchType" validate:"required"`
	MatchValue string `json:"matchValue" validate:"required"`
	MatchOp    string `json:"matchOp" validate:"omitempty,oneof=exact contains prefix suffix wildcard regex"`
	Action     string `json:"action" validate:"required,oneof=allow deny challenge log"`
	TTL        int    `json:"ttl"`
	Enabled    bool   `json:"enabled"`
	Remark     string `json:"remark"`
}

type WAFRuleOp struct {
	ID      uint  `json:"id" validate:"required"`
	Enabled *bool `json:"enabled"`
}

type WAFWebsiteOp struct {
	WebsiteID uint   `json:"websiteId" validate:"required"`
	Operate   string `json:"operate" validate:"required,oneof=enable disable"`
}

type WAFCCUpdate struct {
	WebsiteID uint   `json:"websiteId" validate:"required"`
	Limit     int    `json:"limit"`
	Window    int    `json:"window"`
	Action    string `json:"action" validate:"omitempty,oneof=deny challenge log"`
	ByURI     bool   `json:"byUri"`
}

type WAFOptionUpdate struct {
	WebsiteID     uint `json:"websiteId" validate:"required"`
	BotEnabled    bool `json:"botEnabled"`
	AllowGoodBots bool `json:"allowGoodBots"`
	BlockBadBots  bool `json:"blockBadBots"`
	ProbeEnabled  bool `json:"probeEnabled"`
	ProbeMaxURIs  int  `json:"probeMaxURIs"`
	ProbeWindow   int  `json:"probeWindow"`
	ProbeMaxRPS   int  `json:"probeMaxRPS"`
}

type WAFWebhookUpdate struct {
	Enable bool   `json:"enable"`
	Method string `json:"method" validate:"omitempty,oneof=custom wecom dingtalk feishu"`
	URL    string `json:"url"`
}

type WAFLogSearch struct {
	WebsiteID     uint   `form:"websiteId" json:"websiteId"`
	AttackType    string `form:"attackType" json:"attackType"`
	IP            string `form:"ip" json:"ip"`
	RuleID        string `form:"ruleId" json:"ruleId"`
	Action        string `form:"action" json:"action"`
	FalsePositive *bool  `form:"falsePositive" json:"falsePositive"`
	StartTime     int64  `form:"startTime" json:"startTime"`
	EndTime       int64  `form:"endTime" json:"endTime"`
	Page          int    `form:"page" json:"page"`
	PageSize      int    `form:"pageSize" json:"pageSize"`
	Order         string `form:"order" json:"order"`
	Format        string `form:"format" json:"format"`
}

type WAFLogRuleOp struct {
	LogID  uint   `json:"logId" validate:"required"`
	Action string `json:"action" validate:"required,oneof=allow deny log"`
}

type WAFFalsePositiveOp struct {
	LogID  uint   `json:"logId" validate:"required"`
	TTL    int    `json:"ttl" validate:"omitempty,min=60,max=2592000"`
	Remark string `json:"remark"`
}
