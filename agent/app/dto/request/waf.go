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
	MatchType  string `json:"matchType" validate:"required,oneof=ip cidr ip_group geo path ua referer header cookie method expr"`
	MatchValue string `json:"matchValue" validate:"required"`
	MatchOp    string `json:"matchOp" validate:"omitempty,oneof=exact contains prefix suffix wildcard regex not_exact not_contains not_prefix not_suffix not_wildcard not_regex"`
	Action     string `json:"action" validate:"required,oneof=allow deny challenge log"`
	TTL        int    `json:"ttl"`
	Remark     string `json:"remark"`
	// KeepInspecting：白名单「加白时仍检测」，仅 action=allow 时生效。
	KeepInspecting bool `json:"keepInspecting"`
}

type WAFRuleUpdate struct {
	ID             uint   `json:"id" validate:"required"`
	Name           string `json:"name" validate:"required"`
	Priority       int    `json:"priority"`
	MatchType      string `json:"matchType" validate:"required,oneof=ip cidr ip_group geo path ua referer header cookie method expr"`
	MatchValue     string `json:"matchValue" validate:"required"`
	MatchOp        string `json:"matchOp" validate:"omitempty,oneof=exact contains prefix suffix wildcard regex not_exact not_contains not_prefix not_suffix not_wildcard not_regex"`
	Action         string `json:"action" validate:"required,oneof=allow deny challenge log"`
	TTL            int    `json:"ttl"`
	Enabled        bool   `json:"enabled"`
	Remark         string `json:"remark"`
	KeepInspecting bool   `json:"keepInspecting"`
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
	WebsiteID uint `json:"websiteId" validate:"required"`
	// Enabled 是 CC 防护的总开关。之前开关状态是从 Limit>0 派生的，
	// 于是「配好阈值但先不启用」无法表达：把 limit 填成 0 就等于把配置丢掉。
	Enabled bool   `json:"enabled"`
	Limit   int    `json:"limit"`
	Window  int    `json:"window"`
	Action  string `json:"action" validate:"omitempty,oneof=deny challenge log"`
	ByURI   bool   `json:"byUri"`
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
	// Mode 防护模式：block（防护）/ observe（观察）/ maintenance（维护）。
	// 空 = 保持原有值（新建时为 block）。取值必须与 Lua 侧一致。
	Mode string `json:"mode" validate:"omitempty,oneof=block observe maintenance"`
	// 拦截页定制。留空 = 用内置默认样式。
	// 刻意不接受 HTML 片段：这个页面会展示给所有访问者（含攻击者）。
	//
	// 这四个字段以及下面的 DisabledDetectors 用 *string：必须能区分
	// 「本次没传」与「传了空串」。用 string 时 `if req.X != ""` 会把
	// 「用户清空自定义文案 / 重新勾选全部检测器」当成没改，
	// 界面上表现为取消勾选、清空输入框后保存无效。
	BlockPageTitle     *string `json:"blockPageTitle" validate:"omitempty,max=200"`
	BlockPageBody      *string `json:"blockPageBody" validate:"omitempty,max=2000"`
	BlockPageBgColor   *string `json:"blockPageBgColor" validate:"omitempty,max=32"`
	BlockPageTextColor *string `json:"blockPageTextColor" validate:"omitempty,max=32"`
	// SemanticLevel / BotLevel 保护强度分档：off / observe / balanced / high。
	// 空 = 保持原有值。取值必须与 Lua 侧一致。
	SemanticLevel string `json:"semanticLevel" validate:"omitempty,oneof=off observe balanced high"`
	BotLevel      string `json:"botLevel" validate:"omitempty,oneof=off observe balanced high"`
	// DisabledDetectors 被关闭的语义检测器名，逗号分隔。
	// nil = 不修改；空串 = 全部启用（这是「重新勾选」的唯一表达方式）。
	DisabledDetectors *string `json:"disabledDetectors" validate:"omitempty,max=1000"`
}

type WAFWebhookUpdate struct {
	Enable bool `json:"enable"`
	// 取值必须与 constant.WeCom/DingTalk/FeiShu/Custom 完全一致（驼峰），
	// 也必须与 webhook_sender.BuildWebhookPayload 的 switch 分支名一致。
	// 曾误写成小写 wecom/dingtalk/feishu，导致前端按常量传值一律被 oneof 拒绝，
	// 而面板没有这个配置界面，于是该功能自上线起无人能用过。
	Method string `json:"method" validate:"omitempty,oneof=custom weCom dingTalk feiShu"`
	URL    string `json:"url" validate:"required_if=Enable true,omitempty,url"`
}

// WAFRuleReorder 黑白名单拖动排序。
// 传完整的目标顺序（按数组下标=最终优先级次序），而不是逐条传 priority：
// 前端拖完只有一份最终顺序，让后端按顺序重新编号比前端算差值更不容易错。
// WAFIPGroupCreate / Update 是 IP 组的增改。
//
// 刻意不接受"组名含空格或中文逗号"这类隐式约定 —— 组名会原样出现在
// rules.json 里作为 map 的 key，用户在规则里填错一个字符就是
// 「组不存在」且**没有任何报错**（Lua 查不到键只能放行）。
// 所以组名只允许字母数字下划线短横线，长度上限 64。
type WAFIPGroupCreate struct {
	Name      string `json:"name" validate:"required,max=64"`
	Scope     string `json:"scope" validate:"required,oneof=global site"`
	WebsiteID uint   `json:"websiteId"`
	Enabled   bool   `json:"enabled"`
	Remark    string `json:"remark" validate:"max=255"`
	// CIDRs 是换行或逗号分隔的 IP/CIDR。后端会去空白、去空项、去重。
	// 单次上限 4096 条 —— 再多就该走订阅名单那种外部数据源了。
	CIDRs string `json:"cidrs" validate:"max=65536"`
}

type WAFIPGroupUpdate struct {
	ID        uint   `json:"id" validate:"required,gt=0"`
	Name      string `json:"name" validate:"max=64"`
	Scope     string `json:"scope" validate:"omitempty,oneof=global site"`
	WebsiteID uint   `json:"websiteId"`
	Enabled   bool   `json:"enabled"`
	Remark    string `json:"remark" validate:"max=255"`
	CIDRs     string `json:"cidrs" validate:"max=65536"`
}

type WAFRuleReorder struct {
	// IDs 是有序的规则 ID 列表，第一个优先级最高（数字最小）。
	IDs []uint `json:"ids" validate:"required,min=1,dive,gt=0"`
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
	// OrderBy 指定排序列。与 Order 分开传，而不是让前端拼 "ip:desc" 这种
	// 需要后端二次解析的格式 —— 排序列是白名单校验的，方向是自由值。
	OrderBy string `form:"orderBy" json:"orderBy"`
	// TrendGranularity 控制趋势图的时间粒度：day（默认）或 hour。
	// 小时粒度用于「看峰值」，跨度大时前端会自动退回按天。
	TrendGranularity string `form:"trendGranularity" json:"trendGranularity" validate:"omitempty,oneof=day hour"`
	Format           string `form:"format" json:"format"`
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
