package service

import (
	"strconv"
	"time"

	"github.com/3panel-dev/3panel/agent/app/dto/request"
	"github.com/3panel-dev/3panel/agent/app/model"
	"github.com/3panel-dev/3panel/agent/global"
	"gorm.io/gorm"
)

// WAFStatItem 是通用的「键 → 计数」统计项，前端统一按条形图渲染。
type WAFStatItem struct {
	Key   string `json:"key"`
	Count int64  `json:"count"`
}

// WAFStatSummary 是一眼能看完的汇总指标。
//
// 与各维度分布分开返回：分布回答"哪里多"，汇总回答"总体什么情况"。
// 合并成一个字段会让前端 KPI 卡片要自己遍历一遍分布再算，容易算错。
type WAFStatSummary struct {
	Total         int64 `json:"total"`
	Denied        int64 `json:"denied"`
	Allowed       int64 `json:"allowed"`
	Challenged    int64 `json:"challenged"`
	Logged        int64 `json:"logged"`
	UniqueIPs     int64 `json:"uniqueIPs"`
	FalsePositive int64 `json:"falsePositive"`
	// AvgDurationMs 是平均处理耗时。无数据时为 0 而不是 NaN ——
	// 前端直接渲染，NaN 会显示成 "NaN"。
	AvgDurationMs float64 `json:"avgDurationMs"`
	MaxDurationMs float64 `json:"maxDurationMs"`
}

// WAFStats 是统计接口的完整响应。
//
// 用结构体而不是 map[string][]WAFStatItem：summary 不是"键→计数"的形状，
// 塞进 map 只能靠约定 key 名，类型系统帮不上忙；结构体还能让前端
// 明确知道有哪些维度、字段名拼错时编译期就报错。
type WAFStats struct {
	Summary WAFStatSummary `json:"summary"`

	AttackType []WAFStatItem `json:"attackType"`
	TopIP      []WAFStatItem `json:"topIP"`
	Trend      []WAFStatItem `json:"trend"`

	// Layer 各防护层的命中分布：判断"到底哪一层在起作用"。
	// 配了语义检测但层分布里全是 rules，说明语义层压根没触发。
	Layer []WAFStatItem `json:"layer"`
	// Action 处置构成：拦截 / 放行 / 仅记录 / 挑战。
	Action []WAFStatItem `json:"action"`
	// Area 攻击来源国家/地区。数据来自日志入库时的 maxmind 解析，
	// 所以这个维度不需要数据面参与统计。
	Area []WAFStatItem `json:"area"`
	// TopPath 被打得最多的路径。
	TopPath []WAFStatItem `json:"topPath"`
	// TopUA 攻击来源的 User-Agent 指纹 —— 多数扫描器的 UA 是固定串。
	TopUA []WAFStatItem `json:"topUA"`
	// Method 请求方法分布：异常方法（PUT/DELETE 打静态站）往往就是探测。
	Method []WAFStatItem `json:"method"`
	// TopRule 命中次数最多的规则：用来发现"一条规则包打天下"或规则互相遮蔽。
	TopRule []WAFStatItem `json:"topRule"`
	// Website 站点排行（全局视角下哪个站点被打得最多）。
	Website []WAFStatItem `json:"website"`
	// Duration 处理耗时分布，用于判断 WAF 本身是否拖慢请求。
	Duration []WAFStatItem `json:"duration"`
	// FalsePositive 被标记为误报的攻击类型分布 —— 哪一类检测器最需要调。
	FalsePositive []WAFStatItem `json:"falsePositive"`
}

// 各维度返回的条数上限。
//
// path / UA / area / rule 都是高基数字段（一条日志一个值），不加 LIMIT
// 会把整张表的分组结果全拉回来 —— 既是网络传输问题，也是内存问题。
// 统计界面只展示前 N 项，再多也没人看。
const (
	wafStatTopN      = 10
	wafStatRuleTopN  = 10
	wafStatSiteTopN  = 10
	wafStatAreaTopN  = 10
	wafStatFalsePosN = 10
)

// durationBuckets 是耗时分桶的上界（毫秒）与标签。
// 顺序即展示顺序 —— 不能靠 SQL 的字符串排序，否则 "<1" 会排在 ">=100" 后面。
var durationBuckets = []struct {
	Upper int
	Label string
}{
	{1, "<1ms"},
	{5, "1-5ms"},
	{20, "5-20ms"},
	{100, "20-100ms"},
	{-1, ">=100ms"}, // -1 表示无上界
}

// StatLogs 聚合统计。
//
// 全部维度都在 SQL 侧完成分组。历史教训：早先的趋势查询把时间范围内的
// 每一行 Select 进 Go 内存再按天计数，一个月的高流量站点能轻松到百万行，
// 直接把 agent 进程撑爆。这里每个维度都是 GROUP BY + LIMIT。
func (w WAFService) StatLogs(req request.WAFLogSearch) (*WAFStats, error) {
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

	stats := &WAFStats{}

	summary, err := statSummary(newBase())
	if err != nil {
		return nil, err
	}
	stats.Summary = summary

	// groupBy 是「GROUP BY 单列 + 取 Top N」的通用封装。
	// 每个维度都手写一遍 Select/Group/Order/Scan 会有 8 处几乎相同的代码，
	// 改动时容易漏掉某一处的 Limit。
	groupBy := func(col string, limit int, excludeEmpty bool) ([]WAFStatItem, error) {
		var items []WAFStatItem
		q := newBase().Select(col + " as key, count(*) as count")
		if excludeEmpty {
			// 空字符串分组会变成一个没有意义的条目（"未知"），
			// 在攻击类型这类维度上是噪音；但在 method 维度上空值本身
			// 就有意义（畸形请求），所以由调用方决定要不要排除。
			q = q.Where(col + " != ''")
		}
		q = q.Group(col).Order("count desc")
		if limit > 0 {
			q = q.Limit(limit)
		}
		if err := q.Scan(&items).Error; err != nil {
			return nil, err
		}
		return nonNilItems(items), nil
	}

	if stats.AttackType, err = groupBy("attack_type", wafStatTopN, true); err != nil {
		return nil, err
	}
	if stats.TopIP, err = groupBy("ip", wafStatTopN, true); err != nil {
		return nil, err
	}
	if stats.Layer, err = groupBy("layer", wafStatTopN, true); err != nil {
		return nil, err
	}
	if stats.Action, err = groupBy("action", 0, true); err != nil {
		return nil, err
	}
	if stats.Area, err = groupBy("area", wafStatAreaTopN, true); err != nil {
		return nil, err
	}
	// path 是 text 列，且查询串可能带随机值 —— 基数极高，必须 LIMIT。
	if stats.TopPath, err = groupBy("path", wafStatTopN, true); err != nil {
		return nil, err
	}
	if stats.TopUA, err = groupBy("user_agent", wafStatTopN, true); err != nil {
		return nil, err
	}
	// method 不排除空值：没有方法的请求本身是畸形流量，值得看见。
	if stats.Method, err = groupBy("method", 0, false); err != nil {
		return nil, err
	}
	if stats.TopRule, err = groupBy("rule_name", wafStatRuleTopN, true); err != nil {
		return nil, err
	}
	// 站点排行只在全局视角下有意义：单站查询时这一项恒为一条，
	// 前端可以据此隐藏该图。
	if stats.Website, err = groupBy("website_name", wafStatSiteTopN, true); err != nil {
		return nil, err
	}

	if stats.Trend, err = statLogsTrend(newBase(), req); err != nil {
		return nil, err
	}
	if stats.Duration, err = statDurationBuckets(newBase()); err != nil {
		return nil, err
	}
	if stats.FalsePositive, err = statFalsePositiveTypes(newBase(), wafStatFalsePosN); err != nil {
		return nil, err
	}

	return stats, nil
}

// nonNilItems 把 nil 切片换成空切片。
//
// 无数据时 JSON 会序列化成 null，前端的 stat.attackType.length 拿到
// undefined 直接抛错；每个维度都要保证是 []。
func nonNilItems(items []WAFStatItem) []WAFStatItem {
	if items == nil {
		return []WAFStatItem{}
	}
	return items
}

// statSummary 用一条查询算出全部汇总指标。
//
// 不用多次 count(*)：同一批过滤条件要跑 8 次，每次都要扫一遍索引。
// 条件聚合（SUM(CASE WHEN ...)）只扫一次。
func statSummary(base *gorm.DB) (WAFStatSummary, error) {
	var row struct {
		Total         int64
		Denied        int64
		Allowed       int64
		Challenged    int64
		Logged        int64
		UniqueIPs     int64
		FalsePositive int64
		AvgDuration   float64
		MaxDuration   float64
	}
	// COALESCE 的作用是让空集语义显式。
	//
	// 实测 SQLite 的驱动会把 SUM/AVG 的 NULL 静默转成 0，所以直接写
	// sum(...) 在空库上不会报错（这一点和某些 Go SQL 驱动的行为不同）。
	// 但依赖驱动的隐式转换不是好主意：换驱动或换存储时会变成
	// "converting NULL to int64 is unsupported" 的运行时错误，
	// 而统计接口在空库上跑是很常见的场景（新装、刚清空日志）。
	err := base.Select(`
		count(*) as total,
		coalesce(sum(case when action = 'deny' then 1 else 0 end), 0) as denied,
		coalesce(sum(case when action = 'allow' then 1 else 0 end), 0) as allowed,
		coalesce(sum(case when action = 'challenge' then 1 else 0 end), 0) as challenged,
		coalesce(sum(case when action = 'log' then 1 else 0 end), 0) as logged,
		count(distinct ip) as unique_ips,
		coalesce(sum(case when false_positive = ? then 1 else 0 end), 0) as false_positive,
		coalesce(avg(duration_ms), 0) as avg_duration,
		coalesce(max(duration_ms), 0) as max_duration`,
		true).
		Scan(&row).Error
	if err != nil {
		return WAFStatSummary{}, err
	}
	return WAFStatSummary{
		Total:         row.Total,
		Denied:        row.Denied,
		Allowed:       row.Allowed,
		Challenged:    row.Challenged,
		Logged:        row.Logged,
		UniqueIPs:     row.UniqueIPs,
		FalsePositive: row.FalsePositive,
		AvgDurationMs: row.AvgDuration,
		MaxDurationMs: row.MaxDuration,
	}, nil
}

// statDurationBuckets 处理耗时分布。
//
// 分桶在 SQL 侧用 CASE 完成，只回 5 行。桶的顺序在 Go 里按
// durationBuckets 的固定顺序补齐 —— SQL 只能按字符串排序，
// "<1ms" 会排到 ">=100ms" 后面。
func statDurationBuckets(base *gorm.DB) ([]WAFStatItem, error) {
	counts := make(map[int]int64, len(durationBuckets))

	var caseSQL string
	for i, b := range durationBuckets {
		if i > 0 {
			caseSQL += " "
		}
		if b.Upper < 0 {
			caseSQL += "else " + strconv.Itoa(i)
		} else {
			caseSQL += "when duration_ms < " + strconv.Itoa(b.Upper) + " then " + strconv.Itoa(i)
		}
	}
	var rows []struct {
		Bkt   int
		Count int64
	}
	err := base.Select("case " + caseSQL + " end as bkt, count(*) as count").
		Group("bkt").Scan(&rows).Error
	if err != nil {
		return nil, err
	}
	for _, r := range rows {
		counts[r.Bkt] = r.Count
	}

	out := make([]WAFStatItem, 0, len(durationBuckets))
	for i, b := range durationBuckets {
		out = append(out, WAFStatItem{Key: b.Label, Count: counts[i]})
	}
	return out, nil
}

// statFalsePositiveTypes 统计被标记为误报的攻击类型。
//
// 这个维度直接指向"哪一类检测器最需要调"：某个类型误报数明显高于其它，
// 要么规则太松，要么该类型不该对该站点开启。
func statFalsePositiveTypes(base *gorm.DB, limit int) ([]WAFStatItem, error) {
	var items []WAFStatItem
	err := base.
		Select("attack_type as key, count(*) as count").
		Where("false_positive = ?", true).
		Where("attack_type != ''").
		Group("attack_type").
		Order("count desc").
		Limit(limit).
		Scan(&items).Error
	if err != nil {
		return nil, err
	}
	return nonNilItems(items), nil
}
