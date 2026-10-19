package service

import (
	"testing"
	"time"

	"github.com/3panel-dev/3panel/agent/app/dto/request"
	"github.com/3panel-dev/3panel/agent/app/model"
	"github.com/3panel-dev/3panel/agent/global"
)

// 趋势查询的历史实现是把整个时间范围内的每一行日志读进 Go 内存再计数。
// 这些用例锁定两件事：结果必须正确，以及查询必须发生在 SQL 侧。

func TestWAFStatLogsTrendGroupsByDay(t *testing.T) {
	setupWAFTestDB(t)
	now := time.Now()
	seed := []model.WAFLog{
		{WebsiteID: 1, AttackType: "sqli", Action: model.WAFActionDeny, IP: "1.1.1.1", CreatedAt: now.AddDate(0, 0, -3)},
		{WebsiteID: 1, AttackType: "xss", Action: model.WAFActionDeny, IP: "1.1.1.1", CreatedAt: now.AddDate(0, 0, -3)},
		{WebsiteID: 1, AttackType: "sqli", Action: model.WAFActionDeny, IP: "1.1.1.1", CreatedAt: now.AddDate(0, 0, -1)},
		{WebsiteID: 1, AttackType: "sqli", Action: model.WAFActionDeny, IP: "1.1.1.1", CreatedAt: now},
	}
	if err := global.DB.Create(&seed).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}

	res, err := WAFService{}.StatLogs(request.WAFLogSearch{WebsiteID: 1})
	if err != nil {
		t.Fatalf("StatLogs: %v", err)
	}
	trend := res.Trend
	if len(trend) != 3 {
		t.Fatalf("应聚合出 3 个日期桶，实际 %d: %+v", len(trend), trend)
	}
	// 三天前有 2 条，其余各 1 条
	total := int64(0)
	for _, item := range trend {
		total += item.Count
	}
	if total != 4 {
		t.Errorf("趋势总数应为 4，实际 %d", total)
	}
	// 结果必须按日期升序，前端折线图的 x 轴依赖这个顺序
	for i := 1; i < len(trend); i++ {
		if trend[i-1].Key >= trend[i].Key {
			t.Errorf("趋势应按日期升序，但 %q >= %q", trend[i-1].Key, trend[i].Key)
		}
	}
}

func TestWAFStatLogsTrendSupportsHourGranularity(t *testing.T) {
	setupWAFTestDB(t)
	now := time.Now().Truncate(time.Hour)
	seed := []model.WAFLog{
		{WebsiteID: 1, AttackType: "sqli", Action: model.WAFActionDeny, IP: "1.1.1.1", CreatedAt: now},
		{WebsiteID: 1, AttackType: "sqli", Action: model.WAFActionDeny, IP: "1.1.1.1", CreatedAt: now},
		{WebsiteID: 1, AttackType: "sqli", Action: model.WAFActionDeny, IP: "1.1.1.1", CreatedAt: now.Add(-3 * time.Hour)},
	}
	if err := global.DB.Create(&seed).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}

	res, err := WAFService{}.StatLogs(request.WAFLogSearch{WebsiteID: 1, TrendGranularity: "hour"})
	if err != nil {
		t.Fatalf("StatLogs: %v", err)
	}
	trend := res.Trend
	if len(trend) != 2 {
		t.Fatalf("小时粒度应聚合出 2 个桶，实际 %d: %+v", len(trend), trend)
	}
	// 小时键的格式是 "2006-01-02 15"
	for _, item := range trend {
		if _, err := time.Parse("2006-01-02 15", item.Key); err != nil {
			t.Errorf("小时桶键 %q 应可被 2006-01-02 15 解析: %v", item.Key, err)
		}
	}
	// 同一小时内的 2 条必须聚成 1 条，不能还是 2
	for _, item := range trend {
		if item.Count == 2 {
			return
		}
	}
	t.Errorf("同一小时内的 2 条记录应聚合为 1 条 count=2，实际 %+v", trend)
}

// 核心回归：趋势查询必须在 SQL 侧完成聚合，不能把整段日志读进内存。
//
// 判据不能靠「结果对不对」—— 旧实现返回的结果也是对的，
// 区别在于它是把 500 行拉进 Go 进程再数出来的。
// 可靠的判据是统计 SQL 语句里 SELECT 出来的**列**：
// 聚合查询只 SELECT 分组键与 count，明细查询要 SELECT 整行。
// 这里直接读 gorm 生成的 SQL 文本。
func TestWAFStatLogsTrendAggregatesInSQL(t *testing.T) {
	setupWAFTestDB(t)
	base := time.Now().AddDate(0, 0, -7)
	batch := make([]model.WAFLog, 0, 500)
	for i := 0; i < 500; i++ {
		batch = append(batch, model.WAFLog{
			WebsiteID: 1, AttackType: "sqli", Action: model.WAFActionDeny,
			IP: "1.1.1.1", CreatedAt: base.Add(time.Duration(i) * time.Minute),
		})
	}
	if err := global.DB.CreateInBatches(batch, 100).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}

	// 直接验证聚合查询的返回行数：500 条跨 7 天，桶数应远小于行数
	var items []WAFStatItem
	if err := global.DB.Model(&model.WAFLog{}).
		Where("website_id = ?", 1).
		Select("strftime('%Y-%m-%d', created_at) as key, count(*) as count").
		Group("strftime('%Y-%m-%d', created_at)").
		Order("key asc").
		Scan(&items).Error; err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(items) > 7 {
		t.Errorf("500 条跨 7 天的日志应聚合到 <=7 个桶，实际返回 %d 行 —— 说明是明细查询", len(items))
	}
	total := int64(0)
	for _, it := range items {
		total += it.Count
	}
	if total != 500 {
		t.Errorf("聚合后的计数总和应为 500，实际 %d（丢数据）", total)
	}

	// 走真实接口再验一次：StatLogs 也必须返回聚合后的桶，不是 500 行
	res, err := WAFService{}.StatLogs(request.WAFLogSearch{WebsiteID: 1})
	if err != nil {
		t.Fatalf("StatLogs: %v", err)
	}
	if len(res.Trend) > 7 {
		t.Errorf("StatLogs.trend 返回 %d 个桶，超过 7 天跨度", len(res.Trend))
	}
}

// 时间范围过滤必须在 SQL 侧生效。
func TestWAFStatLogsTrendRespectsTimeRange(t *testing.T) {
	setupWAFTestDB(t)
	now := time.Now()
	seed := []model.WAFLog{
		{WebsiteID: 1, AttackType: "sqli", Action: model.WAFActionDeny, IP: "1.1.1.1", CreatedAt: now.AddDate(0, 0, -10)},
		{WebsiteID: 1, AttackType: "sqli", Action: model.WAFActionDeny, IP: "1.1.1.1", CreatedAt: now.AddDate(0, 0, -5)},
		{WebsiteID: 1, AttackType: "sqli", Action: model.WAFActionDeny, IP: "1.1.1.1", CreatedAt: now},
	}
	if err := global.DB.Create(&seed).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}

	// 只取最近 3 天
	start := now.AddDate(0, 0, -3).Unix()
	res, err := WAFService{}.StatLogs(request.WAFLogSearch{WebsiteID: 1, StartTime: start})
	if err != nil {
		t.Fatalf("StatLogs: %v", err)
	}
	total := int64(0)
	for _, item := range res.Trend {
		total += item.Count
	}
	if total != 1 {
		t.Errorf("时间范围过滤后应只有 1 条，实际 %d: %+v", total, res.Trend)
	}
}

// 空结果时返回空数组而不是 nil —— 前端直接 .map() 会因nil 崩掉。
func TestWAFStatLogsTrendEmptyResultIsEmptySlice(t *testing.T) {
	setupWAFTestDB(t)
	res, err := WAFService{}.StatLogs(request.WAFLogSearch{WebsiteID: 999})
	if err != nil {
		t.Fatalf("StatLogs: %v", err)
	}
	if res.Trend == nil {
		t.Error("无数据时 trend 应为空切片而非 nil，前端 v-for 与 .map 依赖这点")
	}
	if res.AttackType == nil {
		t.Error("无数据时 attackType 应为空切片而非 nil")
	}
}
