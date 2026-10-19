package service

import (
	"strconv"
	"testing"
	"time"

	"github.com/3panel-dev/3panel/agent/app/dto/request"
	"github.com/3panel-dev/3panel/agent/app/model"
	"github.com/3panel-dev/3panel/agent/global"
)

// seedStatLog 插入一条日志，字段由调用方按需覆盖。
func seedStatLog(t *testing.T, logs ...model.WAFLog) {
	t.Helper()
	if len(logs) == 0 {
		return
	}
	if err := global.DB.CreateInBatches(logs, 100).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}
}

// 空库：所有维度必须是空切片而不是 nil。
// nil 序列化成 null，前端 stat.attackType.length 会抛错。
func TestWAFStatsEmptyIsNotNil(t *testing.T) {
	setupWAFTestDB(t)
	stats, err := newIPGroupSvc().StatLogs(request.WAFLogSearch{})
	if err != nil {
		t.Fatalf("StatLogs: %v", err)
	}
	slices := map[string][]WAFStatItem{
		"attackType": stats.AttackType, "topIP": stats.TopIP, "trend": stats.Trend,
		"layer": stats.Layer, "action": stats.Action, "area": stats.Area,
		"topPath": stats.TopPath, "topUA": stats.TopUA, "method": stats.Method,
		"topRule": stats.TopRule, "website": stats.Website,
		"duration": stats.Duration, "falsePositive": stats.FalsePositive,
	}
	for name, s := range slices {
		if s == nil {
			t.Errorf("%s 无数据时应为 []，实际是 nil（前端会拿到 null）", name)
		}
	}
	// 汇总指标同理
	if stats.Summary.Total != 0 || stats.Summary.AvgDurationMs != 0 {
		t.Errorf("空库汇总应全 0，实际 %+v", stats.Summary)
	}
	if stats.Summary.AvgDurationMs != stats.Summary.AvgDurationMs { // NaN 自比较为假
		t.Error("平均耗时不应为 NaN（前端会显示成 NaN）")
	}
}

// 汇总指标：一次分流算清各动作数量、独立 IP、误报数、耗时。
func TestWAFStatsSummary(t *testing.T) {
	setupWAFTestDB(t)
	now := time.Now()
	seedStatLog(t,
		model.WAFLog{WebsiteID: 1, Action: "deny", IP: "1.1.1.1", AttackType: "sqli", DurationMs: 2, CreatedAt: now},
		model.WAFLog{WebsiteID: 1, Action: "deny", IP: "1.1.1.1", AttackType: "sqli", DurationMs: 4, CreatedAt: now},
		model.WAFLog{WebsiteID: 1, Action: "allow", IP: "2.2.2.2", AttackType: "", DurationMs: 6, CreatedAt: now},
		model.WAFLog{WebsiteID: 1, Action: "log", IP: "3.3.3.3", AttackType: "xss", DurationMs: 8, FalsePositive: true, CreatedAt: now},
		model.WAFLog{WebsiteID: 1, Action: "challenge", IP: "4.4.4.4", AttackType: "cc", DurationMs: 10, CreatedAt: now},
	)

	stats, err := newIPGroupSvc().StatLogs(request.WAFLogSearch{})
	if err != nil {
		t.Fatalf("StatLogs: %v", err)
	}
	s := stats.Summary
	if s.Total != 5 {
		t.Errorf("total 应为 5，实际 %d", s.Total)
	}
	if s.Denied != 2 || s.Allowed != 1 || s.Logged != 1 || s.Challenged != 1 {
		t.Errorf("动作分流不对：%+v", s)
	}
	// 独立 IP 不是行数：1.1.1.1 出现两次只算一个
	if s.UniqueIPs != 4 {
		t.Errorf("独立 IP 应为 4，实际 %d", s.UniqueIPs)
	}
	if s.FalsePositive != 1 {
		t.Errorf("误报数应为 1，实际 %d", s.FalsePositive)
	}
	// (2+4+6+8+10)/5 = 6
	if s.AvgDurationMs != 6 {
		t.Errorf("平均耗时应为 6，实际 %v", s.AvgDurationMs)
	}
	if s.MaxDurationMs != 10 {
		t.Errorf("最大耗时应为 10，实际 %v", s.MaxDurationMs)
	}
}

// 各维度分组正确，且按计数降序。
func TestWAFStatsDimensions(t *testing.T) {
	setupWAFTestDB(t)
	now := time.Now()
	seedStatLog(t,
		model.WAFLog{WebsiteID: 1, WebsiteName: "a.com", Action: "deny", IP: "1.1.1.1",
			AttackType: "sqli", Layer: "rules", Area: "中国", Method: "GET", Path: "/login",
			UserAgent: "sqlmap", RuleName: "r1", DurationMs: 1, CreatedAt: now},
		model.WAFLog{WebsiteID: 1, WebsiteName: "a.com", Action: "deny", IP: "1.1.1.1",
			AttackType: "sqli", Layer: "rules", Area: "中国", Method: "GET", Path: "/login",
			UserAgent: "sqlmap", RuleName: "r1", DurationMs: 1, CreatedAt: now},
		model.WAFLog{WebsiteID: 1, WebsiteName: "a.com", Action: "deny", IP: "2.2.2.2",
			AttackType: "xss", Layer: "semantic", Area: "美国", Method: "POST", Path: "/api",
			UserAgent: "curl", RuleName: "r2", DurationMs: 50, CreatedAt: now},
	)

	stats, err := newIPGroupSvc().StatLogs(request.WAFLogSearch{})
	if err != nil {
		t.Fatalf("StatLogs: %v", err)
	}

	expectTop := func(name string, items []WAFStatItem, wantKey string, wantCount int64) {
		t.Helper()
		if len(items) == 0 {
			t.Errorf("%s 不应为空", name)
			return
		}
		if items[0].Key != wantKey || items[0].Count != wantCount {
			t.Errorf("%s 首项应为 %s=%d，实际 %s=%d", name, wantKey, wantCount, items[0].Key, items[0].Count)
		}
	}
	expectTop("attackType", stats.AttackType, "sqli", 2)
	expectTop("topIP", stats.TopIP, "1.1.1.1", 2)
	expectTop("layer", stats.Layer, "rules", 2)
	expectTop("area", stats.Area, "中国", 2)
	expectTop("topPath", stats.TopPath, "/login", 2)
	expectTop("topUA", stats.TopUA, "sqlmap", 2)
	expectTop("topRule", stats.TopRule, "r1", 2)
	expectTop("website", stats.Website, "a.com", 3)
	expectTop("action", stats.Action, "deny", 3)
}

// 耗时分桶必须按固定顺序返回，而不是按字符串排序。
// SQL 只能按 key 排序，"<1ms" 会排到 ">=100ms" 之后。
func TestWAFStatsDurationBucketOrder(t *testing.T) {
	setupWAFTestDB(t)
	now := time.Now()
	seedStatLog(t,
		model.WAFLog{WebsiteID: 1, Action: "deny", IP: "1.1.1.1", DurationMs: 0.5, CreatedAt: now},
		model.WAFLog{WebsiteID: 1, Action: "deny", IP: "1.1.1.1", DurationMs: 3, CreatedAt: now},
		model.WAFLog{WebsiteID: 1, Action: "deny", IP: "1.1.1.1", DurationMs: 10, CreatedAt: now},
		model.WAFLog{WebsiteID: 1, Action: "deny", IP: "1.1.1.1", DurationMs: 50, CreatedAt: now},
		model.WAFLog{WebsiteID: 1, Action: "deny", IP: "1.1.1.1", DurationMs: 500, CreatedAt: now},
	)

	stats, err := newIPGroupSvc().StatLogs(request.WAFLogSearch{})
	if err != nil {
		t.Fatalf("StatLogs: %v", err)
	}
	wantLabels := []string{"<1ms", "1-5ms", "5-20ms", "20-100ms", ">=100ms"}
	if len(stats.Duration) != len(wantLabels) {
		t.Fatalf("应有 %d 个分桶，实际 %d", len(wantLabels), len(stats.Duration))
	}
	for i, want := range wantLabels {
		if stats.Duration[i].Key != want {
			t.Errorf("第 %d 个分桶应为 %q，实际 %q（顺序不能靠字符串排序）", i, want, stats.Duration[i].Key)
		}
		// 每条日志落在不同桶，各 1 条
		if stats.Duration[i].Count != 1 {
			t.Errorf("分桶 %q 计数应为 1，实际 %d", want, stats.Duration[i].Count)
		}
	}
}

// 高基数维度必须 LIMIT，否则会把整表分组结果拉回来。
func TestWAFStatsTopNIsLimited(t *testing.T) {
	setupWAFTestDB(t)
	now := time.Now()
	// 造 30 个不同的 path / UA，超过 TopN=10
	batch := make([]model.WAFLog, 0, 30)
	for i := 0; i < 30; i++ {
		batch = append(batch, model.WAFLog{
			WebsiteID: 1, Action: "deny", IP: "1.1.1.1",
			Path:      "/p" + strconv.Itoa(i),
			UserAgent: "ua" + strconv.Itoa(i),
			Area:      "area" + strconv.Itoa(i),
			RuleName:  "rule" + strconv.Itoa(i),
			CreatedAt: now,
		})
	}
	seedStatLog(t, batch...)

	stats, err := newIPGroupSvc().StatLogs(request.WAFLogSearch{})
	if err != nil {
		t.Fatalf("StatLogs: %v", err)
	}
	for name, items := range map[string][]WAFStatItem{
		"topPath": stats.TopPath, "topUA": stats.TopUA,
		"area": stats.Area, "topRule": stats.TopRule,
	} {
		if len(items) > wafStatTopN {
			t.Errorf("%s 应被 LIMIT 到 %d 条，实际 %d 条（高基数字段不限会拉爆内存）",
				name, wafStatTopN, len(items))
		}
	}
}

// action / method 是低基数维度，不该被截断 —— 截掉一个动作就等于
// 汇总数字对不上分布图。
func TestWAFStatsLowCardinalityNotTruncated(t *testing.T) {
	setupWAFTestDB(t)
	now := time.Now()
	actions := []string{"deny", "allow", "log", "challenge"}
	batch := make([]model.WAFLog, 0, len(actions))
	for _, a := range actions {
		batch = append(batch, model.WAFLog{
			WebsiteID: 1, Action: a, IP: "1.1.1.1", Method: a + "M", CreatedAt: now,
		})
	}
	seedStatLog(t, batch...)

	stats, err := newIPGroupSvc().StatLogs(request.WAFLogSearch{})
	if err != nil {
		t.Fatalf("StatLogs: %v", err)
	}
	if len(stats.Action) != len(actions) {
		t.Errorf("action 应返回全部 %d 种，实际 %d 种", len(actions), len(stats.Action))
	}
	// method 不排除空值：空方法本身是畸形流量，要能看见
	if len(stats.Method) != len(actions) {
		t.Errorf("method 应返回全部 %d 种，实际 %d 种", len(actions), len(stats.Method))
	}
}

// 误报维度只统计被标记的，并按攻击类型分组 —— 直接指向哪类检测器要调。
func TestWAFStatsFalsePositiveByType(t *testing.T) {
	setupWAFTestDB(t)
	now := time.Now()
	seedStatLog(t,
		model.WAFLog{WebsiteID: 1, Action: "deny", IP: "1.1.1.1", AttackType: "sqli", FalsePositive: true, CreatedAt: now},
		model.WAFLog{WebsiteID: 1, Action: "deny", IP: "1.1.1.1", AttackType: "sqli", FalsePositive: true, CreatedAt: now},
		model.WAFLog{WebsiteID: 1, Action: "deny", IP: "1.1.1.1", AttackType: "xss", FalsePositive: true, CreatedAt: now},
		// 未标记误报的不该计入
		model.WAFLog{WebsiteID: 1, Action: "deny", IP: "1.1.1.1", AttackType: "rce", FalsePositive: false, CreatedAt: now},
	)

	stats, err := newIPGroupSvc().StatLogs(request.WAFLogSearch{})
	if err != nil {
		t.Fatalf("StatLogs: %v", err)
	}
	if len(stats.FalsePositive) != 2 {
		t.Fatalf("应只有 sqli 与 xss 两类误报，实际 %d 类: %+v",
			len(stats.FalsePositive), stats.FalsePositive)
	}
	if stats.FalsePositive[0].Key != "sqli" || stats.FalsePositive[0].Count != 2 {
		t.Errorf("误报首项应为 sqli=2，实际 %+v", stats.FalsePositive[0])
	}
}

// 时间范围过滤要在每个维度都生效，不能只作用于某几个。
func TestWAFStatsTimeFilterApplies(t *testing.T) {
	setupWAFTestDB(t)
	old := time.Now().AddDate(0, 0, -10)
	recent := time.Now()
	seedStatLog(t,
		model.WAFLog{WebsiteID: 1, Action: "deny", IP: "1.1.1.1", AttackType: "old", Layer: "rules", CreatedAt: old},
		model.WAFLog{WebsiteID: 1, Action: "deny", IP: "2.2.2.2", AttackType: "new", Layer: "semantic", CreatedAt: recent},
	)

	start := time.Now().AddDate(0, 0, -1).Unix()
	stats, err := newIPGroupSvc().StatLogs(request.WAFLogSearch{StartTime: start})
	if err != nil {
		t.Fatalf("StatLogs: %v", err)
	}
	if stats.Summary.Total != 1 {
		t.Errorf("时间过滤后 total 应为 1，实际 %d", stats.Summary.Total)
	}
	if len(stats.AttackType) != 1 || stats.AttackType[0].Key != "new" {
		t.Errorf("attackType 应只剩 new，实际 %+v", stats.AttackType)
	}
	if len(stats.Layer) != 1 || stats.Layer[0].Key != "semantic" {
		t.Errorf("layer 维度也必须受时间过滤，实际 %+v", stats.Layer)
	}
}

// 站点过滤：单站查询时不该看到别的站点数据。
func TestWAFStatsWebsiteFilter(t *testing.T) {
	setupWAFTestDB(t)
	now := time.Now()
	seedStatLog(t,
		model.WAFLog{WebsiteID: 1, WebsiteName: "a.com", Action: "deny", IP: "1.1.1.1", CreatedAt: now},
		model.WAFLog{WebsiteID: 2, WebsiteName: "b.com", Action: "deny", IP: "2.2.2.2", CreatedAt: now},
	)

	stats, err := newIPGroupSvc().StatLogs(request.WAFLogSearch{WebsiteID: 1})
	if err != nil {
		t.Fatalf("StatLogs: %v", err)
	}
	if stats.Summary.Total != 1 {
		t.Errorf("单站查询 total 应为 1，实际 %d", stats.Summary.Total)
	}
	if len(stats.Website) != 1 || stats.Website[0].Key != "a.com" {
		t.Errorf("站点排行应只含本站，实际 %+v", stats.Website)
	}
}
