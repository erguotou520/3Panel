package service

import (
	"testing"

	"github.com/3panel-dev/3panel/agent/app/dto/request"
	"github.com/3panel-dev/3panel/agent/app/model"
	"github.com/3panel-dev/3panel/agent/global"
	"github.com/3panel-dev/3panel/agent/utils/waf"
)

func newIPGroupSvc() WAFService {
	return WAFService{syncRulesFn: func() error { return nil }}
}

// parseCIDROrIP 的归一化行为。裸 IP 必须补成 /32 或 /128 ——
// 否则 Lua 侧的 in_cidr 与导出格式要处理两种形态。
func TestParseCIDROrIP(t *testing.T) {
	cases := []struct{ in, want string }{
		{"1.2.3.4", "1.2.3.4/32"},
		{"10.0.0.0/8", "10.0.0.0/8"},
		{"::1", "::1/128"},
		{"2001:db8::/32", "2001:db8::/32"},
		// IPv4-mapped IPv6：用户从 IPv4 网站复制地址时经常带这层包装，
		// 不 Unmap 就与 rules.json 里的 IPv4 CIDR 对不上
		{"::ffff:1.2.3.4", "1.2.3.4/32"},
	}
	for _, c := range cases {
		got, err := parseCIDROrIP(c.in)
		if err != nil {
			t.Errorf("%q 应解析成功，实际 %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("%q 应归一化为 %q，实际 %q", c.in, c.want, got)
		}
	}
}

func TestParseCIDROrIPRejectsInvalid(t *testing.T) {
	for _, in := range []string{"", "1.2.3", "1.2.3.4.5", "abc", "1.2.3.4/33", "10.0.0.0/-1"} {
		if _, err := parseCIDROrIP(in); err == nil {
			t.Errorf("%q 应被拒绝", in)
		}
	}
	// 主机位非零的前缀必须拒：1.2.3.4/24 语义上等于 1.2.3.0/24，
	// 放过去会让用户以为两条规则不同，实际匹配范围完全一样。
	if _, err := parseCIDROrIP("1.2.3.4/24"); err == nil {
		t.Error("主机位非零的前缀应被拒绝")
	}
}

// 用户粘贴的文本：换行、逗号、分号、空格都要能分隔。
// 云厂商控制台复制出来的是逗号分隔，从文件贴的是换行分隔。
func TestParseIPGroupCIDRsAcceptsSeparators(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want []string
	}{
		{"换行", "1.1.1.1\n2.2.2.2", []string{"1.1.1.1/32", "2.2.2.2/32"}},
		{"逗号", "1.1.1.1,2.2.2.2", []string{"1.1.1.1/32", "2.2.2.2/32"}},
		{"分号", "1.1.1.1;2.2.2.2", []string{"1.1.1.1/32", "2.2.2.2/32"}},
		{"空格", "1.1.1.1 2.2.2.2", []string{"1.1.1.1/32", "2.2.2.2/32"}},
		{"混合", "1.1.1.1, 2.2.2.2\n3.3.3.3", []string{"1.1.1.1/32", "2.2.2.2/32", "3.3.3.3/32"}},
		{"CRLF", "1.1.1.1\r\n2.2.2.2", []string{"1.1.1.1/32", "2.2.2.2/32"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := parseIPGroupCIDRs(c.raw)
			if err != nil {
				t.Fatalf("解析失败: %v", err)
			}
			if len(got) != len(c.want) {
				t.Fatalf("期望 %d 条，实际 %d: %v", len(c.want), len(got), got)
			}
			for i := range got {
				if got[i] != c.want[i] {
					t.Errorf("第 %d 条应为 %q，实际 %q", i, c.want[i], got[i])
				}
			}
		})
	}
}

func TestParseIPGroupCIDRsDedupes(t *testing.T) {
	got, err := parseIPGroupCIDRs("1.1.1.1, 1.1.1.1\n1.1.1.1/32")
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	// 1.1.1.1 与 1.1.1.1/32 归一化后是同一个，应只剩一条
	if len(got) != 1 || got[0] != "1.1.1.1/32" {
		t.Errorf("去重后应只剩一条 1.1.1.1/32，实际 %v", got)
	}
}

// 非法条目必须报错而不是跳过。组里写错了却静默丢弃，
// 用户会以为已生效，实际防护范围比预期小 —— 在安全配置里
// 这比直接报错危险得多。
func TestParseIPGroupCIDRsRejectsInvalidEntry(t *testing.T) {
	if _, err := parseIPGroupCIDRs("1.1.1.1\nnot-an-ip"); err == nil {
		t.Error("含非法条目时应报错，而不是静默跳过")
	}
	// 空行、纯空白不算非法
	if _, err := parseIPGroupCIDRs("\n\n1.1.1.1\n\n\n"); err != nil {
		t.Errorf("空行不应算非法: %v", err)
	}
}

func TestCreateIPGroup(t *testing.T) {
	setupWAFTestDB(t)
	svc := newIPGroupSvc()

	err := svc.CreateIPGroup(request.WAFIPGroupCreate{
		Name:   "office",
		Scope:  model.WAFScopeGlobal,
		Remark: "公司出口",
		CIDRs:  "10.0.0.0/8\n192.168.1.1",
		// gorm 的 default:true 会把零值也写成 true，这里显式给 true
	})
	// Enabled 是 bool 零值 false：先确认默认行为是否符合预期
	if err != nil {
		t.Fatalf("创建失败: %v", err)
	}

	var g model.WAFIPGroup
	if err := global.DB.Where("name = ?", "office").First(&g).Error; err != nil {
		t.Fatalf("读取失败: %v", err)
	}
	if g.Scope != model.WAFScopeGlobal {
		t.Errorf("scope 应为 global，实际 %q", g.Scope)
	}
	if g.CIDRs != "10.0.0.0/8\n192.168.1.1/32" {
		t.Errorf("CIDRs 应已归一化并用换行存储，实际 %q", g.CIDRs)
	}
}

// 空组必须被拒：一个空组配出来的规则永远不命中，
// 但界面上看着"配好了"。
func TestCreateIPGroupRejectsEmpty(t *testing.T) {
	setupWAFTestDB(t)
	svc := newIPGroupSvc()
	if err := svc.CreateIPGroup(request.WAFIPGroupCreate{
		Name: "empty", Scope: model.WAFScopeGlobal, CIDRs: "\n\n  \n",
	}); err == nil {
		t.Error("空组应被拒绝")
	}
}

// 组名白名单：组名会原样成为 rules.json 里的 map key，
// 用户在规则里填错一个字符就是「组不存在」且没有任何报错。
//
// 校验放在 service 而不是 DTO tag —— service 才是真正写入的地方，
// 这里的校验对所有调用方生效，不依赖调用链上恰好跑过 validator。
func TestIPGroupNameValidation(t *testing.T) {
	for _, name := range []string{"", "a b", "a,b", "组名", "a/b", "a'b", "a.b"} {
		if err := validateIPGroupName(name); err == nil {
			t.Errorf("非法组名 %q 应被拒绝", name)
		}
	}
	for _, name := range []string{"office", "office_v2", "office-v2", "Abc123"} {
		if err := validateIPGroupName(name); err != nil {
			t.Errorf("合法组名 %q 应通过校验，实际 %v", name, err)
		}
	}
	// 超长也要拒
	long := ""
	for i := 0; i < 65; i++ {
		long += "a"
	}
	if err := validateIPGroupName(long); err == nil {
		t.Error("超过 64 字符的组名应被拒绝")
	}
}

// 组名非法时 CreateIPGroup 必须拒绝 —— 不能只靠前端下拉约束。
func TestCreateIPGroupRejectsBadName(t *testing.T) {
	setupWAFTestDB(t)
	svc := newIPGroupSvc()
	if err := svc.CreateIPGroup(request.WAFIPGroupCreate{
		Name: "bad name", Scope: model.WAFScopeGlobal, CIDRs: "1.1.1.1",
	}); err == nil {
		t.Error("含空格的组名应被 service 层拒绝")
	}
	var n int64
	global.DB.Model(&model.WAFIPGroup{}).Count(&n)
	if n != 0 {
		t.Errorf("校验失败时不应落库，实际 %d 条", n)
	}
}

// ListIPGroups 必须返回「本站 + 全局」，与 ListRules 的语义一致。
func TestListIPGroupsIncludesGlobal(t *testing.T) {
	setupWAFTestDB(t)
	svc := newIPGroupSvc()

	mustCreate := func(name, scope string, websiteID uint) {
		t.Helper()
		if err := svc.CreateIPGroup(request.WAFIPGroupCreate{
			Name: name, Scope: scope, WebsiteID: websiteID, CIDRs: "1.1.1.1", Enabled: true,
		}); err != nil {
			t.Fatalf("创建 %s 失败: %v", name, err)
		}
	}
	mustCreate("g_group", model.WAFScopeGlobal, 0)
	mustCreate("s1_group", model.WAFScopeSite, 1)
	mustCreate("s2_group", model.WAFScopeSite, 2)

	groups, err := svc.ListIPGroups(1)
	if err != nil {
		t.Fatalf("列举失败: %v", err)
	}
	names := map[string]bool{}
	for _, g := range groups {
		names[g.Name] = true
	}
	if !names["g_group"] {
		t.Error("站点 1 应看得到全局组")
	}
	if !names["s1_group"] {
		t.Error("站点 1 应看得到自己的组")
	}
	if names["s2_group"] {
		t.Error("站点 1 不应看得到站点 2 的组")
	}
}

// 导出：禁用组与空组都不该出现在 rules.json 里。
// 禁用组若还导出，Lua 查到就会命中，「关闭」就成了摆设。
func TestIPGroupsExported(t *testing.T) {
	dir := t.TempDir()
	groups := []model.WAFIPGroup{
		{Name: "office", Scope: model.WAFScopeGlobal, Enabled: true, CIDRs: "10.0.0.0/8\n192.168.1.1/32"},
		{Name: "disabled", Scope: model.WAFScopeGlobal, Enabled: false, CIDRs: "1.2.3.4/32"},
		{Name: "blank", Scope: model.WAFScopeGlobal, Enabled: true, CIDRs: "  \n\n "},
		{Name: "site1", Scope: model.WAFScopeSite, WebsiteID: 1, Enabled: true, CIDRs: "172.16.0.0/12"},
	}
	if err := waf.ExportRules(nil, nil, nil, map[uint]bool{1: true}, dir, false, groups); err != nil {
		t.Fatalf("导出失败: %v", err)
	}
	doc := readRulesJSON(t, dir)

	globalGroups, _ := doc["global"].(map[string]any)["ip_groups"].(map[string]any)
	if globalGroups == nil {
		t.Fatalf("global.ip_groups 缺失：%v", doc)
	}
	if _, ok := globalGroups["office"]; !ok {
		t.Error("启用的全局组应导出")
	}
	if _, ok := globalGroups["disabled"]; ok {
		t.Error("禁用的组不应导出（会让「关闭」变成摆设）")
	}
	if _, ok := globalGroups["blank"]; ok {
		t.Error("内容为空的组不应导出（配出来也永远不命中）")
	}

	site, _ := doc["sites"].(map[string]any)["1"].(map[string]any)
	siteGroups, _ := site["ip_groups"].(map[string]any)
	if siteGroups == nil {
		t.Fatalf("site.ip_groups 缺失：%v", site)
	}
	if _, ok := siteGroups["site1"]; !ok {
		t.Error("本站的组应导出到站点下")
	}
}

// 字段名契约：导出的 JSON 键必须与 Lua 侧读取的一致。
// 踩过一次 —— 一边驼峰一边下划线，编译与测试全绿但数据面读不到。
func TestIPGroupFieldNamesMatchLua(t *testing.T) {
	const luaGlobalKey = "ip_groups"
	const luaSiteKey = "ip_groups"

	dir := t.TempDir()
	groups := []model.WAFIPGroup{
		{Name: "office", Scope: model.WAFScopeGlobal, Enabled: true, CIDRs: "10.0.0.0/8"},
		{Name: "site1", Scope: model.WAFScopeSite, WebsiteID: 1, Enabled: true, CIDRs: "10.0.0.0/8"},
	}
	if err := waf.ExportRules(nil, nil, nil, map[uint]bool{1: true}, dir, false, groups); err != nil {
		t.Fatalf("导出失败: %v", err)
	}
	doc := readRulesJSON(t, dir)

	g, _ := doc["global"].(map[string]any)
	if _, ok := g[luaGlobalKey]; !ok {
		t.Errorf("global 下应存在 %q，实际键 %v", luaGlobalKey, keysOf(g))
	}
	site, _ := doc["sites"].(map[string]any)["1"].(map[string]any)
	if _, ok := site[luaSiteKey]; !ok {
		t.Errorf("站点下应存在 %q，实际键 %v", luaSiteKey, keysOf(site))
	}
}
