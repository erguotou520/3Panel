package waf

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/3panel-dev/3panel/agent/app/model"
)

func mustPrefix(t *testing.T, s string) netip.Prefix {
	t.Helper()
	p, err := netip.ParsePrefix(s)
	if err != nil {
		t.Fatalf("parse %q: %v", s, err)
	}
	return p
}

func prefixes(t *testing.T, ss ...string) []netip.Prefix {
	t.Helper()
	out := make([]netip.Prefix, 0, len(ss))
	for _, s := range ss {
		out = append(out, mustPrefix(t, s))
	}
	return out
}

// 两条兄弟前缀必须合成父前缀。
// 这是压缩率的来源：一个国家列表里大量网段是同一段地址被切碎而成。
func TestMergePrefixesSiblings(t *testing.T) {
	got := mergePrefixes(prefixes(t, "10.0.0.0/25", "10.0.0.128/25"))
	if len(got) != 1 || got[0].String() != "10.0.0.0/24" {
		t.Errorf("两条 /25 应合成 /24，实际 %v", got)
	}
}

// 四个 /26 逐级合成 /24。
func TestMergePrefixesCascade(t *testing.T) {
	got := mergePrefixes(prefixes(t,
		"10.0.0.0/26", "10.0.0.64/26", "10.0.0.128/26", "10.0.0.192/26"))
	if len(got) != 1 || got[0].String() != "10.0.0.0/24" {
		t.Errorf("四个 /26 应级联合成 /24，实际 %v", got)
	}
}

// 顺序打乱也要能合 —— mergePrefixes 内部会排序。
func TestMergePrefixesUnorderedInput(t *testing.T) {
	got := mergePrefixes(prefixes(t, "10.0.0.128/25", "10.0.0.0/25"))
	if len(got) != 1 || got[0].String() != "10.0.0.0/24" {
		t.Errorf("乱序输入也应合成 /24，实际 %v", got)
	}
}

// 🔴 非兄弟不能合。强行合会扩大匹配范围 ——
// 多拦一个不该拦的 IP，比多存几字节严重得多。
func TestMergePrefixesNonSiblings(t *testing.T) {
	// 同位数但不同父
	got := mergePrefixes(prefixes(t, "10.0.0.0/25", "10.0.1.0/25"))
	if len(got) != 2 {
		t.Errorf("不同父的 /25 不应合并，实际 %v", got)
	}
	// 位数不同且互为包含
	got = mergePrefixes(prefixes(t, "10.0.0.0/24", "10.0.0.0/25"))
	if len(got) != 2 {
		t.Errorf("包含关系的不同位数不应合并，实际 %v", got)
	}
	// 地址相邻但位数不同
	got = mergePrefixes(prefixes(t, "10.0.0.0/25", "10.0.0.128/26"))
	if len(got) != 2 {
		t.Errorf("位数不同的相邻前缀不应合并，实际 %v", got)
	}
}

// 完全重复的前缀要去重。
func TestMergePrefixesDedupe(t *testing.T) {
	got := mergePrefixes(prefixes(t, "10.0.0.0/24", "10.0.0.0/24"))
	if len(got) != 1 {
		t.Errorf("重复前缀应去重，实际 %v", got)
	}
}

// IPv4 与 IPv6 不能互相合并。
func TestMergePrefixesMixedFamily(t *testing.T) {
	got := mergePrefixes(prefixes(t, "10.0.0.0/25", "::/25"))
	if len(got) != 2 {
		t.Errorf("v4 与 v6 不应合并，实际 %v", got)
	}
}

// 单条与空输入原样返回。
func TestMergePrefixesTrivial(t *testing.T) {
	if got := mergePrefixes(nil); len(got) != 0 {
		t.Errorf("空输入应返回空，实际 %v", got)
	}
	one := prefixes(t, "10.0.0.0/24")
	if got := mergePrefixes(one); len(got) != 1 || got[0] != one[0] {
		t.Errorf("单条应原样返回，实际 %v", got)
	}
}

// /0 不能再往上合（位数为 0 时没有"更宽的父"）。
func TestMergePrefixesTopLevel(t *testing.T) {
	got := mergePrefixes(prefixes(t, "0.0.0.0/0"))
	if len(got) != 1 || got[0].String() != "0.0.0.0/0" {
		t.Errorf("/0 应原样保留，实际 %v", got)
	}
}

// prefixFromIPNet 必须把 IPv4 正确识别为 IPv4。
// net.IPNet 的 IP 常是 16 字节形式的 IPv4，直接 AddrFromSlice
// 会得到 ::ffff:1.2.3.4，与数据面的 IPv4 CIDR 对不上。
func TestPrefixFromIPNetIPv4As16Bytes(t *testing.T) {
	_, ipnet, err := net.ParseCIDR("1.2.3.0/24")
	if err != nil {
		t.Fatalf("ParseCIDR: %v", err)
	}
	// 转成 16 字节形态，模拟 mmdb 的返回
	ipnet.IP = ipnet.IP.To16()
	p, ok := prefixFromIPNet(ipnet)
	if !ok {
		t.Fatal("应转换成功")
	}
	if p.Addr().Is6() && !p.Addr().Is4In6() {
		t.Errorf("IPv4 被误判成纯 IPv6: %v", p)
	}
	if got := p.String(); got != "1.2.3.0/24" {
		t.Errorf("应为 1.2.3.0/24，实际 %q", got)
	}
}

func TestPrefixFromIPNetIPv6(t *testing.T) {
	_, ipnet, err := net.ParseCIDR("2001:db8::/32")
	if err != nil {
		t.Fatalf("ParseCIDR: %v", err)
	}
	p, ok := prefixFromIPNet(ipnet)
	if !ok {
		t.Fatal("应转换成功")
	}
	if got := p.String(); got != "2001:db8::/32" {
		t.Errorf("应为 2001:db8::/32，实际 %q", got)
	}
}

func TestPrefixFromIPNetNil(t *testing.T) {
	if _, ok := prefixFromIPNet(nil); ok {
		t.Error("nil 应返回 false")
	}
}

// 只收 geo 类型的规则，且国家码要规范化（大写、去重、去空白）。
func TestCollectGeoCodes(t *testing.T) {
	rules := []model.WAFRule{
		{MatchType: "geo", MatchValue: "CN", Enabled: true},
		{MatchType: "geo", MatchValue: "us", Enabled: true},   // 小写进来，大写出去
		{MatchType: "geo", MatchValue: " CN ", Enabled: true}, // 空白去掉后与第一条重复
		{MatchType: "geo", MatchValue: "JP,KR", Enabled: true},
		{MatchType: "ip", MatchValue: "1.2.3.4", Enabled: true},  // 非 geo 忽略
		{MatchType: "geo", MatchValue: "DE", Enabled: false},     // 禁用忽略
		{MatchType: "geo", MatchValue: "TOOLONG", Enabled: true}, // 非 2 位忽略
		{MatchType: "geo", MatchValue: "", Enabled: true},        // 空忽略
	}
	got := collectGeoCodes(rules)
	want := []string{"CN", "JP", "KR", "US"}
	if len(got) != len(want) {
		t.Fatalf("应收集 %v，实际 %v", want, got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("第 %d 项应为 %q，实际 %q", i, want[i], got[i])
		}
	}
}

func TestCollectGeoCodesEmpty(t *testing.T) {
	if got := collectGeoCodes(nil); len(got) != 0 {
		t.Errorf("无规则时应返回空，实际 %v", got)
	}
	// 有 geo 规则但全被禁用
	if got := collectGeoCodes([]model.WAFRule{
		{MatchType: "geo", MatchValue: "CN", Enabled: false},
	}); len(got) != 0 {
		t.Errorf("全禁用的 geo 规则不该收集国家码，实际 %v", got)
	}
}

// mmdb 不存在时必须返回 (nil, nil) 而不是报错。
// 报错会让整个规则导出失败 —— 地理数据缺失不该影响其它规则的同步。
func TestResolveCountryCIDRsMissingMMDB(t *testing.T) {
	got, err := ResolveCountryCIDRs("/nonexistent/path/GeoIP.mmdb", []string{"CN"}, true)
	if err != nil {
		t.Fatalf("mmdb 缺失不应报错，实际 %v", err)
	}
	if got != nil {
		t.Errorf("mmdb 缺失时应返回 nil（调用方据此标记不可用），实际 %v", got)
	}
}

// 空国家码列表：不打开文件，直接返回空 map。
func TestResolveCountryCIDRsNoCodes(t *testing.T) {
	got, err := ResolveCountryCIDRs("/nonexistent/path/GeoIP.mmdb", nil, true)
	if err != nil {
		t.Fatalf("不应报错: %v", err)
	}
	if got == nil || len(got) != 0 {
		t.Errorf("无国家码时应返回空 map，实际 %v", got)
	}
}

// 国家码在 mmdb 里有三个可能位置。面板资源包实际下发的 GeoLite2-City
// 变体用的是**顶层 iso**（{country:{en,zh}, iso:"CN", ...}），
// 只认 country.iso_code 时整库都读成空串 —— 文件能打开、网段能遍历，
// 但所有国家的 CIDR 列表都是 []，geo 规则静默失效。
func TestGeoRecordCountryCode(t *testing.T) {
	var top geoRecord
	top.ISO = "cn"
	if got := top.countryCode(); got != "CN" {
		t.Errorf("顶层 iso 应为 CN，实际 %q", got)
	}

	var isoCode geoRecord
	isoCode.Country.ISOCode = "jp"
	if got := isoCode.countryCode(); got != "JP" {
		t.Errorf("country.iso_code 应为 JP，实际 %q", got)
	}

	var innerISO geoRecord
	innerISO.Country.ISO = "de"
	if got := innerISO.countryCode(); got != "DE" {
		t.Errorf("country.iso 应为 DE，实际 %q", got)
	}

	var reg geoRecord
	reg.RegisteredCountry.ISOCode = "fr"
	if got := reg.countryCode(); got != "FR" {
		t.Errorf("registered_country 应为 FR，实际 %q", got)
	}

	var empty geoRecord
	if got := empty.countryCode(); got != "" {
		t.Errorf("无国家信息应为空串，实际 %q", got)
	}
}

// 国家级判定不需要比 /24（IPv4）和 /32（IPv6）更细。
// 不收敛的话，本机 City 库的 CN 会产出 2.7 万条 IPv4 + 2.7 万条 IPv6，
// 数据面每个请求都要线性扫一遍。
func TestCoarsenPrefix(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"1.2.3.4/32", "1.2.3.0/24"},
		{"1.2.3.0/25", "1.2.3.0/24"},
		{"1.2.0.0/16", "1.2.0.0/16"},           // 已经比 /24 粗，保持
		{"2400:3200::1/128", "2400:3200::/32"}, // IPv6 收敛到 /32
		{"2400:3200::/29", "2400:3200::/29"},   // 已经比 /32 粗，保持
	}
	for _, tt := range tests {
		got := coarsenPrefix(mustPrefix(t, tt.in)).String()
		if got != tt.want {
			t.Errorf("coarsenPrefix(%s) = %s，期望 %s", tt.in, got, tt.want)
		}
	}
}

// 收敛后仍超限时逐档退到 /16、/12、/8，而不是按地址顺序截断。
// 截断会放行本国地址空间的后半段，且日志里看不出异常。
func TestAggregateToShrinksWithoutTruncating(t *testing.T) {
	// 造 300 个同 /16 下的 /24，收敛到 /16 后应只剩 1 条
	in := make([]netip.Prefix, 0, 300)
	for i := 0; i < 300; i++ {
		in = append(in, mustPrefix(t, fmt.Sprintf("10.1.%d.0/24", i%256)))
	}
	got := aggregateTo(in, 16, 32)
	if len(got) != 1 || got[0].String() != "10.1.0.0/16" {
		t.Fatalf("/16 收敛应合并成 1 条，实际 %d 条: %v", len(got), got)
	}
}

// 缓存 key 必须带 mmdb 的 size/mtime：库里换了数据却命中旧缓存，
// 表现是「更新了 GeoIP 库但拦截范围没变」，排查成本很高。
func TestGeoCacheKeyTracksMMDBChange(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "geo-*.mmdb")
	if err != nil {
		t.Fatalf("create temp: %v", err)
	}
	path := f.Name()
	if _, err := f.WriteString("aaaa"); err != nil {
		t.Fatalf("write: %v", err)
	}
	_ = f.Close()

	k1 := geoCacheKeyOf(path, []string{"cn", "us"}, true)

	// 同内容同大小，但 mtime 变了（模拟库被替换成同样大小的新文件）
	future := time.Now().Add(2 * time.Hour)
	if err := os.Chtimes(path, future, future); err != nil {
		t.Fatalf("chtimes: %v", err)
	}
	k2 := geoCacheKeyOf(path, []string{"cn", "us"}, true)
	if k1 == k2 {
		t.Fatal("mmdb mtime 变化后缓存 key 必须变化")
	}

	// 国家码顺序不同但集合相同 → 同一个 key
	if geoCacheKeyOf(path, []string{"us", "cn"}, true) != k2 {
		t.Error("国家码顺序不应影响缓存 key")
	}
	// merge 开关是 key 的一部分
	if geoCacheKeyOf(path, []string{"cn", "us"}, false) == k2 {
		t.Error("merge 开关应参与缓存 key")
	}
}
