package waf

import (
	"net"
	"net/netip"
	"testing"

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
