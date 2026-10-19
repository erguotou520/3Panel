package waf

import (
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"

	"github.com/3panel-dev/3panel/agent/app/model"
	"github.com/3panel-dev/3panel/agent/global"
	"github.com/oschwald/maxminddb-golang"
)

// geoMaxNetworksPerCountry 单国家 CIDR 数量上限。
//
// GeoLite2 里一个大国约 8000~10000 条 IPv4 网络，加上 IPv6 会再多一些。
// 合并相邻前缀后通常能压掉 20~40%。这里给到 20000 是留足余量，
// 同时防止某个异常 mmdb 把内存吃光 —— 真超了宁可少算，也不能拖垮 agent。
const geoMaxNetworksPerCountry = 20000

// geoMaxTotalNetworks 所有国家合计上限，防止一条规则引用几十个国家。
const geoMaxTotalNetworks = 60000

// geoRecord 是 mmdb 里我们关心的那部分结构。
type geoRecord struct {
	Country struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"country"`
	RegisteredCountry struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"registered_country"`
}

// ResolveCountryCIDRs 解析国家码对应的 CIDR 列表。
//
// 为什么是「解析成 CIDR」而不是「请求时查 mmdb」：匹配发生在 Lua/OpenResty
// 侧，Go 不在请求路径上。把国家展开成 CIDR 后，数据面复用已有的 in_cidr
// 判定即可，不需要在 Lua 里解析二进制格式。
//
// 只在有启用的 geo 规则时才调用，且只解析**被引用到的**国家码 ——
// 把全世界都写进 rules.json 会让它膨胀到几 MB，而绝大多数站点只关心
// 自己那一两个国家。
//
// mmdb 不存在时返回 (nil, nil)：调用方据此标记 geo 不可用，
// 而不是让整个导出失败 —— 地理数据缺失不该影响其它规则的同步。
func ResolveCountryCIDRs(mmdbPath string, codes []string, merge bool) (map[string][]string, error) {
	if len(codes) == 0 {
		return map[string][]string{}, nil
	}

	reader, err := maxminddb.Open(mmdbPath)
	if err != nil {
		// 文件缺失/损坏都归为「不可用」，由调用方决定怎么呈现。
		return nil, nil
	}
	defer func() { _ = reader.Close() }()

	want := make(map[string]bool, len(codes))
	for _, c := range codes {
		up := strings.ToUpper(strings.TrimSpace(c))
		if up != "" {
			want[up] = true
		}
	}
	if len(want) == 0 {
		return map[string][]string{}, nil
	}

	// 按国家收集 netip.Prefix。用 netip 而不是 net.IPNet：
	// 它可比较、可排序，后面合并前缀时省掉大量字节比较。
	collected := make(map[string][]netip.Prefix, len(want))
	total := 0

	networks := reader.Networks(maxminddb.SkipAliasedNetworks)
	for networks.Next() {
		var rec geoRecord
		ipnet, err := networks.Network(&rec)
		if err != nil || ipnet == nil {
			continue
		}
		code := strings.ToUpper(rec.Country.ISOCode)
		if code == "" {
			// 有些库把国家信息放在 registered_country 里。
			code = strings.ToUpper(rec.RegisteredCountry.ISOCode)
		}
		if code == "" || !want[code] {
			continue
		}
		p, ok := prefixFromIPNet(ipnet)
		if !ok {
			continue
		}
		collected[code] = append(collected[code], p)
		total++
		if total > geoMaxTotalNetworks {
			return nil, fmt.Errorf(
				"geo rule references too many networks (>%d); narrow the country list",
				geoMaxTotalNetworks)
		}
	}
	if err := networks.Err(); err != nil {
		return nil, fmt.Errorf("traverse geo db: %w", err)
	}

	out := make(map[string][]string, len(collected))
	for code, prefixes := range collected {
		if merge {
			prefixes = mergePrefixes(prefixes)
		}
		if len(prefixes) > geoMaxNetworksPerCountry {
			prefixes = prefixes[:geoMaxNetworksPerCountry]
		}
		list := make([]string, 0, len(prefixes))
		for _, p := range prefixes {
			list = append(list, p.String())
		}
		sort.Strings(list)
		out[code] = list
	}
	// 引用了但库里没有的国家也要出现（空数组）：Lua 侧查得到键、
	// 拿到空表 → 不命中。前端据此显示「该国家无数据」而不是静默缺失。
	for code := range want {
		if _, ok := out[code]; !ok {
			out[code] = []string{}
		}
	}
	return out, nil
}

// prefixFromIPNet 把 net.IPNet 转成 netip.Prefix。
//
// net.IPNet 的 IP 可能是 16 字节形式的 IPv4，Mask 也可能是 4 字节 ——
// 直接 netip.AddrFromSlice 会得到 IPv6 地址，与数据面里的 IPv4 CIDR
// 对不上。这里显式区分。
func prefixFromIPNet(n *net.IPNet) (netip.Prefix, bool) {
	if n == nil {
		return netip.Prefix{}, false
	}
	ones, bits := n.Mask.Size()
	if ones < 0 {
		return netip.Prefix{}, false
	}
	var addr netip.Addr
	if v4 := n.IP.To4(); v4 != nil && bits == 32 {
		a, ok := netip.AddrFromSlice(v4)
		if !ok {
			return netip.Prefix{}, false
		}
		addr = a.Unmap()
	} else {
		a, ok := netip.AddrFromSlice(n.IP)
		if !ok {
			return netip.Prefix{}, false
		}
		addr = a
	}
	p, err := addr.Prefix(ones)
	if err != nil {
		return netip.Prefix{}, false
	}
	return p.Masked(), true
}

// mergePrefixes 合并互为兄弟的相邻前缀（10.0.0.0/25 + 10.0.0.128/25 → /24）。
//
// 为什么值得做：一个国家的网络列表里大量前缀是同一段连续地址被切碎而成，
// 合并后通常能少 20~40% 条目，rules.json 直接小一圈。
//
// 只合并**兄弟**（除最后一位外完全相同、位数相同）—— 那是唯一能无损
// 合成单条前缀的情形。地址相邻但不同父的（如 /25 + /26）不合，
// 强行合会扩大匹配范围，在多接一个不该拦的 IP 面前，省这几字节不值得。
func mergePrefixes(in []netip.Prefix) []netip.Prefix {
	if len(in) < 2 {
		return in
	}
	// 先按 (地址, 位数) 升序，保证兄弟相邻。
	sorted := make([]netip.Prefix, len(in))
	copy(sorted, in)
	sort.Slice(sorted, func(i, j int) bool {
		if c := sorted[i].Addr().Compare(sorted[j].Addr()); c != 0 {
			return c < 0
		}
		return sorted[i].Bits() < sorted[j].Bits()
	})

	out := make([]netip.Prefix, 0, len(sorted))
	for _, p := range sorted {
		cur := p
		for {
			merged := false
			if len(out) > 0 {
				last := out[len(out)-1]
				if parent, ok := mergeSiblings(last, cur); ok {
					out = out[:len(out)-1]
					cur = parent
					merged = true
				}
			}
			if !merged {
				break
			}
		}
		// 去重：完全相同的连续前缀不要重复塞进去。
		if len(out) > 0 && out[len(out)-1] == cur {
			continue
		}
		out = append(out, cur)
	}
	return out
}

// mergeSiblings 判断两条前缀是否互为兄弟并返回父前缀。
func mergeSiblings(a, b netip.Prefix) (netip.Prefix, bool) {
	if a.Bits() != b.Bits() || a.Bits() == 0 {
		return netip.Prefix{}, false
	}
	if a.Addr().BitLen() != b.Addr().BitLen() {
		return netip.Prefix{}, false
	}
	parentBits := a.Bits() - 1
	pa, err := a.Addr().Prefix(parentBits)
	if err != nil {
		return netip.Prefix{}, false
	}
	pb, err := b.Addr().Prefix(parentBits)
	if err != nil {
		return netip.Prefix{}, false
	}
	if pa.Masked() != pb.Masked() {
		return netip.Prefix{}, false
	}
	return pa.Masked(), true
}

// collectGeoCodes 从规则里收集被引用的国家码（去重、大写）。
//
// 只收 match_type == "geo" 的规则：别的类型的 match_value 是 IP/路径/UA，
// 拿去当国家码查只会白白扩大解析范围。
func collectGeoCodes(rules []model.WAFRule) []string {
	seen := make(map[string]bool)
	var out []string
	for _, r := range rules {
		if r.MatchType != "geo" || !r.Enabled {
			continue
		}
		// 支持一条规则写多个国家：CN,US,JP
		for _, part := range strings.Split(r.MatchValue, ",") {
			code := strings.ToUpper(strings.TrimSpace(part))
			if code == "" || seen[code] {
				continue
			}
			// 只接受 2 位字母国家码。写错格式的条目直接忽略 ——
			// 解析阶段会把它当作"库里没有"报出来。
			if len(code) != 2 {
				continue
			}
			seen[code] = true
			out = append(out, code)
		}
	}
	sort.Strings(out)
	return out
}

// logGeoResolveFailure 记录地理解析失败。
//
// 单独抽出来是为了在测试里替换掉 —— 这条路径不该依赖全局 logger。
var logGeoResolveFailure = func(err error) {
	if global.LOG != nil {
		global.LOG.Errorf("[waf] resolve geo cidrs failed: %v", err)
	}
}
