package waf

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"sort"
	"strings"
	"sync"

	"github.com/3panel-dev/3panel/agent/app/model"
	"github.com/3panel-dev/3panel/agent/global"
	"github.com/oschwald/maxminddb-golang"
)

// geoMaxNetworksPerCountry 单国家输出上限（合并 + 必要时聚合之后）。
//
// 这个数字直接决定数据面开销：Lua 侧对每个请求在该国的区间表上做二分，
// 1 万条约等于 14 次比较，可以忽略；20 万条会让 rules.json 涨到几 MB、
// 每次规则同步都变慢。实测本机 GeoLite2-City：CN 合并后 IPv4 7332、
// IPv6 27148，聚合到 /24 与 /32 后共 10632 条，落在这个上限内。
const geoMaxNetworksPerCountry = 20000

// geoHardCapNetworks 遍历时的硬性熔断，只防异常库把内存吃光。
// 正常库（City 级 229 万网段）远达不到。
const geoHardCapNetworks = 500000

// geoRecord 是 mmdb 里我们关心的那部分结构。
//
// 国家码在库里可能出现在三个位置，必须都试：
//  1. country.iso_code —— 标准 GeoLite2-Country 的写法
//  2. country.iso      —— 部分裁剪版/第三方构建
//  3. 顶层 iso          —— 面板资源包实际下发的 GeoLite2-City 变体就是这种：
//     {country:{en:"China",zh:"中国"}, iso:"CN", latitude:..., province:{...}}
//
// 只认 iso_code 时，本机 19MB 的 GeoIP.mmdb 能打开、能遍历 229 万个网段，
// 但每条记录的国家码都读成空串，于是所有国家的 CIDR 列表都是 []，
// 界面上配了 geo 规则却完全不生效 —— 打开文件不等于读懂了它。
type geoRecord struct {
	ISO     string `maxminddb:"iso"`
	Country struct {
		ISO     string `maxminddb:"iso"`
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"country"`
	RegisteredCountry struct {
		ISO     string `maxminddb:"iso"`
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"registered_country"`
}

// countryCode 按上面三种位置依次取值，返回大写国家码。
func (r *geoRecord) countryCode() string {
	for _, c := range []string{
		r.Country.ISOCode,
		r.Country.ISO,
		r.ISO,
		r.RegisteredCountry.ISOCode,
		r.RegisteredCountry.ISO,
	} {
		if c != "" {
			return strings.ToUpper(c)
		}
	}
	return ""
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

	// 遍历一次 City 级库要 0.9 秒左右，而每次规则增删改都会同步一次数据面。
	// 命中缓存直接返回，避免用户每保存一次规则就等将近一秒。
	if cached, ok := geoCacheGet(mmdbPath, codes, merge); ok {
		return cached, nil
	}

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
	//
	// 收集时就直接收敛到 /24（IPv4）与 /32（IPv6）并用 map 去重，原因：
	// 拿到的可能是 City 级库（本机这份 19MB GeoLite2-City 有 229 万网段，
	// 单是 CN 就有 2.7 万条 IPv4 + 2.7 万条 IPv6）。先原样收下再聚合，
	// 内存和遍历时间都会翻好几倍，而 geo 规则本身就是国家级判定，
	// 比 /24 更细的划分对结果没有意义。
	collected := make(map[string]map[netip.Prefix]struct{}, len(want))
	total := 0

	networks := reader.Networks(maxminddb.SkipAliasedNetworks)
	for networks.Next() {
		var rec geoRecord
		ipnet, err := networks.Network(&rec)
		if err != nil || ipnet == nil {
			continue
		}
		code := rec.countryCode()
		if code == "" || !want[code] {
			continue
		}
		p, ok := prefixFromIPNet(ipnet)
		if !ok {
			continue
		}
		p = coarsenPrefix(p)
		if collected[code] == nil {
			collected[code] = make(map[netip.Prefix]struct{}, 4096)
		}
		if _, dup := collected[code][p]; dup {
			continue
		}
		collected[code][p] = struct{}{}
		total++
		// 这个上限只防异常库把内存吃光。收敛 + 去重后，正常库远达不到。
		if total > geoHardCapNetworks {
			return nil, fmt.Errorf(
				"geo database yields more than %d distinct networks; refusing to expand",
				geoHardCapNetworks)
		}
	}
	if err := networks.Err(); err != nil {
		return nil, fmt.Errorf("traverse geo db: %w", err)
	}

	out := make(map[string][]string, len(collected))
	for code, set := range collected {
		prefixes := make([]netip.Prefix, 0, len(set))
		for p := range set {
			prefixes = append(prefixes, p)
		}
		if merge {
			prefixes = mergePrefixes(prefixes)
		}
		// 收敛到 /24 后仍超限（实测 US 有 2 万+ 个 /24，收敛到 /16 后
		// 仍有 2 万+ 个 /16），逐档退到 /12、/8，直到落进上限。
		//
		// 为什么不是直接截断：截断是**按地址顺序**砍掉尾部，等于放行本国
		// 地址空间的后半段；多拦一点邻国地址，远比漏掉半个国家轻。
		for _, bits := range []int{16, 12, 8} {
			if len(prefixes) <= geoMaxNetworksPerCountry {
				break
			}
			prefixes = aggregateTo(prefixes, bits, 32)
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
	geoCachePut(mmdbPath, codes, merge, out)
	return out, nil
}

// ---- 解析结果缓存 ----------------------------------------------------------
//
// 只缓存最近一次结果：规则里的国家集合就是实际被引用的那几个，页面上的改动
// 也是在这几个之间来回，单槽足够且不用考虑淘汰策略。
// 必须以 mmdb 的 size + mtime 作为 key 的一部分 —— 库里更新了地址段却命中
// 旧缓存，表现是"换了 GeoIP 库但拦截范围没变"，很难查。

var (
	geoCacheMu   sync.Mutex
	geoCacheKey  string
	geoCacheData map[string][]string
)

func geoCacheKeyOf(mmdbPath string, codes []string, merge bool) string {
	sorted := make([]string, 0, len(codes))
	for _, c := range codes {
		sorted = append(sorted, strings.ToUpper(strings.TrimSpace(c)))
	}
	sort.Strings(sorted)
	stamp := ""
	if fi, err := os.Stat(mmdbPath); err == nil {
		stamp = fmt.Sprintf("%d/%d", fi.Size(), fi.ModTime().UnixNano())
	}
	return fmt.Sprintf("%s|%s|%t|%s", mmdbPath, stamp, merge, strings.Join(sorted, ","))
}

func geoCacheGet(mmdbPath string, codes []string, merge bool) (map[string][]string, bool) {
	key := geoCacheKeyOf(mmdbPath, codes, merge)
	geoCacheMu.Lock()
	defer geoCacheMu.Unlock()
	if geoCacheData == nil || geoCacheKey != key {
		return nil, false
	}
	// 返回副本：调用方（exporter）会把它塞进 JSON 数据结构里，
	// 共享同一份 map 会让后续改动串到缓存上。
	out := make(map[string][]string, len(geoCacheData))
	for k, v := range geoCacheData {
		cp := make([]string, len(v))
		copy(cp, v)
		out[k] = cp
	}
	return out, true
}

func geoCachePut(mmdbPath string, codes []string, merge bool, data map[string][]string) {
	key := geoCacheKeyOf(mmdbPath, codes, merge)
	geoCacheMu.Lock()
	defer geoCacheMu.Unlock()
	geoCacheKey = key
	geoCacheData = data
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

// coarsenPrefix 把前缀收敛到国家级粒度：IPv4 不超过 /24，IPv6 不超过 /32。
//
// 这是**有损**的：会把同一 /24 里其他国家的地址也算进本国。取舍依据是
// IPv4 地址块按国家分配、IPv6 的 /32 是运营商块，跨界 /24 极少；
// 而付出这个代价换来的是输出规模可控（CN 从 5.4 万条降到 1.06 万条），
// 数据面每次请求的匹配次数也随之从几万次降到十几次二分。
func coarsenPrefix(p netip.Prefix) netip.Prefix {
	return coarsenTo(p, 24, 32)
}

// coarsenTo 按指定粒度收敛（IPv4 用 v4Bits，IPv6 用 v6Bits）。
func coarsenTo(p netip.Prefix, v4Bits, v6Bits int) netip.Prefix {
	maxBits := v6Bits
	if p.Addr().Is4() {
		maxBits = v4Bits
	}
	bits := p.Bits()
	if bits > maxBits {
		bits = maxBits
	}
	q, err := p.Addr().Prefix(bits)
	if err != nil {
		return p.Masked()
	}
	return q.Masked()
}

// aggregatePrefixes 对一批前缀做 coarsenPrefix 并去重（兜底用）。
func aggregatePrefixes(in []netip.Prefix) []netip.Prefix {
	return aggregateTo(in, 24, 32)
}

func aggregateTo(in []netip.Prefix, v4Bits, v6Bits int) []netip.Prefix {
	seen := make(map[netip.Prefix]struct{}, len(in))
	for _, p := range in {
		seen[coarsenTo(p, v4Bits, v6Bits)] = struct{}{}
	}
	out := make([]netip.Prefix, 0, len(seen))
	for p := range seen {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool {
		if c := out[i].Addr().Compare(out[j].Addr()); c != 0 {
			return c < 0
		}
		return out[i].Bits() < out[j].Bits()
	})
	return out
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
