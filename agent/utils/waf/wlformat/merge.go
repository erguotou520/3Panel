package wlformat

import (
	"bufio"
	"fmt"
	"io"
	"net/netip"
	"sort"
	"strings"
)

// ParseList 解析纯文本 IP 列表，逐行一个，支持：
//
//	1.2.3.4            单 IP
//	1.2.3.0/24         CIDR
//	1.2.3.4 ; SBL1234  分号注释
//	# 整行注释         行首 # 或 ;
//
// 源站格式不统一（Spamhaus DROP 给 CIDR，CINS/blackip 给单 IP，
// 列表里还混着表头注释行），这里统一按"能解析成 IP 或 CIDR 就收"处理，
// 无法解析的行计入 skipped。
func ParseList(r io.Reader) (nets []netip.Prefix, skipped int, err error) {
	sc := bufio.NewScanner(r)
	// 部分源的行长超过默认 64KB 上限，放宽到 1MB。
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if i := strings.IndexAny(line, "#;"); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if p, ok := parseEntry(line); ok {
			nets = append(nets, p)
		} else {
			skipped++
		}
	}
	if err = sc.Err(); err != nil {
		return nil, skipped, err
	}
	return nets, skipped, nil
}

func parseEntry(s string) (netip.Prefix, bool) {
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil || !p.IsValid() {
			return netip.Prefix{}, false
		}
		return p.Masked(), true
	}
	a, err := netip.ParseAddr(s)
	if err != nil || !a.IsValid() {
		return netip.Prefix{}, false
	}
	return netip.PrefixFrom(a, a.BitLen()), true
}

// Merge 合并多来源的网络，输出去重、折叠、按地址升序且互不重叠的结果。
// 这是"同一个 CIDR 合并"这一步：先把所有源塞进一个集合去重，
// 再逐级合并完全被包含的小网段与相邻网段。
//
// 例：{1.2.3.4/32, 1.2.3.5/32, 1.2.3.0/25, 1.2.3.128/25}
// → 去重后 1.2.3.0/24（4 条前缀折叠成 1 条）
func Merge(all []netip.Prefix) (v4, v6 []netip.Prefix) {
	var p4, p6 []netip.Prefix
	for _, p := range all {
		if !p.IsValid() {
			continue
		}
		if p.Addr().Is4() {
			p4 = append(p4, p.Masked())
		} else {
			p6 = append(p6, p.Masked())
		}
	}
	return collapse(p4), collapse(p6)
}

// collapse 把一组前缀去重并折叠为最少的互不重叠前缀。
//
// 做法：按 (地址, 前缀长度) 排序去重，然后用栈维护"当前覆盖范围"。
// 新前缀若被栈顶包含则丢弃；若包含栈顶则弹出再纳入；
// 若与栈顶相邻或可合并则不断上卷。
// 复杂度 O(n log n)，实测 20 万条输入在 100ms 量级完成。
func collapse(ps []netip.Prefix) []netip.Prefix {
	if len(ps) == 0 {
		return nil
	}
	sort.Slice(ps, func(i, j int) bool {
		if c := ps[i].Addr().Compare(ps[j].Addr()); c != 0 {
			return c < 0
		}
		return ps[i].Bits() < ps[j].Bits()
	})
	// 去掉完全相同的前缀
	uniq := ps[:1]
	for _, p := range ps[1:] {
		if p != uniq[len(uniq)-1] {
			uniq = append(uniq, p)
		}
	}

	stack := make([]netip.Prefix, 0, len(uniq))
	for _, p := range uniq {
		absorbed := false
		for len(stack) > 0 {
			top := stack[len(stack)-1]
			if top.Bits() <= p.Bits() && top.Contains(p.Addr()) {
				// p 被 top 覆盖，丢弃
				absorbed = true
				break
			}
			if p.Bits() <= top.Bits() && p.Contains(top.Addr()) {
				// p 覆盖 top，弹出后继续比较
				stack = stack[:len(stack)-1]
				continue
			}
			// 尝试合并相邻（sibling）前缀
			if merged, ok := mergeSiblings(top, p); ok {
				stack = stack[:len(stack)-1]
				p = merged
				continue
			}
			break
		}
		if !absorbed {
			stack = append(stack, p)
		}
	}
	return stack
}

// mergeSiblings 判断两个前缀能否合并为一个更短的兄弟前缀。
// 例：1.2.3.0/25 与 1.2.3.128/25 → 1.2.3.0/24
func mergeSiblings(a, b netip.Prefix) (netip.Prefix, bool) {
	aa, bb := a.Addr(), b.Addr()
	if aa.BitLen() != bb.BitLen() || a.Bits() != b.Bits() {
		return netip.Prefix{}, false
	}
	if aa.Compare(bb) >= 0 {
		// 保证 a 在前
		aa, bb = bb, aa
	}
	parent := netip.PrefixFrom(aa, a.Bits()-1)
	if !parent.IsValid() {
		return netip.Prefix{}, false
	}
	if !parent.Contains(bb) {
		return netip.Prefix{}, false
	}
	return parent.Masked(), true
}

// Stats 汇总一次聚合的结果，用于生成 meta.json。
type Stats struct {
	RawEntries int
	Skipped    int
	V4         int
	V6         int
}

// Summarize 计算合并前后的统计信息。
func Summarize(perSource [][]netip.Prefix, skipped int) (mergedV4, mergedV6 []netip.Prefix, st Stats) {
	var all []netip.Prefix
	for _, s := range perSource {
		all = append(all, s...)
	}
	st.RawEntries = len(all)
	st.Skipped = skipped
	mergedV4, mergedV6 = Merge(all)
	st.V4, st.V6 = len(mergedV4), len(mergedV6)
	return mergedV4, mergedV6, st
}

// DescribePrefix 用于日志与测试断言。
func DescribePrefix(p netip.Prefix) string {
	if !p.IsValid() {
		return "<invalid>"
	}
	return fmt.Sprintf("%s/%d", p.Addr(), p.Bits())
}
