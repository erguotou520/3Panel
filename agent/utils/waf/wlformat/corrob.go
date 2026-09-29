package wlformat

import (
	"fmt"
	"net/netip"
	"sort"
)

// 跨源佐证：让「上报候选」有机会进名单，但必须先被独立公开源收录。
//
// 上报候选来自 WAF 上报 Worker 的 /candidates.txt。它的升格条件是
// 「>= 3 个不同 panelId 上报过」，而 panelId 由客户端自报、没有任何鉴权 ——
// 写个脚本循环构造 3 个 panelId，就能把任意 IP 推成「3 个独立实例确认」，
// 于是任意人都能往全球 3panel 用户的黑名单里塞任意地址。
//
// 因此本文件实现前半个条件：
//
//	采纳 = 被 >= MinSources 个独立公开源收录 AND Worker 侧 >= 3 个 panelId 上报
//
// 后半个 Worker 已经做了。攻击者伪造 panelId 能推动的，只剩下
// 「已经被别人标记过」的 IP —— 而这类 IP 本来就会被各公开源收录，
// 伪造因此毫无收益。
//
// 反过来还有个更强的推论：MinSources >= 1 时，每个被采纳的候选都已落在
// 某个独立源的覆盖范围内，追加到并集里不会改变折叠结果。也就是说，
// 上报候选通道对最终名单的**净贡献恒为 0 条新网段**，它只提供审计价值
// （证明上报链路在跑、哪些 IP 被佐证过）。cmd/wlbuild 会在构建时实测这一点
// 并在非 0 时拒绝发布 —— 那意味着佐证逻辑漏了，产物即成注入通道。

// SourceCover 回答「某个地址被哪几个独立源收录」，用于候选的佐证查询。
//
// 每个源各自 Merge 一次，得到升序、互不重叠的区间表；查询时逐表二分。
// 单次查询 O(源数 × log n)：10 个源、13 万条 v4 上约 170 步，
// 远好于拿原始条目线性扫（10 万候选 × 20 万条目 = 20 亿次比较）。
//
// 刻意不做「全部源合并成一张表 + 布尔查询」：那样只能回答「是否被收录」，
// 拿不到「被几个源收录」，而分源计数正是审计与调参（要不要把 MinSources
// 提到 2）所必需的。
type SourceCover struct {
	perSource []sourceIndex
}

type sourceIndex struct {
	v4 []netip.Prefix
	v6 []netip.Prefix
}

// NewCover 为一组**相互独立**的公开源建索引。
//
// 调用方必须只传公开源，绝不能把上报候选源也传进来：一旦候选参与了
// 佐证索引，先被采纳的伪造候选就会替后续候选背书，佐证随即失效。
func NewCover(perSource [][]netip.Prefix) *SourceCover {
	c := &SourceCover{perSource: make([]sourceIndex, 0, len(perSource))}
	for _, ps := range perSource {
		v4, v6 := Merge(ps)
		c.perSource = append(c.perSource, sourceIndex{v4: v4, v6: v6})
	}
	return c
}

// Count 返回收录 addr 的独立源数量。
func (c *SourceCover) Count(addr netip.Addr) int {
	if c == nil || !addr.IsValid() {
		return 0
	}
	n := 0
	for _, s := range c.perSource {
		lst := s.v6
		if addr.Is4() {
			lst = s.v4
		}
		if prefixSetContains(lst, addr) {
			n++
		}
	}
	return n
}

// prefixSetContains 在升序、互不重叠的前缀表里二分查找。
// 找最后一个起点 <= addr 的前缀，再看它是否覆盖 addr。
// 前提由 Merge 保证；非升序/有重叠的表会给出错误答案，故调用方只传 Merge 结果。
func prefixSetContains(ps []netip.Prefix, addr netip.Addr) bool {
	i := sort.Search(len(ps), func(i int) bool { return ps[i].Addr().Compare(addr) > 0 }) - 1
	if i < 0 {
		return false
	}
	return ps[i].Contains(addr)
}

// CorroborateStats 是候选池佐证的统计，写进 meta.json 供审计。
type CorroborateStats struct {
	// Total 是候选池去重前的条目数。
	Total int `json:"total"`
	// Accepted 是被采纳的候选数。
	Accepted int `json:"accepted"`
	// Rejected 是被拒绝的候选数，等于两个拒绝原因之和。
	Rejected int `json:"rejected"`
	// RejectedNoCover 是「未被足够多独立源收录」而拒绝的数量，
	// 也就是伪造 panelId 能直接观测到的那部分攻击。
	RejectedNoCover int `json:"rejectedNoCorroboration"`
	// RejectedNotHost 是「不是单个主机地址」而拒绝的数量。
	RejectedNotHost int `json:"rejectedNotSingleHost"`
	// Histogram 按「被 N 个独立源收录」分桶统计全部候选（N=0 即无源收录）。
	// 从它可以直接看出把 MinSources 提到 2 会砍掉多少候选。
	Histogram map[string]int `json:"corroborationHistogram"`
}

// Corroborate 过滤候选池，只留下被至少 min 个独立源收录的单 IP。
//
// 只收单 IP（/32、/128）是刻意的：上报通道是无鉴权的，IP 级信誉信号
// （某个 IP 确实被多实例观测为攻击源）与「整个网段拉黑」不是一回事，
// 后者正是无差别误伤正常用户的手段。Worker 也只会输出单 IP。
// CIDR 候选一律拒绝并计入 RejectedNotHost。
//
// min 必须 >= 1：传 0 等于关掉佐证，候选源会退化成任意 IP 注入通道。
func (c *SourceCover) Corroborate(cands []netip.Prefix, min int) ([]netip.Prefix, CorroborateStats, error) {
	if min < 1 {
		return nil, CorroborateStats{}, fmt.Errorf("wlformat: corroborate min sources must be >= 1, got %d", min)
	}
	st := CorroborateStats{Total: len(cands), Histogram: map[string]int{}}
	accepted := make([]netip.Prefix, 0, len(cands))
	for _, p := range cands {
		if !p.IsValid() {
			st.Rejected++
			st.RejectedNotHost++
			continue
		}
		// 必须是主机地址：/32 或 /128。
		if p.Bits() != p.Addr().BitLen() {
			st.Rejected++
			st.RejectedNotHost++
			continue
		}
		n := c.Count(p.Addr())
		st.Histogram[fmt.Sprint(n)]++
		if n < min {
			st.Rejected++
			st.RejectedNoCover++
			continue
		}
		accepted = append(accepted, p)
	}
	st.Accepted = len(accepted)
	return accepted, st, nil
}
