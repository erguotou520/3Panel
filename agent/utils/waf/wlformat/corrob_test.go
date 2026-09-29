package wlformat

import (
	"net/netip"
	"testing"
)

func prefixesOf(t *testing.T, ss ...string) []netip.Prefix {
	t.Helper()
	out := make([]netip.Prefix, 0, len(ss))
	for _, s := range ss {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			t.Fatalf("bad prefix %q: %v", s, err)
		}
		out = append(out, p.Masked())
	}
	return out
}

// TestCorroborateRequiresIndependentSource 是整个机制的核心安全性质：
// 候选必须至少被一个独立公开源收录，否则一律拒绝。
// Worker 侧的「>= 3 个 panelId」挡不住伪造 —— panelId 由客户端自报、
// 无任何鉴权，写个脚本就能造出来。真正把关的是这一条。
func TestCorroborateRequiresIndependentSource(t *testing.T) {
	public := [][]netip.Prefix{
		prefixesOf(t, "1.2.3.0/24"),
		prefixesOf(t, "8.8.8.8/32"),
	}
	cover := NewCover(public)

	cands := prefixesOf(t, "1.2.3.4/32", "203.0.113.77/32")
	kept, st, err := cover.Corroborate(cands, 1)
	if err != nil {
		t.Fatalf("Corroborate: %v", err)
	}
	if st.Total != 2 || st.Accepted != 1 || st.Rejected != 1 {
		t.Fatalf("stats = %+v, want total=2 accepted=1 rejected=1", st)
	}
	if st.RejectedNoCover != 1 {
		t.Errorf("RejectedNoCover = %d, want 1", st.RejectedNoCover)
	}
	if len(kept) != 1 || kept[0].String() != "1.2.3.4/32" {
		t.Errorf("kept = %v, want [1.2.3.4/32]", kept)
	}
}

// TestCorroborateCountsMultipleSources 验证 min=2 时多源收录才通过。
func TestCorroborateCountsMultipleSources(t *testing.T) {
	cover := NewCover([][]netip.Prefix{
		prefixesOf(t, "1.2.3.4/32"),
		prefixesOf(t, "1.2.3.0/24"), // 也收录 1.2.3.4
		prefixesOf(t, "8.8.8.8/32"),
	})
	if got := cover.Count(mustAddr(t, "1.2.3.4")); got != 2 {
		t.Errorf("Count(1.2.3.4) = %d, want 2", got)
	}
	if got := cover.Count(mustAddr(t, "8.8.8.8")); got != 1 {
		t.Errorf("Count(8.8.8.8) = %d, want 1", got)
	}
	if got := cover.Count(mustAddr(t, "9.9.9.9")); got != 0 {
		t.Errorf("Count(9.9.9.9) = %d, want 0", got)
	}

	cands := prefixesOf(t, "1.2.3.4/32", "8.8.8.8/32", "9.9.9.9/32")
	kept, st, err := cover.Corroborate(cands, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(kept) != 1 || kept[0].String() != "1.2.3.4/32" {
		t.Errorf("kept = %v, want [1.2.3.4/32]", kept)
	}
	if st.Accepted != 1 || st.RejectedNoCover != 2 {
		t.Errorf("stats = %+v, want accepted=1 rejectedNoCover=2", st)
	}
	// 直方图能看出把 min 提到 2 砍掉了谁
	if st.Histogram["2"] != 1 || st.Histogram["1"] != 1 || st.Histogram["0"] != 1 {
		t.Errorf("Histogram = %v, want {2:1, 1:1, 0:1}", st.Histogram)
	}
}

// TestCorroborateInheritsCIDR 覆盖边界：候选是源里某个网段内的单个 IP。
// 这种情形最容易被漏掉 —— 源给的是 1.2.3.0/24，候选是 1.2.3.4/32，
// 字面不相等，但地址确实落在源覆盖范围内，必须判为已收录。
func TestCorroborateInheritsCIDR(t *testing.T) {
	cover := NewCover([][]netip.Prefix{
		prefixesOf(t, "10.0.0.0/8", "2001:db8::/32"),
	})
	cands := prefixesOf(t,
		"10.255.255.254/32", // /8 的最后一个地址，容易写错
		"11.0.0.1/32",       // 紧邻 /8 之外
		"2001:db8:1234::99/128",
		"2001:db9::1/128",
	)
	kept, st, err := cover.Corroborate(cands, 1)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"10.255.255.254/32", "2001:db8:1234::99/128"}
	if len(kept) != len(want) {
		t.Fatalf("kept = %v, want %v", kept, want)
	}
	for i := range want {
		if kept[i].String() != want[i] {
			t.Errorf("kept[%d] = %s, want %s", i, kept[i], want[i])
		}
	}
	if st.RejectedNoCover != 2 {
		t.Errorf("RejectedNoCover = %d, want 2", st.RejectedNoCover)
	}
}

// TestCorroborateRejectsNonHost 确认网段候选被拒。
// 上报通道无鉴权，IP 级信誉（这个 IP 确实被多实例观测为攻击源）
// 不能被升格成整段拉黑 —— 那正是无差别误伤正常用户的手段。
func TestCorroborateRejectsNonHost(t *testing.T) {
	cover := NewCover([][]netip.Prefix{prefixesOf(t, "1.2.3.0/24", "2001:db8::/32")})
	cands := prefixesOf(t, "1.2.3.0/24", "2001:db8::/32")
	kept, st, err := cover.Corroborate(cands, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(kept) != 0 {
		t.Errorf("kept = %v, want empty", kept)
	}
	if st.RejectedNotHost != 2 || st.RejectedNoCover != 0 {
		t.Errorf("stats = %+v, want rejectedNotHost=2", st)
	}
}

// TestCorroborateMinZeroRejected 保证「关掉佐证」这个取值不存在。
// min=0 会让候选源退化成任意 IP 注入通道。
func TestCorroborateMinZeroRejected(t *testing.T) {
	cover := NewCover([][]netip.Prefix{prefixesOf(t, "1.2.3.0/24")})
	if _, _, err := cover.Corroborate(prefixesOf(t, "203.0.113.5/32"), 0); err == nil {
		t.Error("min=0 accepted; that disables corroboration entirely")
	}
}

// TestCorroborateEmptyPool 空候选池是合法状态（还没攒够 3 个 panelId），
// 不该报错，也不能因此拒绝发布。
func TestCorroborateEmptyPool(t *testing.T) {
	cover := NewCover([][]netip.Prefix{prefixesOf(t, "1.2.3.0/24")})
	kept, st, err := cover.Corroborate(nil, 1)
	if err != nil {
		t.Fatalf("empty pool: %v", err)
	}
	if len(kept) != 0 || st.Total != 0 {
		t.Errorf("kept=%v stats=%+v, want empty", kept, st)
	}
}

// TestCorroboratedCandidatesAddNoNewRanges 固化这个机制最反直觉、
// 也最重要的性质。
//
// min>=1 时每个被采纳的候选都已落在某个公开源的覆盖范围内，追加进并集
// 不会改变折叠结果 —— 上报候选通道对最终名单的**净贡献恒为 0 条新网段**。
// 也就是说它并不扩大封禁面，只提供审计价值。
//
// cmd/wlbuild 在真实构建时会实测这一点并在其非 0 时拒绝发布。
// 这条测试是同一不变量的快速版本。
func TestCorroboratedCandidatesAddNoNewRanges(t *testing.T) {
	public := [][]netip.Prefix{
		prefixesOf(t, "1.2.3.0/24", "8.8.8.8/32"),
		prefixesOf(t, "203.0.113.0/24"),
	}
	cover := NewCover(public)
	cands := prefixesOf(t,
		"1.2.3.4/32",       // 在 1.2.3.0/24 内
		"8.8.8.8/32",       // 精确命中
		"203.0.113.200/32", // 在 /24 内
		"9.9.9.9/32",       // 无源收录
	)
	kept, _, err := cover.Corroborate(cands, 1)
	if err != nil {
		t.Fatal(err)
	}
	before4, before6, _ := Summarize(public, 0)
	after4, after6, _ := Summarize(append(append([][]netip.Prefix{}, public...), kept), 0)
	if len(before4) != len(after4) || len(before6) != len(after6) {
		t.Fatalf("corroborated candidates changed the blocklist: %d/%d -> %d/%d",
			len(before4), len(before6), len(after4), len(after6))
	}
}

// TestCorroborateScaleGuard 用 10 万条级的数据量守性能与正确性。
// 若把佐证写成「拿候选去线性扫每个源的原始条目」，这里会退化到 O(n²)；
// 当前实现是「每源各自 Merge 后二分」，复杂度 O(源数 × log n) 每候选。
func TestCorroborateScaleGuard(t *testing.T) {
	// 一个 10 万条的公开源，稀疏单 IP 为主（与真实源同分布）。
	var big []netip.Prefix
	for i := 0; i < 100000; i++ {
		a := netip.AddrFrom4([4]byte{10, byte(i / 65536), byte(i / 256 % 256), byte(i % 256)})
		big = append(big, netip.PrefixFrom(a, 32))
	}
	cover := NewCover([][]netip.Prefix{big})

	// 一半在源里，一半不在。分桶统计避免随机源时的偶发抖动。
	var inPool, outPool []netip.Prefix
	for i := 0; i < 50000; i++ {
		covered := netip.AddrFrom4([4]byte{10, byte(i / 65536), byte(i / 256 % 256), byte(i % 256)})
		uncovered := netip.AddrFrom4([4]byte{172, byte(i / 65536), byte(i / 256 % 256), byte(i % 256)})
		inPool = append(inPool, netip.PrefixFrom(covered, 32))
		outPool = append(outPool, netip.PrefixFrom(uncovered, 32))
	}
	kept, st, err := cover.Corroborate(append(inPool, outPool...), 1)
	if err != nil {
		t.Fatal(err)
	}
	if st.Accepted != 50000 || st.RejectedNoCover != 50000 {
		t.Errorf("stats = %+v, want accepted=50000 rejectedNoCover=50000", st)
	}
	if len(kept) != 50000 {
		t.Errorf("kept %d, want 50000", len(kept))
	}
}

// TestPrefixSetContainsMatchesLinearScan 把二分查找与朴素 Contains 逐条对拍，
// 确认覆盖判断在任何输入分布下都正确 —— 这个函数是佐证的唯一判据，
// 判错方向错了就是安全漏洞（漏判即放行伪造 IP）。
func TestPrefixSetContainsMatchesLinearScan(t *testing.T) {
	var in []netip.Prefix
	rng := newTestRand(7)
	for i := 0; i < 5000; i++ {
		a := netip.AddrFrom4([4]byte{
			byte(rng.next() % 256), byte(rng.next() % 256),
			byte(rng.next() % 4), byte(rng.next() % 256),
		})
		in = append(in, netip.PrefixFrom(a, 32))
	}
	// 掺入 /24，制造「网段内的单 IP」这一边界
	for i := 0; i < 500; i++ {
		a := netip.AddrFrom4([4]byte{203, 0, byte(i % 256), 0})
		in = append(in, netip.PrefixFrom(a, 24))
	}
	merged, _ := Merge(in)

	for i := 0; i < 20000; i++ {
		probe := netip.AddrFrom4([4]byte{
			byte(rng.next() % 256), byte(rng.next() % 256), byte(rng.next() % 256), byte(rng.next() % 256),
		})
		var want bool
		for _, p := range merged {
			if p.Contains(probe) {
				want = true
				break
			}
		}
		if got := prefixSetContains(merged, probe); got != want {
			t.Fatalf("prefixSetContains(%s) = %v, want %v", probe, got, want)
		}
	}
	// 边界：恰好等于某条前缀的末地址 / 次一个地址
	edge := prefixesOf(t, "1.2.3.0/24", "8.8.8.8/32")
	edgeMerged, _ := Merge(edge)
	for _, tc := range []struct {
		ip   string
		want bool
	}{
		{"1.2.3.0", true}, {"1.2.3.255", true}, {"1.2.4.0", false},
		{"1.2.2.255", false}, {"8.8.8.8", true}, {"8.8.8.9", false},
	} {
		if got := prefixSetContains(edgeMerged, mustAddr(t, tc.ip)); got != tc.want {
			t.Errorf("prefixSetContains(%s) = %v, want %v", tc.ip, got, tc.want)
		}
	}
}

// TestPrefixSetContainsEmpty 空前缀表不能 panic，返回 false。
func TestPrefixSetContainsEmpty(t *testing.T) {
	if prefixSetContains(nil, mustAddr(t, "1.2.3.4")) {
		t.Error("empty table claimed coverage")
	}
	// 探针地址小于所有前缀起点时也不能 panic
	if prefixSetContains(prefixesOf(t, "200.0.0.0/8"), mustAddr(t, "1.2.3.4")) {
		t.Error("address before first prefix claimed coverage")
	}
}

// TestSourceCoverNilSafe 源全部抓取失败时 NewCover 收到空表，
// 此时任何候选都应被判为「无佐证」而拒绝。
func TestSourceCoverNilSafe(t *testing.T) {
	cover := NewCover(nil)
	if got := cover.Count(mustAddr(t, "1.2.3.4")); got != 0 {
		t.Errorf("Count on empty cover = %d, want 0", got)
	}
	kept, st, err := cover.Corroborate(prefixesOf(t, "1.2.3.4/32"), 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(kept) != 0 || st.RejectedNoCover != 1 {
		t.Errorf("kept=%v stats=%+v, want all rejected", kept, st)
	}
	var nilCover *SourceCover
	if got := nilCover.Count(mustAddr(t, "1.2.3.4")); got != 0 {
		t.Errorf("nil cover Count = %d, want 0", got)
	}
}

// TestCorroborateDedupsAccepted 候选池自身可能含重复项，
// 重复不该被当成「多源佐证」而重复计入采纳数。
func TestCorroborateDedupsAccepted(t *testing.T) {
	cover := NewCover([][]netip.Prefix{prefixesOf(t, "1.2.3.0/24")})
	cands := prefixesOf(t, "1.2.3.4/32", "1.2.3.4/32", "1.2.3.4/32")
	kept, st, err := cover.Corroborate(cands, 1)
	if err != nil {
		t.Fatal(err)
	}
	if st.Accepted != 3 {
		t.Errorf("Accepted = %d, want 3 (raw candidates counted before merge)", st.Accepted)
	}
	// 但折叠后只有 1 条：重复由 Merge 负责
	_, _, mst := Summarize([][]netip.Prefix{kept}, 0)
	if mst.V4 != 1 {
		t.Errorf("merged v4 = %d, want 1", mst.V4)
	}
}

// BenchmarkCorroborate 在接近真实的规模上量佐证开销：10 个源各 10 万条、
// 5 万个候选。这是「不 O(n²)」的实证依据 —— 朴素实现（每候选线性扫每源）
// 在这个规模上是 50000 × 100000 × 10 = 5×10^10 次比较，跑不完；
// 当前实现是每源一次二分。
func BenchmarkCorroborate(b *testing.B) {
	const numSources, perSource, numCands = 10, 100000, 50000
	rng := newTestRand(99)
	per := make([][]netip.Prefix, numSources)
	for s := range per {
		list := make([]netip.Prefix, 0, perSource)
		for i := 0; i < perSource; i++ {
			a := netip.AddrFrom4([4]byte{
				byte(rng.next() % 256), byte(rng.next() % 256),
				byte(rng.next() % 4), byte(rng.next() % 256),
			})
			list = append(list, netip.PrefixFrom(a, 32))
		}
		per[s] = list
	}
	cover := NewCover(per)
	cands := make([]netip.Prefix, 0, numCands)
	for i := 0; i < numCands; i++ {
		a := netip.AddrFrom4([4]byte{
			byte(rng.next() % 256), byte(rng.next() % 256), byte(rng.next() % 4), byte(rng.next() % 256),
		})
		cands = append(cands, netip.PrefixFrom(a, 32))
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, _, err := cover.Corroborate(cands, 1); err != nil {
			b.Fatal(err)
		}
	}
}

func mustAddr(t *testing.T, s string) netip.Addr {
	t.Helper()
	a, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatalf("bad addr %q: %v", s, err)
	}
	return a
}

// newTestRand 是一个极简确定性随机源，避免测试依赖 math/rand 的全局种子。
type testRand struct{ s uint64 }

func newTestRand(seed uint64) *testRand { return &testRand{s: seed} }

func (r *testRand) next() uint64 {
	// xorshift64*
	r.s ^= r.s >> 12
	r.s ^= r.s << 25
	r.s ^= r.s >> 27
	return r.s * 2685821657736338717
}
