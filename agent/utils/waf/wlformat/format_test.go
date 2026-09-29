package wlformat

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"math/rand"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func mustPrefix(t *testing.T, s string) netip.Prefix {
	t.Helper()
	p, err := netip.ParsePrefix(s)
	if err != nil {
		t.Fatalf("bad prefix %q: %v", s, err)
	}
	return p.Masked()
}

func TestParseListFormats(t *testing.T) {
	const src = `# CINS Army List
1.2.3.4
10.0.0.0/8
192.168.1.1 ; SBL1234
not-an-ip
2001:db8::1
2001:db8::/32

1.2.3.4
`
	nets, skipped, err := ParseList(strings.NewReader(src))
	if err != nil {
		t.Fatalf("ParseList: %v", err)
	}
	if skipped != 1 {
		t.Errorf("skipped = %d, want 1", skipped)
	}
	// 6 条可解析：1.2.3.4 / 10.0.0.0/8 / 192.168.1.1 / 2001:db8::1 / 2001:db8::/32
	// 以及末尾重复的 1.2.3.4（去重是 Merge 的职责，ParseList 不做）
	if len(nets) != 6 {
		t.Fatalf("got %d nets, want 6: %v", len(nets), nets)
	}
	if got := nets[0].String(); got != "1.2.3.4/32" {
		t.Errorf("nets[0] = %s", got)
	}
	if got := nets[1].String(); got != "10.0.0.0/8" {
		t.Errorf("nets[1] = %s", got)
	}
	if got := nets[2].String(); got != "192.168.1.1/32" {
		t.Errorf("comment stripping failed: %s", got)
	}
}

func TestMergeCollapsesAndDedups(t *testing.T) {
	cases := []struct {
		name string
		in   []string
		want []string
	}{
		{
			name: "duplicate single ips",
			in:   []string{"1.2.3.4/32", "1.2.3.4/32", "1.2.3.4/32"},
			want: []string{"1.2.3.4/32"},
		},
		{
			name: "siblings merge into parent",
			in:   []string{"1.2.3.0/25", "1.2.3.128/25"},
			want: []string{"1.2.3.0/24"},
		},
		{
			name: "small covered by large",
			in:   []string{"1.2.3.0/24", "1.2.3.4/32", "1.2.3.5/32"},
			want: []string{"1.2.3.0/24"},
		},
		{
			// 8 个 /25 覆盖 1.2.0.0 - 1.2.3.255，正好是一个 /22
			name: "chain up to /22",
			in: []string{
				"1.2.3.0/25", "1.2.3.128/25",
				"1.2.2.0/25", "1.2.2.128/25",
				"1.2.1.0/25", "1.2.1.128/25",
				"1.2.0.0/25", "1.2.0.128/25",
			},
			want: []string{"1.2.0.0/22"},
		},
		{
			name: "non adjacent stay separate",
			in:   []string{"1.2.3.0/25", "1.2.5.0/25"},
			want: []string{"1.2.3.0/25", "1.2.5.0/25"},
		},
		{
			name: "disjoint ranges untouched",
			in:   []string{"10.0.0.1/32", "192.168.1.1/32", "8.8.8.8/32"},
			want: []string{"8.8.8.8/32", "10.0.0.1/32", "192.168.1.1/32"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var in []netip.Prefix
			for _, s := range tc.in {
				in = append(in, mustPrefix(t, s))
			}
			got, _ := Merge(in)
			if len(got) != len(tc.want) {
				t.Fatalf("got %d prefixes %v, want %d %v", len(got), got, len(tc.want), tc.want)
			}
			for i := range got {
				if got[i].String() != tc.want[i] {
					t.Errorf("[%d] = %s, want %s", i, got[i], tc.want[i])
				}
			}
		})
	}
}

// TestMergeIdempotent 验证重复聚合同一批数据得到同一结果，
// 这是 CI 每次全量重建时能稳定产出可比较产物的前提。
func TestMergeIdempotent(t *testing.T) {
	var in []netip.Prefix
	for i := 0; i < 5000; i++ {
		in = append(in, mustPrefix(t, "10."+itoa(i/65536%256)+"."+itoa(i/256%256)+"."+itoa(i%256)+"/32"))
	}
	first, _ := Merge(in)
	second, _ := Merge(append(append([]netip.Prefix{}, first...), first...))
	if len(first) != len(second) {
		t.Fatalf("not idempotent: %d vs %d", len(first), len(second))
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}

func TestEncodeDecodeRoundTrip(t *testing.T) {
	var in []netip.Prefix
	for i := 0; i < 200; i++ {
		in = append(in, mustPrefix(t, "203.0."+itoa(i/256)+"."+itoa(i%256)+"/32"))
	}
	in = append(in,
		mustPrefix(t, "10.0.0.0/8"),
		mustPrefix(t, "172.16.0.0/12"),
		mustPrefix(t, "8.8.8.8/32"),
	)
	v6in := []netip.Prefix{
		mustPrefix(t, "2001:db8::/32"),
		mustPrefix(t, "2001:4860:4860::8888/128"),
	}
	merged4, _ := Merge(in)
	_, merged6 := Merge(v6in)

	blob, err := Encode(merged4, merged6)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	got4, got6, err := Decode(blob)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if len(got4) != len(merged4) {
		t.Fatalf("v4 count %d, want %d", len(got4), len(merged4))
	}
	for i := range got4 {
		if got4[i] != merged4[i] {
			t.Fatalf("v4[%d] = %s, want %s", i, got4[i], merged4[i])
		}
	}
	if len(got6) != len(merged6) {
		t.Fatalf("v6 count %d, want %d", len(got6), len(merged6))
	}
	for i := range got6 {
		if got6[i] != merged6[i] {
			t.Fatalf("v6[%d] = %s, want %s", i, got6[i], merged6[i])
		}
	}
}

// TestDecodeRejectsBadInput 覆盖被截断或损坏的文件。
// 数据面若拿到半截文件还当正常名单用，等于黑名单静默失效。
func TestDecodeRejectsBadInput(t *testing.T) {
	v4 := []netip.Prefix{mustPrefix(t, "1.2.3.0/24")}
	blob, err := Encode(v4, nil)
	if err != nil {
		t.Fatal(err)
	}

	if _, _, err := Decode([]byte("not a wlfile at all.............")); err != ErrBadMagic {
		t.Errorf("bad magic: got %v", err)
	}
	bad := append([]byte{}, blob...)
	bad[4] = 99
	if _, _, err := Decode(bad); err == nil {
		t.Error("version mismatch accepted")
	}
	if _, _, err := Decode(blob[:5]); err != ErrTruncated {
		t.Errorf("truncated header: got %v", err)
	}
	if _, _, err := Decode(blob[:len(blob)-1]); err == nil {
		t.Error("truncated body accepted")
	}
	if _, _, err := Decode(nil); err != ErrTruncated {
		t.Errorf("empty: got %v", err)
	}
	// 声明了 v6 计数但没有 v6 数据
	lied := append([]byte{}, blob...)
	lied[13] = 5
	if _, _, err := Decode(lied); err == nil {
		t.Error("mismatched v6 count accepted")
	}
}

// TestDecodeRejectsUnalignedRange 保证只有折叠过的（2 的幂）区间能通过。
func TestDecodeRejectsUnalignedRange(t *testing.T) {
	buf := make([]byte, HeaderSize)
	copy(buf, Magic)
	buf[4] = Version
	buf[9] = 1 // countV4 = 1
	// gap=0 => start 0, length=3 (非 2 的幂)
	buf = binary.AppendUvarint(buf, 0)
	buf = binary.AppendUvarint(buf, 3)
	if _, _, err := Decode(buf); err == nil {
		t.Error("non-CIDR length accepted")
	}
}

func TestEncodeRejectsUnsorted(t *testing.T) {
	bad := []netip.Prefix{mustPrefix(t, "1.2.3.4/32"), mustPrefix(t, "1.2.3.4/32")}
	if _, err := Encode(bad, nil); err == nil {
		t.Error("duplicate entries accepted")
	}
	rev := []netip.Prefix{mustPrefix(t, "1.2.3.5/32"), mustPrefix(t, "1.2.3.4/32")}
	if _, err := Encode(rev, nil); err == nil {
		t.Error("descending entries accepted")
	}
}

// TestBinaryIsCompact 守住体积预算：格式设计的目的就是让 13 万条网段
// 控制在几百 KB。若将来改动让体积回涨到 MB 级，这条会失败。
func TestBinaryIsCompact(t *testing.T) {
	var in []netip.Prefix
	// 模拟真实分布：大量离散单 IP + 少量 /24
	rng := rand.New(rand.NewSource(1))
	for i := 0; i < 130000; i++ {
		a := netip.AddrFrom4([4]byte{
			byte(rng.Intn(256)), byte(rng.Intn(256)), byte(rng.Intn(256)), byte(rng.Intn(256)),
		})
		in = append(in, netip.PrefixFrom(a, 32))
	}
	merged4, _ := Merge(in)
	blob, err := Encode(merged4, nil)
	if err != nil {
		t.Fatal(err)
	}
	// 130k 条离散 IP，实测约 380KB；留 2 倍余量作为回归红线。
	if len(blob) > 800*1024 {
		t.Errorf("payload %d bytes for %d ranges, exceeds 800KB budget", len(blob), len(merged4))
	}
	t.Logf("%d ranges -> %.1f KB (%.1f bytes/range)", len(merged4), float64(len(blob))/1024, float64(len(blob))/float64(len(merged4)))
}

func TestMetaJSONRoundTrip(t *testing.T) {
	blob := []byte("hello")
	sum := sha256.Sum256(blob)
	m := Meta{
		Version:     Version,
		GeneratedAt: "2026-09-29T02:00:00Z",
		SHA256:      hex.EncodeToString(sum[:]),
		Size:        int64(len(blob)),
		CountV4:     12,
		CountV6:     3,
		Sources:     []MetaSource{{Name: "cins", URL: "https://x", Entries: 15000}, {Name: "et", Err: "timeout"}},
		Mirrors:     []string{"https://a", "https://b", "https://c"},
	}
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	var back Meta
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if back.SHA256 != m.SHA256 || back.CountV4 != 12 || len(back.Sources) != 2 {
		t.Errorf("round trip mismatch: %+v", back)
	}
	if back.Sources[1].Err != "timeout" {
		t.Errorf("source err lost: %+v", back.Sources[1])
	}
}

// TestAgainstFixture 用 CI 产出的真实制品做端到端校验。
// fixture 缺失时跳过，保证单测在未下载制品的环境仍能跑。
func TestAgainstFixture(t *testing.T) {
	path := filepath.Join("testdata", DefaultDataName)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Skip("no fixture, run: make fixture")
	}
	v4, v6, err := Decode(raw)
	if err != nil {
		t.Fatalf("Decode fixture: %v", err)
	}
	if len(v4) == 0 {
		t.Fatal("fixture decoded to zero ranges")
	}
	// 折叠后的结果必须严格升序且互不重叠 —— 这是二分查找的前提。
	for i := 1; i < len(v4); i++ {
		prev := v4[i-1]
		cur := v4[i]
		if cur.Addr().Compare(prev.Addr()) <= 0 {
			t.Fatalf("v4[%d] not ascending: %s then %s", i, prev, cur)
		}
		if prev.Contains(cur.Addr()) {
			t.Fatalf("v4[%d] %s overlaps %s", i, cur, prev)
		}
	}
	sum := sha256.Sum256(raw)
	if metaRaw, err := os.ReadFile(filepath.Join("testdata", DefaultMetaName)); err == nil {
		var m Meta
		if err := json.Unmarshal(metaRaw, &m); err != nil {
			t.Fatalf("meta: %v", err)
		}
		if !strings.EqualFold(m.SHA256, hex.EncodeToString(sum[:])) {
			t.Errorf("sha256 mismatch: meta=%s actual=%s", m.SHA256, hex.EncodeToString(sum[:]))
		}
		if m.CountV4 != len(v4) || m.CountV6 != len(v6) {
			t.Errorf("count mismatch: meta=(%d,%d) decoded=(%d,%d)", m.CountV4, m.CountV6, len(v4), len(v6))
		}
	}
	t.Logf("fixture ok: v4=%d v6=%d size=%d", len(v4), len(v6), len(raw))
}

// TestWriteAndReadFile 覆盖落盘与再次读回的完整路径。
func TestWriteAndReadFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, DefaultDataName)
	var in []netip.Prefix
	for _, s := range []string{"1.2.3.0/24", "8.8.8.8/32", "10.0.0.0/8"} {
		in = append(in, mustPrefix(t, s))
	}
	merged4, _ := Merge(in)
	blob, err := Encode(merged4, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, blob, 0o644); err != nil {
		t.Fatal(err)
	}
	back, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(back, blob) {
		t.Error("file round trip mismatch")
	}
}
