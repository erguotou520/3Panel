package iplistsync

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/3panel-dev/3panel/agent/utils/waf/wlformat"
)

// makeBlob 造一份合法的制品。
func makeBlob(t *testing.T, ips ...string) ([]byte, wlformat.Meta) {
	t.Helper()
	var v4 []netip.Prefix
	for _, s := range ips {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			a, aerr := netip.ParseAddr(s)
			if aerr != nil {
				t.Fatalf("bad ip %q", s)
			}
			p = netip.PrefixFrom(a, a.BitLen())
		}
		v4 = append(v4, p.Masked())
	}
	merged, _ := wlformat.Merge(v4)
	blob, err := wlformat.Encode(merged, nil)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(blob)
	return blob, wlformat.Meta{
		Version: wlformat.Version,
		SHA256:  hex.EncodeToString(sum[:]),
		Size:    int64(len(blob)),
		CountV4: len(merged),
		CountV6: 0,
		Mirrors: []string{"test"},
	}
}

// serve 在本地起一个镜像。
func serve(t *testing.T, blob []byte, meta wlformat.Meta, failData bool) Mirror {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/meta.json", func(w http.ResponseWriter, r *http.Request) {
		b, _ := json.Marshal(meta)
		w.Header().Set("content-type", "application/json")
		_, _ = w.Write(b)
	})
	mux.HandleFunc("/wl_v2.bin", func(w http.ResponseWriter, r *http.Request) {
		if failData {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		_, _ = w.Write(blob)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return Mirror{Name: "test", MetaURL: srv.URL + "/meta.json", DataURL: srv.URL + "/wl_v2.bin"}
}

func TestUpdateDownloadsAndValidates(t *testing.T) {
	dir := t.TempDir()
	blob, meta := makeBlob(t, "1.2.3.4/32", "8.8.8.0/24")
	m := serve(t, blob, meta, false)

	c := NewClient(dir, []Mirror{m})
	changed, source, err := c.Update()
	if err != nil || !changed || source != "test" {
		t.Fatalf("update: changed=%v source=%q err=%v", changed, source, err)
	}
	got, err := os.ReadFile(c.DataPath())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(blob) {
		t.Fatalf("blob len %d want %d", len(got), len(blob))
	}
	st, err := c.Status()
	if err != nil {
		t.Fatal(err)
	}
	if st.SHA256 != meta.SHA256 || st.CountV4 != meta.CountV4 {
		t.Errorf("status mismatch: %+v", st)
	}
	if st.Source != "test" {
		t.Errorf("source = %q, want test", st.Source)
	}
}

// TestUpdateSkipsWhenUnchanged 验证 sha256 未变时不重复下载。
func TestUpdateSkipsWhenUnchanged(t *testing.T) {
	dir := t.TempDir()
	blob, meta := makeBlob(t, "1.2.3.4/32")

	var dataHits int32
	mux := http.NewServeMux()
	mux.HandleFunc("/meta.json", func(w http.ResponseWriter, r *http.Request) {
		b, _ := json.Marshal(meta)
		_, _ = w.Write(b)
	})
	mux.HandleFunc("/wl_v2.bin", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&dataHits, 1)
		_, _ = w.Write(blob)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	m := Mirror{Name: "t", MetaURL: srv.URL + "/meta.json", DataURL: srv.URL + "/wl_v2.bin"}

	c := NewClient(dir, []Mirror{m})
	if _, _, err := c.Update(); err != nil {
		t.Fatal(err)
	}
	changed, _, err := c.Update()
	if err != nil {
		t.Fatal(err)
	}
	if changed {
		t.Error("内容未变却报告 changed")
	}
	if got := atomic.LoadInt32(&dataHits); got != 1 {
		t.Errorf("数据文件被下载 %d 次，应为 1（sha256 未变时应跳过）", got)
	}
}

// TestFailoverToSecondMirror 是本包的核心性质：首个镜像不可用时
// 必须自动降级到下一个，而不是直接失败。
func TestFailoverToSecondMirror(t *testing.T) {
	dir := t.TempDir()
	blob, meta := makeBlob(t, "9.9.9.9/32")
	bad := Mirror{Name: "dead", MetaURL: "http://127.0.0.1:1/meta.json", DataURL: "http://127.0.0.1:1/wl_v2.bin"}
	good := serve(t, blob, meta, false)

	c := NewClient(dir, []Mirror{bad, good})
	changed, source, err := c.Update()
	if err != nil {
		t.Fatalf("failover 未生效: %v", err)
	}
	if !changed || source != "test" {
		t.Errorf("changed=%v source=%q", changed, source)
	}
	if _, err := os.Stat(c.DataPath()); err != nil {
		t.Fatalf("failover 后未落盘: %v", err)
	}
}

// TestAllMirrorsDownKeepsOldData 覆盖最重要的降级性质：
// 全部镜像都挂掉时，已有文件必须原封不动。
func TestAllMirrorsDownKeepsOldData(t *testing.T) {
	dir := t.TempDir()
	blob, meta := makeBlob(t, "5.5.5.5/32")
	m := serve(t, blob, meta, false)

	c := NewClient(dir, []Mirror{m})
	if _, _, err := c.Update(); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(c.DataPath())
	if err != nil {
		t.Fatal(err)
	}

	// 全部镜像改为不可达
	dead := Mirror{Name: "dead", MetaURL: "http://127.0.0.1:1/meta.json", DataURL: "http://127.0.0.1:1/wl_v2.bin"}
	c2 := NewClient(dir, []Mirror{dead})
	changed, _, err := c2.Update()
	if err == nil {
		t.Error("全部镜像不可用时应当报错")
	}
	if changed {
		t.Error("全部镜像不可用时不应报告 changed")
	}
	after, err := os.ReadFile(c.DataPath())
	if err != nil {
		t.Fatalf("旧数据被破坏: %v", err)
	}
	if string(before) != string(after) {
		t.Error("旧名单内容发生了变化")
	}
}

// TestCorruptDownloadRejected 覆盖 sha256 不匹配时必须拒绝落盘。
func TestCorruptDownloadRejected(t *testing.T) {
	dir := t.TempDir()
	_, meta := makeBlob(t, "7.7.7.7/32")
	bad := []byte("this is not a valid wl_v2 artifact at all")

	mux := http.NewServeMux()
	mux.HandleFunc("/meta.json", func(w http.ResponseWriter, r *http.Request) {
		b, _ := json.Marshal(meta)
		_, _ = w.Write(b)
	})
	mux.HandleFunc("/wl_v2.bin", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(bad)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	m := Mirror{Name: "t", MetaURL: srv.URL + "/meta.json", DataURL: srv.URL + "/wl_v2.bin"}

	c := NewClient(dir, []Mirror{m})
	if _, _, err := c.Update(); err == nil {
		t.Fatal("sha256 不匹配却接受了")
	}
	if _, err := os.Stat(c.DataPath()); err == nil {
		t.Error("坏数据不应落盘")
	}
}

// TestMetaVersionMismatchRejected 防止旧客户端按未知格式解析。
func TestMetaVersionMismatchRejected(t *testing.T) {
	dir := t.TempDir()
	blob, meta := makeBlob(t, "1.1.1.1/32")
	meta.Version = 99
	m := serve(t, blob, meta, false)
	c := NewClient(dir, []Mirror{m})
	if _, _, err := c.Update(); err == nil || !strings.Contains(err.Error(), "unsupported version") {
		t.Errorf("应拒绝未知版本，实际 err=%v", err)
	}
}

// TestTruncatedArtifactRejected 覆盖「能通过 sha256 但内容非法」的情况：
// 例如 CI 端编码有 bug 产出了自洽但解不开的文件。
func TestTruncatedArtifactRejected(t *testing.T) {
	dir := t.TempDir()
	blob, _ := makeBlob(t, "1.1.1.1/32")
	// 截断到一半，但 sha256 按截断后的内容算 —— 模拟上游产出坏文件
	broken := blob[:len(blob)/2]
	sum := sha256.Sum256(broken)
	meta := wlformat.Meta{
		Version: wlformat.Version,
		SHA256:  hex.EncodeToString(sum[:]),
		Size:    int64(len(broken)),
	}
	m := serve(t, broken, meta, false)
	c := NewClient(dir, []Mirror{m})
	if _, _, err := c.Update(); err == nil {
		t.Fatal("截断的制品不应被接受")
	}
	if _, err := os.Stat(c.DataPath()); err == nil {
		t.Error("非法制品不应落盘")
	}
}

func TestWriteFileAtomicLeavesNoTemp(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "x.bin")
	if err := writeFileAtomic(path, []byte("hello")); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "x.bin" {
		t.Errorf("目录应只剩目标文件，实际 %v", entries)
	}
}

func TestStatusMissingFile(t *testing.T) {
	c := NewClient(t.TempDir(), nil)
	if _, err := c.Status(); err == nil {
		t.Error("未下载时 Status 应返回错误")
	}
}

func TestDefaultMirrorsOrder(t *testing.T) {
	if len(DefaultMirrors) < 3 {
		t.Fatalf("应至少配置 3 个镜像，实际 %d", len(DefaultMirrors))
	}
	if DefaultMirrors[0].Name != "cloudsmith" {
		t.Errorf("首选镜像应为 cloudsmith，实际 %s", DefaultMirrors[0].Name)
	}
	for i, m := range DefaultMirrors {
		if !strings.HasPrefix(m.MetaURL, "https://") {
			t.Errorf("镜像 %d 必须是 https: %s", i, m.MetaURL)
		}
	}
}
