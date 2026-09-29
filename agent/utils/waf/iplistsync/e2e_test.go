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
	"testing"
	"time"

	"github.com/3panel-dev/3panel/agent/utils/waf/wlformat"
)

// fakeClock 让时间可控，避免测试依赖真实时钟。
type fakeClock struct{ t time.Time }

func (c *fakeClock) Now() time.Time { return c.t }

// TestEndToEndAgainstRealArtifact 用 wlbuild 产出的真实制品走完整链路：
// 拉取 -> 校验 -> 落盘 -> 用 wlformat 解回来验证内容正确。
//
// 这是订阅链路的最后一块拼图：前面各测试都用合成数据，
// 这里确认「Go 侧能正确处理真实世界 40 万字节的制品」。
func TestEndToEndAgainstRealArtifact(t *testing.T) {
	artifact := findArtifact(t)
	if artifact == "" {
		t.Skip("未找到真实制品，跳过（先运行 wlbuild 生成）")
	}
	blob, err := os.ReadFile(artifact)
	if err != nil {
		t.Fatal(err)
	}

	// 本地起一个镜像，暴露 meta.json 与 wl_v2.bin。
	meta := wlformatMetaFor(blob)
	mux := http.NewServeMux()
	mux.HandleFunc("/meta.json", func(w http.ResponseWriter, r *http.Request) {
		b, _ := json.Marshal(meta)
		w.Header().Set("content-type", "application/json")
		_, _ = w.Write(b)
	})
	mux.HandleFunc("/wl_v2.bin", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(blob)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	dir := t.TempDir()
	m := Mirror{Name: "local", MetaURL: srv.URL + "/meta.json", DataURL: srv.URL + "/wl_v2.bin"}
	c := NewClient(dir, []Mirror{m})
	c.now = (&fakeClock{t: time.Unix(1759200000, 0)}).Now

	changed, source, err := c.Update()
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if !changed || source != "local" {
		t.Fatalf("changed=%v source=%q", changed, source)
	}

	// 落盘内容必须与源字节一致
	got, err := os.ReadFile(c.DataPath())
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(blob) {
		t.Fatalf("落盘内容与源不一致：%d vs %d bytes", len(got), len(blob))
	}

	// 关键：解码回来的区间必须严格升序且互不重叠。
	// 这是 Lua 侧二分查找的前提，不满足会静默失效（不报错，只是查不到）。
	v4, v6, err := decode(got)
	if err != nil {
		t.Fatalf("解码真实制品失败: %v", err)
	}
	if len(v4) == 0 {
		t.Fatal("真实制品解码后为空")
	}
	for i := 1; i < len(v4); i++ {
		if v4[i].Addr().Compare(v4[i-1].Addr()) <= 0 {
			t.Fatalf("v4[%d] 未严格升序: %s then %s", i, v4[i-1], v4[i])
		}
		if v4[i-1].Contains(v4[i].Addr()) {
			t.Fatalf("v4[%d] 与前一条重叠: %s / %s", i, v4[i-1], v4[i])
		}
	}
	t.Logf("真实制品 %d bytes -> v4=%d v6=%d，顺序与不重叠校验通过", len(blob), len(v4), len(v6))
}

// findArtifact 查找 wlbuild 的输出，找不到返回空串。
func findArtifact(t *testing.T) string {
	t.Helper()
	for _, p := range []string{
		filepath.Join("testdata", "wl_v2.bin"),
		"/tmp/wl_final.bin",
		"/tmp/wl3.bin",
	} {
		if st, err := os.Stat(p); err == nil && st.Size() > 0 {
			return p
		}
	}
	return ""
}

// TestUpdateTwiceIsStable 确认重复更新不会因为「文件已存在」而出错，
// 且第二次会正确判定为未变化。
func TestUpdateTwiceIsStable(t *testing.T) {
	blob, meta := makeBlob(t, "10.0.0.0/8", "192.168.0.0/16")
	mux := http.NewServeMux()
	mux.HandleFunc("/meta.json", func(w http.ResponseWriter, r *http.Request) {
		b, _ := json.Marshal(meta)
		_, _ = w.Write(b)
	})
	mux.HandleFunc("/wl_v2.bin", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(blob)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	dir := t.TempDir()
	c := NewClient(dir, []Mirror{{Name: "l", MetaURL: srv.URL + "/meta.json", DataURL: srv.URL + "/wl_v2.bin"}})
	for i := 0; i < 3; i++ {
		if _, _, err := c.Update(); err != nil {
			t.Fatalf("第 %d 次更新失败: %v", i+1, err)
		}
	}
	// 第三次应是 unchanged
	changed, _, err := c.Update()
	if err != nil {
		t.Fatal(err)
	}
	if changed {
		t.Error("内容未变却报告 changed")
	}
}

// TestLargeArtifactRoundTrip 覆盖真实规模下的解码耗时与体积，
// 防止将来改动让制品膨胀到不可接受。
func TestLargeArtifactRoundTrip(t *testing.T) {
	artifact := findArtifact(t)
	if artifact == "" {
		t.Skip("未找到真实制品")
	}
	blob, err := os.ReadFile(artifact)
	if err != nil {
		t.Fatal(err)
	}
	if len(blob) > 2<<20 {
		t.Errorf("制品 %d bytes 超过 2MB 预算", len(blob))
	}
	v4, _, err := decode(blob)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%d bytes -> %d ranges (%.1f bytes/range)", len(blob), len(v4), float64(len(blob))/float64(len(v4)))
}

// wlformatMetaFor 为给定 blob 构造配套的 meta。
func wlformatMetaFor(blob []byte) wlformat.Meta {
	v4, v6, err := wlformat.Decode(blob)
	if err != nil {
		panic(err)
	}
	return wlformat.Meta{
		Version:     wlformat.Version,
		GeneratedAt: time.Unix(1759200000, 0).UTC().Format(time.RFC3339),
		SHA256:      hexOf(blob),
		Size:        int64(len(blob)),
		CountV4:     len(v4),
		CountV6:     len(v6),
		Mirrors:     []string{"local"},
	}
}

func decode(blob []byte) ([]netip.Prefix, []netip.Prefix, error) {
	return wlformat.Decode(blob)
}

func hexOf(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
