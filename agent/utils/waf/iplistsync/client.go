// Package iplist 实现 WAF IP 黑名单订阅的客户端侧：多镜像 failover 下载、
// meta 比对、完整性校验与原子落盘。
//
// 为什么不在面板侧直接抓各上游源：用户所在网络未必能直连
// raw.githubusercontent.com 等源站（中国大陆尤其如此），且各源格式不统一、
// 会随时变更。改为由 CI 聚合成单一制品，用户只从固定镜像拉，
// 拉不到就继续用旧数据，绝不降级成空名单。
package iplistsync

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/3panel-dev/3panel/agent/utils/waf/wlformat"
)

// Mirror 是一个候选下载地址。同一制品会在多个镜像上发布，
// 客户端按顺序尝试直到有一个成功。
type Mirror struct {
	// Name 仅用于日志定位。
	Name string
	// MetaURL 指向 meta.json。
	MetaURL string
	// DataURL 指向二进制区间表。
	DataURL string
}

// DefaultMirrors 是内置的三个镜像，顺序即优先级：
// 自建对象存储（最快最稳）→ 带 URL 前缀的代理（绕过 raw 不可达）→ 原生 raw。
//
// 刻意不产出 .gz：meta.json 里经过验证的代理不透传 Content-Encoding，
// 预压缩包经代理后会被错误解码。398KB 的裸包对 12 小时一次的拉取完全无压力。
var DefaultMirrors = []Mirror{
	{
		Name:    "cloudsmith",
		MetaURL: "https://generic.cloudsmith.io/3panel/3panel/waf-iplist/latest/meta.json",
		DataURL: "https://generic.cloudsmith.io/3panel/3panel/waf-iplist/latest/wl_v2.bin",
	},
	{
		Name:    "proxy",
		MetaURL: "https://proxy.erguotou.me/https://raw.githubusercontent.com/3panel-dev/3panel/waf-iplist/main/dist/meta.json",
		DataURL: "https://proxy.erguotou.me/https://raw.githubusercontent.com/3panel-dev/3panel/waf-iplist/main/dist/wl_v2.bin",
	},
	{
		Name:    "github",
		MetaURL: "https://raw.githubusercontent.com/3panel-dev/3panel/waf-iplist/main/dist/meta.json",
		DataURL: "https://raw.githubusercontent.com/3panel-dev/3panel/waf-iplist/main/dist/wl_v2.bin",
	},
}

// Status 描述当前生效名单的来源与新鲜度，供前端展示。
type Status struct {
	// SHA256 是当前落盘文件的摘要。
	SHA256 string `json:"sha256"`
	// GeneratedAt 是该制品的生成时间。
	GeneratedAt string `json:"generatedAt"`
	// CountV4 / CountV6 是区间数。
	CountV4 int `json:"countV4"`
	CountV6 int `json:"countV6"`
	// Source 记录最后一次成功下载所用的镜像名。
	Source string `json:"source"`
	// UpdatedAt 是本地最后一次成功更新的时间。
	UpdatedAt string `json:"updatedAt"`
	// Size 是文件字节数。
	Size int64 `json:"size"`
}

// metaFile 是落盘在数据目录旁的小状态文件，用于面板重启后仍能展示新鲜度。
const metaFile = "meta.json"

const dataFile = "wl_v2.bin"

// Client 负责拉取与落盘。dir 为数据面挂载目录（宿主机上 OpenResty 可见）。
type Client struct {
	dir     string
	mirrors []Mirror
	http    *http.Client
	now     func() time.Time
}

// NewClient 创建客户端。mirrors 为空时使用 DefaultMirrors。
func NewClient(dir string, mirrors []Mirror) *Client {
	if len(mirrors) == 0 {
		mirrors = DefaultMirrors
	}
	return &Client{
		dir:     dir,
		mirrors: mirrors,
		http:    &http.Client{Timeout: 120 * time.Second},
		now:     time.Now,
	}
}

// DataPath 返回二进制文件路径。
func (c *Client) DataPath() string { return filepath.Join(c.dir, dataFile) }

func (c *Client) metaPath() string { return filepath.Join(c.dir, metaFile) }

// Update 尝试拉取最新制品。
//
// 流程：逐个镜像取 meta，比对本地 sha256；未变化则不下载数据文件。
// 有变化才下载 wl_v2.bin，校验 sha256 后原子替换。
//
// 任一环节失败都不会破坏现有数据：只有在新文件完整落盘后才 rename，
// 且 rename 前解析校验必须通过。返回的 err 仅用于日志与状态展示。
func (c *Client) Update() (changed bool, source string, err error) {
	local, _ := c.Status()
	var firstErr error
	for _, m := range c.mirrors {
		meta, err := c.fetchMeta(m)
		if err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("%s: %w", m.Name, err)
			}
			continue
		}
		if local.SHA256 != "" && local.SHA256 == meta.SHA256 {
			// 内容未变，跳过下载。镜像之间内容本应一致，
			// 若这里命中说明该镜像与本地同步，是正常路径。
			return false, m.Name, nil
		}
		if err := c.download(m, meta); err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("%s: %w", m.Name, err)
			}
			continue
		}
		return true, m.Name, nil
	}
	if firstErr == nil {
		firstErr = fmt.Errorf("no mirror available")
	}
	return false, "", firstErr
}

func (c *Client) fetchMeta(m Mirror) (wlformat.Meta, error) {
	var meta wlformat.Meta
	req, err := http.NewRequest(http.MethodGet, m.MetaURL, nil)
	if err != nil {
		return meta, err
	}
	req.Header.Set("User-Agent", "3panel-waf-iplist/2")
	resp, err := c.http.Do(req)
	if err != nil {
		return meta, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return meta, fmt.Errorf("meta http %d", resp.StatusCode)
	}
	// meta 很小，限制 1MB 防止被重定向到大文件。
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&meta); err != nil {
		return meta, err
	}
	if meta.Version != wlformat.Version {
		return meta, fmt.Errorf("unsupported version %d", meta.Version)
	}
	if meta.SHA256 == "" {
		return meta, fmt.Errorf("meta missing sha256")
	}
	return meta, nil
}

func (c *Client) download(m Mirror, meta wlformat.Meta) error {
	req, err := http.NewRequest(http.MethodGet, m.DataURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "3panel-waf-iplist/2")
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("data http %d", resp.StatusCode)
	}
	// 制品当前约 400KB，留 8 倍余量；超出说明服务端出了问题，直接失败。
	blob, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return err
	}
	sum := hex.EncodeToString(sha256Sum(blob))
	if !equalFold(sum, meta.SHA256) {
		return fmt.Errorf("sha256 mismatch: got %s want %s", sum, meta.SHA256)
	}
	// 解码校验：编码/解码不对称会让 Lua 侧二分静默失效，
	// 在这里挡住比让数据面拿着坏名单跑要好。
	if _, _, err := wlformat.Decode(blob); err != nil {
		return fmt.Errorf("decode check: %w", err)
	}
	if err := os.MkdirAll(c.dir, 0o755); err != nil {
		return err
	}
	if err := writeFileAtomic(c.DataPath(), blob); err != nil {
		return err
	}
	meta.Source = m.Name
	mb, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(c.metaPath(), append(mb, '\n'))
}

func sha256Sum(b []byte) []byte {
	s := sha256.Sum256(b)
	return s[:]
}

func equalFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if 'A' <= ca && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if 'A' <= cb && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}

// writeFileAtomic 先写临时文件再 rename。
// 数据面每 5 秒读一次该文件，直接覆盖会读到写了一半的内容。
func writeFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // rename 成功后这里是 no-op
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpName, 0o644); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

// Status 读取当前落盘状态。文件不存在时返回零值与错误。
func (c *Client) Status() (Status, error) {
	var st Status
	mb, err := os.ReadFile(c.metaPath())
	if err != nil {
		return st, err
	}
	var meta wlformat.Meta
	if err := json.Unmarshal(mb, &meta); err != nil {
		return st, err
	}
	st = Status{
		SHA256:      meta.SHA256,
		GeneratedAt: meta.GeneratedAt,
		CountV4:     meta.CountV4,
		CountV6:     meta.CountV6,
		Source:      meta.Source,
		UpdatedAt:   meta.GeneratedAt,
		Size:        meta.Size,
	}
	return st, nil
}
