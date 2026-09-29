// Command wlbuild 聚合多个公开 IP 黑名单源，产出一个压缩二进制制品与元信息。
//
// 聚合放在 CI 侧而不是面板侧，是因为用户所在网络未必能直连 raw.githubusercontent.com
// 等源站；与其让每个实例各自碰运气，不如 CI 产出单一制品并多镜像分发。
//
// 用法：
//
//	wlbuild -out dist/wl_v2.bin -meta dist/meta.json
//	wlbuild -out dist/wl_v2.bin -src-dir /tmp/feed   # 从本地文件读，便于离线复现
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/3panel-dev/3panel/agent/utils/waf/wlformat"
)

// source 描述一个上游源。Local/JSONPool 非空时从文件读，否则走 HTTP。
type source struct {
	Name string
	URL  string
	// Local 是纯文本列表的本地路径（配合 -src-dir 指定的目录）。
	Local string
	// JSONPool 是 JSON 字符串数组的本地路径，格式为 ["1.2.3.4", ...]。
	// 为空时回落到 -self-pool 指定的路径。
	JSONPool string
	// Country 预留：blackip 支持按 ISO 3166-1 alpha-2 筛选。
	Country string
}

// 这些源都经过实测：格式混合（有的给单 IP、有的给 CIDR、有的带表头注释），
// 解析统一交给 wlformat.ParseList 处理。
var sources = []source{
	{Name: "cins", URL: "https://cinsscore.com/list/ci-badguys.txt"},
	{Name: "blocklist-de", URL: "https://lists.blocklist.de/lists/all.txt"},
	{Name: "ipsum-l3", URL: "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt"},
	{Name: "spamhaus-drop", URL: "https://www.spamhaus.org/drop/drop.txt"},
	{Name: "emerging-threats", URL: "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"},
	// 国内源：Aabyss-Team/Ban-Hacker-IP-Plan（GPL-3.0），按入侵 / DDoS 两类分文件
	{
		Name: "aabyss-intrusion",
		URL:  "https://raw.githubusercontent.com/Aabyss-Team/Ban-Hacker-IP-Plan/main/Intrusion_Attacks/IPv4_恶意地址.txt",
	},
	{
		Name: "aabyss-ddos",
		URL:  "https://raw.githubusercontent.com/Aabyss-Team/Ban-Hacker-IP-Plan/main/DDoS_CC_Attack/IPv4_恶意地址.txt",
	},
	{
		Name: "aabyss-ddos-cidr",
		URL:  "https://raw.githubusercontent.com/Aabyss-Team/Ban-Hacker-IP-Plan/main/DDoS_CC_Attack/IPv4_恶意地址段.txt",
	},
	// 中文黑名单 IP 库，有公开 API 与 limit 上限
	{Name: "blackip", URL: "https://blackip.scdn.io/api/public.php?ip_version=v4&limit=100000"},
	// 自维护池：长亭（Chaitin）导出的国内威胁情报，实测 5000 条里约 4778 条
	// 为其它源所无。它是 JSON 数组而非纯文本，由 JSONPool 标记并走单独解析。
	// 路径由 -self-pool 指定，默认为仓库内的 scripts/ip_group.json。
	{Name: "ip-group", JSONPool: "scripts/ip_group.json"},
}

var mirrors = []string{
	"https://generic.cloudsmith.io/3panel/3panel/waf-iplist/latest",
	"https://proxy.erguotou.me/https://raw.githubusercontent.com/3panel-dev/3panel/waf-iplist/main/dist",
	"https://raw.githubusercontent.com/3panel-dev/3panel/waf-iplist/main/dist",
}

func main() {
	var (
		outPath  = flag.String("out", "dist/wl_v2.bin", "二进制输出路径")
		metaPath = flag.String("meta", "dist/meta.json", "元信息输出路径")
		srcDir   = flag.String("src-dir", "", "从该目录读 <name>.txt 而非联网；用于离线复现与对拍")
		timeout  = flag.Duration("timeout", 90*time.Second, "单个源的超时")
		selfPool = flag.String("self-pool", "scripts/ip_group.json", "自维护 IP 池（JSON 数组）路径；缺失或为空则整轮失败")
	)
	flag.Parse()

	client := &http.Client{Timeout: *timeout, Transport: &http.Transport{
		MaxIdleConnsPerHost: 4,
	}}

	var perSource [][]netip.Prefix
	var metaSources []wlformat.MetaSource
	totalSkipped := 0
	totalRaw := 0

	for _, s := range sources {
		nets, skipped, err := fetchSource(client, s, *srcDir, *selfPool)
		ms := wlformat.MetaSource{Name: s.Name, URL: s.URL, Entries: len(nets)}
		if err != nil {
			// 自维护池在仓库内、随版本走，缺失或为空属于构建问题而非上游故障。
			// 其它远端源允许降级（记录 err 后继续），这里必须让整轮失败 ——
			// 否则 CI 一次静默少掉几千条 IP，产物照发不误，没人发现得了。
			if s.JSONPool != "" {
				fatalf("self pool %s: %v", s.Name, err)
			}
			ms.Err = err.Error()
			fmt.Fprintf(os.Stderr, "  [warn] %-18s %v\n", s.Name, err)
		} else {
			fmt.Fprintf(os.Stderr, "  [ok]   %-18s %6d entries (%d skipped)\n", s.Name, len(nets), skipped)
		}
		perSource = append(perSource, nets)
		metaSources = append(metaSources, ms)
		totalSkipped += skipped
		totalRaw += len(nets)
	}

	if totalRaw == 0 {
		fatalf("all sources failed, refusing to publish an empty blocklist")
	}

	v4, v6, stats := wlformat.Summarize(perSource, totalSkipped)
	fmt.Fprintf(os.Stderr, "merged: raw=%d -> v4=%d v6=%d (collapsed %.2fx)\n",
		stats.RawEntries, stats.V4, stats.V6,
		float64(stats.RawEntries)/float64(max(stats.V4+stats.V6, 1)))

	blob, err := wlformat.Encode(v4, v6)
	if err != nil {
		fatalf("encode: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(*outPath), 0o755); err != nil {
		fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(*outPath, blob, 0o644); err != nil {
		fatalf("write %s: %v", *outPath, err)
	}

	sum := sha256.Sum256(blob)
	meta := wlformat.Meta{
		Version:     wlformat.Version,
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		SHA256:      hex.EncodeToString(sum[:]),
		Size:        int64(len(blob)),
		CountV4:     len(v4),
		CountV6:     len(v6),
		Sources:     metaSources,
		Mirrors:     mirrors,
	}
	mb, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		fatalf("marshal meta: %v", err)
	}
	if err := os.WriteFile(*metaPath, append(mb, '\n'), 0o644); err != nil {
		fatalf("write %s: %v", *metaPath, err)
	}

	fmt.Fprintf(os.Stderr, "wrote %s (%d bytes, %.1f KB) + %s\n",
		*outPath, len(blob), float64(len(blob))/1024, *metaPath)

	// 解回来做一次自检：编码/解码不对称会让 Lua 侧二分静默失效。
	rv4, rv6, err := wlformat.Decode(blob)
	if err != nil {
		fatalf("self-check decode: %v", err)
	}
	if len(rv4) != len(v4) || len(rv6) != len(v6) {
		fatalf("self-check mismatch: got (%d,%d) want (%d,%d)", len(rv4), len(rv6), len(v4), len(v6))
	}
	for i := 1; i < len(rv4); i++ {
		if rv4[i].Addr().Compare(rv4[i-1].Addr()) <= 0 {
			fatalf("self-check: v4[%d] not ascending", i)
		}
		if rv4[i-1].Contains(rv4[i].Addr()) {
			fatalf("self-check: v4[%d] overlaps v4[%d]", i, i-1)
		}
	}
	fmt.Fprintf(os.Stderr, "self-check ok: strictly ascending, non-overlapping\n")
}

func fetchSource(client *http.Client, s source, srcDir, selfPool string) ([]netip.Prefix, int, error) {
	if s.JSONPool != "" {
		return fetchJSONPool(selfPool)
	}
	if srcDir != "" {
		f, err := os.Open(filepath.Join(srcDir, s.Name+".txt"))
		if err != nil {
			return nil, 0, err
		}
		defer f.Close()
		nets, skipped, err := wlformat.ParseList(f)
		return nets, skipped, err
	}
	req, err := http.NewRequest(http.MethodGet, s.URL, nil)
	if err != nil {
		return nil, 0, err
	}
	// 部分站点（abuse.ch、blackip）对空 UA 直接拒绝。
	req.Header.Set("User-Agent", "3panel-waf-iplist/2 (+https://github.com/3panel-dev/3panel)")
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, 0, fmt.Errorf("http %d", resp.StatusCode)
	}
	// 限制读取体积，避免被重定向到大文件时把内存吃满。
	nets, skipped, err := wlformat.ParseList(io.LimitReader(resp.Body, 64<<20))
	return nets, skipped, err
}

// fetchJSONPool 读取 JSON 字符串数组形式的 IP 池。
// 元素可以是裸 IP 或 CIDR；非字符串与解析失败的项计入 skipped。
func fetchJSONPool(path string) ([]netip.Prefix, int, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		// 池子缺失不能静默跳过：CI 里若因 checkout 漏文件而少几千条，
		// 产物照样能发布，只是默默少了一批 IP，很难被发现。
		// 这里让整轮失败，由 workflow 重跑或告警。
		return nil, 0, fmt.Errorf("read self pool: %w", err)
	}
	var items []any
	if err := json.Unmarshal(raw, &items); err != nil {
		return nil, 0, fmt.Errorf("parse %s: %w", path, err)
	}
	if len(items) == 0 {
		// 空数组同样可疑（导出脚本跑飞、文件被清空），按失败处理。
		return nil, 0, fmt.Errorf("%s is empty", path)
	}
	var nets []netip.Prefix
	skipped := 0
	for _, it := range items {
		s, ok := it.(string)
		if !ok {
			skipped++
			continue
		}
		s = strings.TrimSpace(s)
		if s == "" {
			skipped++
			continue
		}
		if strings.Contains(s, "/") {
			p, err := netip.ParsePrefix(s)
			if err != nil {
				skipped++
				continue
			}
			nets = append(nets, p.Masked())
			continue
		}
		a, err := netip.ParseAddr(s)
		if err != nil {
			skipped++
			continue
		}
		nets = append(nets, netip.PrefixFrom(a, a.BitLen()))
	}
	return nets, skipped, nil
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "wlbuild: "+format+"\n", args...)
	os.Exit(1)
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
