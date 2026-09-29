package service

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"

	"github.com/3panel-dev/3panel/agent/global"
	wafutils "github.com/3panel-dev/3panel/agent/utils/waf"
)

// 攻击上报队列。
//
// 为什么不直接发 HTTP：
//  1. 隐私 —— 每次拦截实时上报，攻击流量对 Worker 持续可见；
//     攒到定时批量，离散后可见性大幅降低。
//  2. 性能 —— 一次日志轮转可能积累上千条，串行发送会长时间占用
//     goroutine，最坏 50 条 × 10s 超时 = 500s。
//
// 为什么不放在内存：
//  面板重启/升级是常态，内存队列会丢样本。磁盘文件天然跨重启存活。
//  重复发送无害 —— Worker 按 (panelId, ip, attackType) 去重。

const (
	// reportQueueMax 为队列上限。超出时丢最旧的：宁可丢样本，
	// 也不能让队列无限增长把磁盘吃满。正常部署每天拦不到这个量。
	reportQueueMax = 20000
	// reportQueueFile 位于 WAF 数据目录下，与 lua 产物同目录。
	reportQueueFile = "report_queue.json"
)

var (
	reportQueueMu sync.Mutex
	// reportQueueDirOverride 供测试重定向队列位置；生产恒为空。
	reportQueueDirOverride string
)

func reportQueuePath() string {
	if reportQueueDirOverride != "" {
		return filepath.Join(reportQueueDirOverride, reportQueueFile)
	}
	confDir, err := wafHostConfDir()
	if err != nil {
		return ""
	}
	dir := wafutils.HostWAFDir(confDir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return ""
	}
	return filepath.Join(dir, reportQueueFile)
}

// enqueueReports 追加事件并落盘。
//
// 整个读-改-写过程持锁，避免 IngestLogs（每分钟）与 SyncReports
// （每天）并发时互相覆盖。代价是同一瞬间只有一个进程内调用方，
// 对本场景完全够用。
func enqueueReports(events []WAFReportEvent) {
	if len(events) == 0 {
		return
	}
	path := reportQueuePath()
	if path == "" {
		return
	}
	reportQueueMu.Lock()
	defer reportQueueMu.Unlock()

	queue := readReportQueue(path)
	queue = append(queue, events...)
	if len(queue) > reportQueueMax {
		// 丢最旧的，保住新的
		queue = queue[len(queue)-reportQueueMax:]
	}
	writeReportQueue(path, queue)
}

// peekReports 返回待发送队列的快照，不修改文件。
func peekReports(limit int) []WAFReportEvent {
	path := reportQueuePath()
	if path == "" {
		return nil
	}
	reportQueueMu.Lock()
	defer reportQueueMu.Unlock()
	q := readReportQueue(path)
	if len(q) > limit {
		return q[:limit]
	}
	return q
}

// dropReports 丢弃前 n 条（已确认发送成功的）。
func dropReports(n int) {
	if n <= 0 {
		return
	}
	path := reportQueuePath()
	if path == "" {
		return
	}
	reportQueueMu.Lock()
	defer reportQueueMu.Unlock()
	q := readReportQueue(path)
	if n >= len(q) {
		q = nil
	} else {
		q = q[n:]
	}
	writeReportQueue(path, q)
}

// reportQueueLog 输出队列相关告警。
// global.LOG 在极早期（测试、启动未完成）可能为 nil，
// 直接调 Warnf 会 panic，而上报本就是可选旁路，不值得因此中断。
func reportQueueLog(format string, args ...any) {
	if global.LOG != nil {
		global.LOG.Warnf(format, args...)
	}
}

// readReportQueue 必须在持有 reportQueueMu 时调用。
func readReportQueue(path string) []WAFReportEvent {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var q []WAFReportEvent
	if err := json.Unmarshal(raw, &q); err != nil {
		// 文件损坏时丢弃而不是让上报彻底卡死：上报是可选旁路，
		// 为它把整个功能锁死不划算。
		reportQueueLog("[waf] report queue corrupted, dropping: %v", err)
		return nil
	}
	return q
}

func writeReportQueue(path string, q []WAFReportEvent) {
	if len(q) == 0 {
		_ = os.Remove(path)
		return
	}
	b, err := json.Marshal(q)
	if err != nil {
		reportQueueLog("[waf] marshal report queue failed: %v", err)
		return
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		reportQueueLog("[waf] write report queue failed: %v", err)
		return
	}
	// 先写临时文件再 rename：进程若在写入中途被杀，
	// 下次启动读到的是完整的旧文件而不是半截 JSON。
	if err := os.Rename(tmp, path); err != nil {
		reportQueueLog("[waf] rotate report queue failed: %v", err)
		_ = os.Remove(tmp)
	}
}
