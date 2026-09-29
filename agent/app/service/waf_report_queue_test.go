package service

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// withTempQueueDir 把队列文件重定向到临时目录。
// 用全局变量而非 t.TempDir()，因为 reportQueuePath 依赖 wafHostConfDir。
func withTempQueueDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	old := reportQueueDirOverride
	reportQueueDirOverride = dir
	t.Cleanup(func() { reportQueueDirOverride = old })
	return dir
}

func TestReportQueueRoundTrip(t *testing.T) {
	withTempQueueDir(t)
	ev := []WAFReportEvent{
		{IP: "1.2.3.4", AttackType: "sqli", URL: "/login"},
		{IP: "5.6.7.8", AttackType: "rce", URL: "/cmd"},
	}
	enqueueReports(ev)

	got := peekReports(100)
	if len(got) != 2 {
		t.Fatalf("peek = %d, want 2", len(got))
	}
	if got[0].IP != "1.2.3.4" || got[1].AttackType != "rce" {
		t.Errorf("顺序或内容不对: %+v", got)
	}
	// peek 不应修改队列
	if again := peekReports(100); len(again) != 2 {
		t.Errorf("peek 破坏了队列: %d", len(again))
	}
}

func TestReportQueueDropPartial(t *testing.T) {
	withTempQueueDir(t)
	enqueueReports([]WAFReportEvent{
		{IP: "1.1.1.1", AttackType: "sqli"},
		{IP: "2.2.2.2", AttackType: "sqli"},
		{IP: "3.3.3.3", AttackType: "sqli"},
	})
	// 模拟：前 2 条发送成功，第 3 条失败
	dropReports(2)
	got := peekReports(100)
	if len(got) != 1 || got[0].IP != "3.3.3.3" {
		t.Fatalf("drop 后应剩最后一条，实际 %+v", got)
	}
}

func TestReportQueuePersistsAcrossRestart(t *testing.T) {
	dir := withTempQueueDir(t)
	enqueueReports([]WAFReportEvent{{IP: "9.9.9.9", AttackType: "rce"}})

	// 模拟进程重启：清掉内存状态，只留磁盘文件。
	// 这里实际没有进程内缓存，读取只走文件，因此直接确认文件内容即可。
	path := filepath.Join(dir, reportQueueFile)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("队列未落盘，重启后会丢: %v", err)
	}
	var restored []WAFReportEvent
	if err := json.Unmarshal(raw, &restored); err != nil {
		t.Fatal(err)
	}
	if len(restored) != 1 || restored[0].IP != "9.9.9.9" {
		t.Errorf("重启后读回的内容不对: %+v", restored)
	}

	// 全部发送成功后文件应被删除，不留垃圾
	dropReports(1)
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("队列清空后文件应删除，实际仍存在: %v", err)
	}
}

// TestReportQueueCapped 保证队列不会无限增长把磁盘写满。
func TestReportQueueCapped(t *testing.T) {
	withTempQueueDir(t)
	// 用较小的上限做验证：直接构造超量输入。
	var many []WAFReportEvent
	for i := 0; i < reportQueueMax+500; i++ {
		many = append(many, WAFReportEvent{IP: "1.1.1.1", AttackType: "sqli"})
	}
	enqueueReports(many)
	got := peekReports(reportQueueMax + 1000)
	if len(got) != reportQueueMax {
		t.Errorf("队列应被截断到 %d，实际 %d", reportQueueMax, len(got))
	}
}

// TestReportQueueCorruptedRecovered 保证文件损坏不会让上报功能彻底卡死。
func TestReportQueueCorruptedRecovered(t *testing.T) {
	dir := withTempQueueDir(t)
	path := filepath.Join(dir, reportQueueFile)
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	// 不 panic，且视为空队列
	if got := peekReports(10); len(got) != 0 {
		t.Errorf("损坏文件应视为空，实际 %d 条", len(got))
	}
	// 之后仍能正常入队
	enqueueReports([]WAFReportEvent{{IP: "4.4.4.4", AttackType: "sqli"}})
	if got := peekReports(10); len(got) != 1 {
		t.Errorf("损坏后应能恢复写入，实际 %d 条", len(got))
	}
}

// TestReportQueueConcurrent 确认并发入队不丢事件。
// IngestLogs 每分钟一次，SyncReports 每天一次，理论上不该重叠，
// 但进程刚启动时两者确实可能并发。
func TestReportQueueConcurrent(t *testing.T) {
	withTempQueueDir(t)
	var wg sync.WaitGroup
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			enqueueReports([]WAFReportEvent{{IP: "1.1.1.1", AttackType: "sqli"}})
		}(w)
	}
	wg.Wait()
	if got := peekReports(1000); len(got) != 8 {
		t.Errorf("并发入队应保留 8 条，实际 %d", len(got))
	}
}
