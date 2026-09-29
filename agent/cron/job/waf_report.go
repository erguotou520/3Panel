package job

import (
	"github.com/3panel-dev/3panel/agent/app/service"
	"github.com/3panel-dev/3panel/agent/global"
)

type wafReport struct{}

func NewWAFReportJob() *wafReport {
	return &wafReport{}
}

// Run 每日发送待上报的攻击事件。
//
// 队列由 IngestLogs 逐轮追加并落盘，进程重启不丢；这里只负责发送。
// 失败即停止并保留队列，下一轮重试 —— 重复发送无害，
// Worker 按 (panelId, ip, attackType) 去重。
func (w *wafReport) Run() {
	svc := service.NewIWAFService()
	svc.SyncReports()
	global.LOG.Debug("waf report scheduled task has completed")
}
