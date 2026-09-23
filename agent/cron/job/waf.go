package job

import (
	"github.com/3panel-dev/3panel/agent/app/service"
	"github.com/3panel-dev/3panel/agent/global"
)

type waf struct{}

func NewWAFJob() *waf {
	return &waf{}
}

// Run 周期任务：数据面日志入库 + 过期名单清理 + 过期日志清理
func (w *waf) Run() {
	svc := service.NewIWAFService()
	svc.IngestLogs()
	svc.CleanExpiredRules()
	svc.CleanExpiredLogs()
	global.LOG.Debug("waf scheduled task has completed")
}
