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
	// IP 黑名单订阅：内部按配置间隔与随机抖动决定是否真的拉取，
	// 这里每分钟调用一次即可。
	svc.SyncIPListIfDue()
	global.LOG.Debug("waf scheduled task has completed")
}
