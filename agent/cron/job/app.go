package job

import (
	"github.com/3panel-dev/3panel/agent/app/service"
	"github.com/3panel-dev/3panel/agent/global"
)

type app struct{}

func NewAppStoreJob() *app {
	return &app{}
}

func (a *app) Run() {
	global.LOG.Info("AppStore scheduled task in progress ...")
	if err := service.NewIAppService().SyncAppListFromRemote(""); err != nil {
		global.LOG.Errorf("AppStore sync failed %s", err.Error())
	}
	global.LOG.Info("AppStore scheduled task has completed")
}
