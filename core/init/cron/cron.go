package cron

import (
	"time"

	"github.com/3panel-dev/3panel/core/app/service"
	"github.com/3panel-dev/3panel/core/global"
	"github.com/3panel-dev/3panel/core/init/cron/job"
	"github.com/3panel-dev/3panel/core/utils/common"
	"github.com/robfig/cron/v3"
)

func Init() {
	nyc, _ := time.LoadLocation(common.LoadTimeZoneByCmd())
	global.Cron = cron.New(cron.WithLocation(nyc), cron.WithChain(cron.Recover(cron.DefaultLogger)), cron.WithChain(cron.DelayIfStillRunning(cron.DefaultLogger)))

	if _, err := global.Cron.AddJob("0 3 */31 * *", job.NewBackupJob()); err != nil {
		global.LOG.Errorf("[core] can not add backup token refresh corn job: %s", err.Error())
	}

	service.StartSync()
	global.Cron.Start()
}
