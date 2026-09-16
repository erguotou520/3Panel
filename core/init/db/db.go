package db

import (
	"path"

	"github.com/3panel-dev/3panel/core/global"
	"github.com/3panel-dev/3panel/core/utils/common"
)

func Init() {
	global.DB = common.LoadDBConnByPath(path.Join(global.CONF.Base.InstallDir, "3panel/db/core.db"), "core")
	global.TaskDB = common.LoadDBConnByPath(path.Join(global.CONF.Base.InstallDir, "3panel/db/task.db"), "task")
	global.AgentDB = common.LoadDBConnByPath(path.Join(global.CONF.Base.InstallDir, "3panel/db/agent.db"), "agent")
	global.AlertDB = common.LoadDBConnByPath(path.Join(global.CONF.Base.InstallDir, "3panel/db/alert.db"), "alert")
}
