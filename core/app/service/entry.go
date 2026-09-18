package service

import "github.com/3panel-dev/3panel/core/app/repo"

var (
	commandRepo    = repo.NewICommandRepo()
	settingRepo    = repo.NewISettingRepo()
	backupRepo     = repo.NewIBackupRepo()
	logRepo        = repo.NewILogRepo()
	groupRepo      = repo.NewIGroupRepo()
	upgradeLogRepo = repo.NewIUpgradeLogRepo()

	agentRepo  = repo.NewIAgentRepo()
	scriptRepo = repo.NewIScriptRepo()

	nodeRepo      = repo.NewINodeRepo()
	nodeTokenRepo = repo.NewINodeTokenRepo()
)
