package v2

import "github.com/3panel-dev/3panel/core/app/service"

type ApiGroup struct {
	BaseApi
}

var ApiGroupApp = new(ApiGroup)

var (
	authService    = service.NewIAuthService()
	backupService  = service.NewIBackupService()
	settingService = service.NewISettingService()
	logService     = service.NewILogService()
	upgradeService = service.NewIUpgradeService()
	groupService   = service.NewIGroupService()
	commandService = service.NewICommandService()
	scriptService  = service.NewIScriptService()
	nodeService    = service.NewINodeService()
)
