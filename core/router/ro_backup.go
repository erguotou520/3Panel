package router

import (
	v2 "github.com/3panel-dev/3panel/core/app/api/v2"
	"github.com/3panel-dev/3panel/core/middleware"
	"github.com/gin-gonic/gin"
)

type BackupRouter struct{}

func (s *BackupRouter) InitRouter(Router *gin.RouterGroup) {
	backupRouter := Router.Group("backups").
		Use(middleware.SessionAuth()).
		Use(middleware.PasswordExpired())
	baseApi := v2.ApiGroupApp.BaseApi
	{
		backupRouter.GET("/client/:clientType", baseApi.LoadBackupClientInfo)
		backupRouter.POST("/refresh/token", baseApi.RefreshToken)
		backupRouter.POST("", baseApi.CreateBackup)
		backupRouter.POST("/del", baseApi.DeleteBackup)
		backupRouter.POST("/update", baseApi.UpdateBackup)
	}
}
