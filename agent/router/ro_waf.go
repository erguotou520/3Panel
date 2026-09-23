package router

import (
	v2 "github.com/3panel-dev/3panel/agent/app/api/v2"
	"github.com/gin-gonic/gin"
)

type WAFRouter struct {
}

func (a *WAFRouter) InitRouter(Router *gin.RouterGroup) {
	wafRouter := Router.Group("waf")

	baseApi := v2.ApiGroupApp.BaseApi
	{
		wafRouter.POST("/website/op", baseApi.OperateWebsiteWAF)
		wafRouter.GET("/cc", baseApi.GetWAFCCConfig)
		wafRouter.POST("/cc/update", baseApi.UpdateWAFCCConfig)
		wafRouter.GET("/webhook", baseApi.GetWAFWebhookSetting)
		wafRouter.POST("/webhook/update", baseApi.UpdateWAFWebhookSetting)
		wafRouter.GET("/option", baseApi.GetWAFOption)
		wafRouter.POST("/option/update", baseApi.UpdateWAFOption)

		wafRouter.POST("/rules/search", baseApi.SearchWAFRules)
		wafRouter.POST("/rules", baseApi.CreateWAFRule)
		wafRouter.POST("/rules/update", baseApi.UpdateWAFRule)
		wafRouter.DELETE("/rules/:id", baseApi.DeleteWAFRule)

		wafRouter.POST("/logs/search", baseApi.SearchWAFLogs)
		wafRouter.POST("/logs/stat", baseApi.StatWAFLogs)
		wafRouter.POST("/logs/export", baseApi.ExportWAFLogs)
		wafRouter.POST("/logs/rule", baseApi.CreateRuleFromWAFLog)
	}
}
