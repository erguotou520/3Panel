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
		wafRouter.POST("/webhook/test", baseApi.TestWAFWebhook)
		wafRouter.GET("/option", baseApi.GetWAFOption)
		wafRouter.POST("/option/update", baseApi.UpdateWAFOption)

		wafRouter.GET("/iplist", baseApi.GetWAFIPListSetting)
		wafRouter.POST("/iplist/update", baseApi.UpdateWAFIPListSetting)
		wafRouter.POST("/iplist/sync", baseApi.SyncWAFIPList)

		wafRouter.POST("/rules/search", baseApi.SearchWAFRules)
		wafRouter.POST("/rules", baseApi.CreateWAFRule)
		wafRouter.POST("/rules/update", baseApi.UpdateWAFRule)
		wafRouter.POST("/rules/reorder", baseApi.ReorderWAFRules)

		// 地理数据可用性：前端据此提示"geo 规则当前是否生效"
		wafRouter.GET("/geo/status", baseApi.GetWAFGEOStatus)

		// IP 组：可复用的 IP/CIDR 集合，供 match_type=ip_group 的规则引用
		ipGroups := wafRouter.Group("/ip-groups")
		{
			ipGroups.GET("", baseApi.ListWAFIPGroups)
			ipGroups.POST("/create", baseApi.CreateWAFIPGroup)
			ipGroups.POST("/update", baseApi.UpdateWAFIPGroup)
			ipGroups.POST("/:id/delete", baseApi.DeleteWAFIPGroup)
		}
		wafRouter.DELETE("/rules/:id", baseApi.DeleteWAFRule)

		wafRouter.POST("/logs/search", baseApi.SearchWAFLogs)
		wafRouter.POST("/logs/stat", baseApi.StatWAFLogs)
		wafRouter.POST("/logs/export", baseApi.ExportWAFLogs)
		wafRouter.POST("/logs/rule", baseApi.CreateRuleFromWAFLog)
		wafRouter.POST("/logs/false-positive", baseApi.MarkWAFFalsePositive)
	}
}
