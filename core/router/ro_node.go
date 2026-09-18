package router

import (
	v2 "github.com/3panel-dev/3panel/core/app/api/v2"
	"github.com/3panel-dev/3panel/core/middleware"
	"github.com/gin-gonic/gin"
)

type NodeRouter struct {
}

func (a *NodeRouter) InitRouter(Router *gin.RouterGroup) {
	baseApi := v2.ApiGroupApp.BaseApi

	// Unauthenticated on purpose: the token is the credential, and a freshly
	// installed agent owns neither a session nor a certificate yet.
	Router.POST("nodes/join", baseApi.JoinNode)

	nodeRouter := Router.Group("nodes").
		Use(middleware.SessionAuth()).
		Use(middleware.PasswordExpired())
	{
		nodeRouter.GET("options", baseApi.ListNodeOptions)
		nodeRouter.POST("search", baseApi.ListNode)
		// Alias kept because the frontend's node switcher already calls /list.
		nodeRouter.POST("list", baseApi.ListNode)
		nodeRouter.POST("check", baseApi.CheckNode)
		nodeRouter.POST("", baseApi.CreateNode)
		nodeRouter.POST("del", baseApi.DeleteNode)
	}
}
