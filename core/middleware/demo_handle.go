package middleware

import (
	"net/http"
	"strings"

	"github.com/3panel-dev/3panel/core/app/dto"
	"github.com/3panel-dev/3panel/core/buserr"
	"github.com/gin-gonic/gin"
)

type demoRoute struct {
	method string
	path   string
}

var demoAllowedRoutes = map[demoRoute]struct{}{
	{http.MethodPost, "/api/v2/dashboard/app/launcher/option"}: {},
	{http.MethodPost, "/api/v2/websites/config"}:               {},
	{http.MethodPost, "/api/v2/files/size"}:                    {},
	{http.MethodPost, "/api/v2/files/ai-search"}:               {},
	{http.MethodPost, "/api/v2/runtimes/sync"}:                 {},
	{http.MethodPost, "/api/v2/toolbox/device/base"}:           {},
	{http.MethodPost, "/api/v2/files/user/group"}:              {},
	{http.MethodPost, "/api/v2/files/mount"}:                   {},
	{http.MethodPost, "/api/v2/hosts/ssh/log"}:                 {},
	{http.MethodPost, "/api/v2/toolbox/clam/base"}:             {},
	{http.MethodPost, "/api/v2/backups/record/size"}:           {},

	{http.MethodPost, "/api/v2/core/auth/login"}:     {},
	{http.MethodPost, "/api/v2/core/logs/login"}:     {},
	{http.MethodPost, "/api/v2/core/logs/operation"}: {},
	{http.MethodPost, "/api/v2/core/auth/logout"}:    {},

	{http.MethodPost, "/api/v2/apps/installed/loadport"}:    {},
	{http.MethodPost, "/api/v2/apps/installed/check"}:       {},
	{http.MethodPost, "/api/v2/apps/installed/conninfo"}:    {},
	{http.MethodPost, "/api/v2/databases/common/info"}:      {},
	{http.MethodPost, "/api/v2/databases/common/load/file"}: {},
	{http.MethodPost, "/api/v2/databases/variables"}:        {},
	{http.MethodPost, "/api/v2/databases/status"}:           {},

	{http.MethodPost, "/api/v2/ai/accounts/counts"}:             {},
	{http.MethodPost, "/api/v2/ai/accounts/models"}:             {},
	{http.MethodPost, "/api/v2/ai/agents/overview"}:             {},
	{http.MethodPost, "/api/v2/ai/agents/hermes/chat/sessions"}: {},
	{http.MethodPost, "/api/v2/ai/agents/agent/list"}:           {},
	{http.MethodPost, "/api/v2/ai/agents/agent/channels"}:       {},
	{http.MethodPost, "/api/v2/ai/agents/agent/md/list"}:        {},
	{http.MethodPost, "/api/v2/ai/agents/plugins/list"}:         {},
	{http.MethodPost, "/api/v2/ai/agents/skills/list"}:          {},
	{http.MethodPost, "/api/v2/alert/cronjob/list"}:             {},

	{http.MethodPost, "/api/v2/core/nodes/list"}: {},
}

var demoDeniedRoutes = map[demoRoute]struct{}{
	{http.MethodGet, "/api/v2/containers/exec"}:          {},
	{http.MethodGet, "/api/v2/hosts/terminal/local"}:     {},
	{http.MethodGet, "/api/v2/hosts/terminal/ssh"}:       {},
	{http.MethodGet, "/api/v2/hosts/terminal/container"}: {},
}

func DemoHandle() gin.HandlerFunc {
	return func(c *gin.Context) {
		if isDemoRequestAllowed(c.Request.Method, c.Request.URL.Path) {
			c.Next()
			return
		}

		c.JSON(http.StatusForbidden, dto.Response{
			Code:    http.StatusForbidden,
			Message: buserr.New("ErrDemoEnvironment").Error(),
		})
		c.Abort()
	}
}

func isDemoRequestAllowed(method, path string) bool {
	route := demoRoute{method: method, path: path}
	if _, denied := demoDeniedRoutes[route]; denied {
		return false
	}
	if method == http.MethodGet {
		return true
	}
	if method == http.MethodPost && hasPathSegment(path, "search") {
		return true
	}
	_, allowed := demoAllowedRoutes[route]
	return allowed
}

func hasPathSegment(path, segment string) bool {
	for _, item := range strings.Split(strings.Trim(path, "/"), "/") {
		if item == segment {
			return true
		}
	}
	return false
}
