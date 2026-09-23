package router

import (
	"errors"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"

	"github.com/3panel-dev/3panel/core/app/api/v2/helper"
	baseRepo "github.com/3panel-dev/3panel/core/app/repo"
	"github.com/3panel-dev/3panel/core/cmd/server/res"
	"github.com/3panel-dev/3panel/core/constant"
	"github.com/3panel-dev/3panel/core/global"
	"github.com/3panel-dev/3panel/core/init/proxy"
	psessionUtils "github.com/3panel-dev/3panel/core/init/session/psession"
	"github.com/3panel-dev/3panel/core/middleware"
	multinode "github.com/3panel-dev/3panel/core/platform/multinode"
	terminalsession "github.com/3panel-dev/3panel/core/utils/terminal_session"
	"github.com/gin-gonic/gin"
)

var errInternalOnlyAgentEndpoint = errors.New("internal agent endpoint cannot be proxied")

func Proxy() gin.HandlerFunc {
	return func(c *gin.Context) {
		terminalsession.ClearForwardedHeaders(c)
		reqPath := c.Request.URL.Path
		if !middleware.ShouldProxyToAgent(reqPath) {
			c.Next()
			return
		}
		var nodeItem string
		queryNode := c.Query("operateNode")
		if queryNode != "" && queryNode != "undefined" {
			nodeItem = queryNode
		} else {
			nodeItem = c.Request.Header.Get("CurrentNode")
		}
		currentNode, err := url.QueryUnescape(nodeItem)
		if err != nil {
			helper.ErrorWithDetail(c, http.StatusBadRequest, "ErrProxy", err)
			return
		}

		apiReq := c.GetBool("API_AUTH")
		terminalRevalidate := c.Query("terminalRevalidate") == "1" && isTerminalRevalidationEndpoint(reqPath)

		if !apiReq && !isLocalAPI(reqPath) && !middleware.IsPublicFileShareAPI(reqPath) && !checkSession(c, !terminalRevalidate) {
			data, _ := res.ErrorMsg.ReadFile("html/401.html")
			c.Data(401, "text/html; charset=utf-8", data)
			c.Abort()
			return
		}

		if userName := middleware.LoadOperationUser(c); userName != "" {
			c.Request.Header.Set("X-Panel-User", url.QueryEscape(userName))
		}
		if identity, ok := terminalsession.FromContext(c); ok {
			terminalsession.SetForwardedHeaders(c, identity)
		}

		if isInternalOnlyAgentEndpoint(reqPath) {
			helper.ErrorWithDetail(c, http.StatusForbidden, "ErrProxy", errInternalOnlyAgentEndpoint)
			return
		}

		if reqPath == "/api/v2/hosts/terminal/local" && (currentNode == "local" || len(currentNode) == 0) {
			proxyLocalAgent(c)
			return
		}

		if !strings.HasPrefix(reqPath, "/api/v2/core") && (currentNode == "local" || len(currentNode) == 0) {
			proxyLocalAgent(c)
			return
		}
		multinode.Provider.Proxy(c, currentNode)
		c.Abort()
	}
}

func isTerminalRevalidationEndpoint(reqPath string) bool {
	switch reqPath {
	case "/api/v2/hosts/terminal/local", "/api/v2/hosts/terminal/ssh", "/api/v2/hosts/terminal/container":
		return true
	default:
		return false
	}
}

func isInternalOnlyAgentEndpoint(reqPath string) bool {
	normalizedPath := path.Clean(reqPath)
	return normalizedPath == "/api/v2/hosts/firewall/port" ||
		normalizedPath == "/api/v2/internal/terminal/sessions/revoke"
}

func proxyLocalAgent(c *gin.Context) {
	defer func() {
		if err := recover(); err != nil && err != http.ErrAbortHandler {
			global.LOG.Debug(err)
		}
	}()
	proxy.LocalAgentProxy.ServeHTTP(c.Writer, c.Request)
	c.Abort()
}

func checkSession(c *gin.Context, refresh bool) bool {
	psession, err := global.SESSION.Get(c)
	if err != nil {
		return false
	}
	c.Set(psessionUtils.GinContextSessionUserKey, psession)
	sessionTimeout, err := baseRepo.NewISettingRepo().GetValueByKey("SessionTimeout")
	if err != nil {
		global.LOG.Errorf("get session timeout failed, err: %v", err)
		return false
	}
	lifeTime, _ := strconv.Atoi(sessionTimeout)
	if !refresh {
		return true
	}
	if _, err := global.SESSION.RefreshIfNeeded(c, psession, global.CONF.Conn.SSL == constant.StatusEnable, lifeTime); err != nil {
		global.LOG.Warnf("proxy refresh session failed, path=%s, err=%v", c.Request.URL.Path, err)
		return false
	}
	return true
}

func isLocalAPI(urlPath string) bool {
	return false
}
