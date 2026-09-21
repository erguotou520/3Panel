package v2

import (
	"net/http"

	"github.com/3panel-dev/3panel/core/app/api/v2/helper"
	appauth "github.com/3panel-dev/3panel/core/app/auth"
	"github.com/3panel-dev/3panel/core/app/dto"
	"github.com/gin-gonic/gin"
)

// @Tags Node
// @Summary List nodes
// @Accept json
// @Success 200 {array} dto.NodeInfo
// @Security ApiKeyAuth
// @Router /nodes [post]
func (b *BaseApi) ListNode(c *gin.Context) {
	var req dto.NodeSearch
	if err := helper.CheckBindAndValidate(&req, c); err != nil {
		return
	}
	res, err := nodeService.List(req)
	if err != nil {
		helper.ErrorWithDetail(c, http.StatusInternalServerError, "ErrNodeList", err)
		return
	}
	helper.SuccessWithData(c, res)
}

// @Tags Node
// @Summary Node options for the switcher
// @Success 200 {array} dto.NodeInfo
// @Security ApiKeyAuth
// @Router /nodes/options [get]
func (b *BaseApi) ListNodeOptions(c *gin.Context) {
	res, err := nodeService.Options()
	if err != nil {
		helper.ErrorWithDetail(c, http.StatusInternalServerError, "ErrNodeList", err)
		return
	}
	helper.SuccessWithData(c, res)
}

// @Tags Node
// @Summary List simple nodes for the dashboard carousel
// @Success 200 {array} dto.SimpleNodeItem
// @Security ApiKeyAuth
// @Router /nodes/simple/all [get]
func (b *BaseApi) ListSimpleNodes(c *gin.Context) {
	res, err := nodeService.SimpleAll()
	if err != nil {
		helper.ErrorWithDetail(c, http.StatusInternalServerError, "ErrNodeList", err)
		return
	}
	helper.SuccessWithData(c, res)
}

// @Tags Node
// @Summary Pin/unpin a node on the dashboard
// @Accept json
// @Param request body dto.NodeFavorite true "request"
// @Security ApiKeyAuth
// @Router /nodes/favorite [post]
func (b *BaseApi) UpdateNodeFavorite(c *gin.Context) {
	var req dto.NodeFavorite
	if err := helper.CheckBindAndValidate(&req, c); err != nil {
		return
	}
	if err := nodeService.Favorite(req); err != nil {
		helper.ErrorWithDetail(c, http.StatusInternalServerError, "ErrNodeUpdate", err)
		return
	}
	helper.SuccessWithData(c, nil)
}

// @Tags Node
// @Summary Create node and return the join command
// @Accept json
// @Param request body dto.NodeCreate true "request"
// @Success 200 {object} dto.NodeJoinCommand
// @Security ApiKeyAuth
// @Router /nodes [post]
func (b *BaseApi) CreateNode(c *gin.Context) {
	var req dto.NodeCreate
	if err := helper.CheckBindAndValidate(&req, c); err != nil {
		return
	}
	// The command has to point at whatever host the operator is using right
	// now, otherwise it would send the agent to 127.0.0.1 on the wrong machine.
	res, err := nodeService.Create(req, requestOrigin(c))
	if err != nil {
		helper.ErrorWithDetail(c, http.StatusInternalServerError, "ErrNodeCreate", err)
		return
	}
	helper.SuccessWithData(c, res)
}

func requestOrigin(c *gin.Context) string {
	return appauth.PasskeyRequestScheme(c) + "://" + c.Request.Host
}

// @Tags Node
// @Summary Upgrade command for a node that has already joined
// @Success 200 {object} dto.NodeUpgradeCommand
// @Security ApiKeyAuth
// @Router /nodes/upgrade [get]
func (b *BaseApi) NodeUpgradeCommand(c *gin.Context) {
	helper.SuccessWithData(c, nodeService.UpgradeCommand())
}

// @Tags Node
// @Summary Delete node
// @Accept json
// @Param request body dto.NodeDelete true "request"
// @Security ApiKeyAuth
// @Router /nodes/del [post]
func (b *BaseApi) DeleteNode(c *gin.Context) {
	var req dto.NodeDelete
	if err := helper.CheckBindAndValidate(&req, c); err != nil {
		return
	}
	if err := nodeService.Delete(req.ID); err != nil {
		helper.ErrorWithDetail(c, http.StatusInternalServerError, "ErrNodeDelete", err)
		return
	}
	helper.SuccessWithData(c, nil)
}

// @Tags Node
// @Summary Probe every node and refresh its reachability
// @Success 200 {array} dto.NodeInfo
// @Security ApiKeyAuth
// @Router /nodes/check [post]
func (b *BaseApi) CheckNode(c *gin.Context) {
	res, err := nodeService.Check()
	if err != nil {
		helper.ErrorWithDetail(c, http.StatusInternalServerError, "ErrNodeList", err)
		return
	}
	helper.SuccessWithData(c, res)
}

// JoinNode is called by a fresh agent to exchange its token for certificates.
// It is deliberately unauthenticated: the token is the credential, and the
// agent has no certificate yet.
//
// @Tags Node
// @Summary Exchange a join token for node certificates
// @Accept json
// @Param request body dto.NodeJoin true "request"
// @Success 200 {object} dto.NodeJoinResult
// @Router /nodes/join [post]
func (b *BaseApi) JoinNode(c *gin.Context) {
	var req dto.NodeJoin
	if err := c.ShouldBindJSON(&req); err != nil {
		helper.ErrorWithDetail(c, http.StatusBadRequest, "ErrInvalidParams", err)
		return
	}
	res, err := nodeService.Join(req)
	if err != nil {
		helper.ErrorWithDetail(c, http.StatusBadRequest, "ErrNodeJoin", err)
		return
	}
	helper.SuccessWithData(c, res)
}
