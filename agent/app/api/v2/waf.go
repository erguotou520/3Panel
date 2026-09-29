package v2

import (
	"strconv"

	"github.com/3panel-dev/3panel/agent/app/api/v2/helper"
	"github.com/3panel-dev/3panel/agent/app/dto"
	"github.com/3panel-dev/3panel/agent/app/dto/request"
	"github.com/3panel-dev/3panel/agent/app/model"
	"github.com/gin-gonic/gin"
)

// @Tags WAF
// @Summary Enable / disable website waf
// @Accept json
// @Param request body request.WAFWebsiteOp true "request"
// @Success 200
// @Security ApiKeyAuth
// @Security Timestamp
// @Router /waf/website/op [post]
func (b *BaseApi) OperateWebsiteWAF(c *gin.Context) {
	var req request.WAFWebsiteOp
	if err := helper.CheckBindAndValidate(&req, c); err != nil {
		return
	}
	if err := wafService.SetWebsiteWAF(req.WebsiteID, req.Operate == "enable"); err != nil {
		helper.InternalServer(c, err)
		return
	}
	helper.Success(c)
}

// @Tags WAF
// @Summary List waf rules
// @Param request body request.WAFRuleSearch true "request"
// @Success 200 {array} model.WAFRule
// @Security ApiKeyAuth
// @Security Timestamp
// @Router /waf/rules/search [post]
func (b *BaseApi) SearchWAFRules(c *gin.Context) {
	var req request.WAFRuleSearch
	if err := helper.CheckBindAndValidate(&req, c); err != nil {
		return
	}
	rules, err := wafService.ListRules(req)
	if err != nil {
		helper.InternalServer(c, err)
		return
	}
	helper.SuccessWithData(c, rules)
}

// @Tags WAF
// @Summary Create waf rule
// @Accept json
// @Param request body request.WAFRuleCreate true "request"
// @Success 200
// @Security ApiKeyAuth
// @Security Timestamp
// @Router /waf/rules [post]
func (b *BaseApi) CreateWAFRule(c *gin.Context) {
	var req request.WAFRuleCreate
	if err := helper.CheckBindAndValidate(&req, c); err != nil {
		return
	}
	if err := wafService.CreateRule(req); err != nil {
		helper.InternalServer(c, err)
		return
	}
	helper.Success(c)
}

// @Tags WAF
// @Summary Update waf rule
// @Accept json
// @Param request body request.WAFRuleUpdate true "request"
// @Success 200
// @Security ApiKeyAuth
// @Security Timestamp
// @Router /waf/rules/update [post]
func (b *BaseApi) UpdateWAFRule(c *gin.Context) {
	var req request.WAFRuleUpdate
	if err := helper.CheckBindAndValidate(&req, c); err != nil {
		return
	}
	if err := wafService.UpdateRule(req); err != nil {
		helper.InternalServer(c, err)
		return
	}
	helper.Success(c)
}

// @Tags WAF
// @Summary Delete waf rule
// @Param id path integer true "id"
// @Success 200
// @Security ApiKeyAuth
// @Security Timestamp
// @Router /waf/rules/:id [delete]
func (b *BaseApi) DeleteWAFRule(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		helper.BadRequest(c, err)
		return
	}
	if err := wafService.DeleteRule(uint(id)); err != nil {
		helper.InternalServer(c, err)
		return
	}
	helper.Success(c)
}

// @Tags WAF
// @Summary Get site cc config
// @Param websiteId query integer true "websiteId"
// @Success 200 {object} model.WAFCCConfig
// @Security ApiKeyAuth
// @Security Timestamp
// @Router /waf/cc [get]
func (b *BaseApi) GetWAFCCConfig(c *gin.Context) {
	websiteID, err := strconv.ParseUint(c.Query("websiteId"), 10, 64)
	if err != nil {
		helper.BadRequest(c, err)
		return
	}
	cc, err := wafService.GetCCConfig(uint(websiteID))
	if err != nil {
		helper.InternalServer(c, err)
		return
	}
	helper.SuccessWithData(c, cc)
}

// @Tags WAF
// @Summary Update site cc config
// @Accept json
// @Param request body request.WAFCCUpdate true "request"
// @Success 200
// @Security ApiKeyAuth
// @Security Timestamp
// @Router /waf/cc/update [post]
func (b *BaseApi) UpdateWAFCCConfig(c *gin.Context) {
	var req request.WAFCCUpdate
	if err := helper.CheckBindAndValidate(&req, c); err != nil {
		return
	}
	if err := wafService.UpdateCCConfig(req); err != nil {
		helper.InternalServer(c, err)
		return
	}
	helper.Success(c)
}

// @Tags WAF
// @Summary Get site bot/probe option
// @Param websiteId query integer true "websiteId"
// @Success 200 {object} model.WAFOption
// @Security ApiKeyAuth
// @Security Timestamp
// @Router /waf/option [get]
func (b *BaseApi) GetWAFOption(c *gin.Context) {
	websiteID, err := strconv.ParseUint(c.Query("websiteId"), 10, 64)
	if err != nil {
		helper.BadRequest(c, err)
		return
	}
	opt, err := wafService.GetOption(uint(websiteID))
	if err != nil {
		helper.InternalServer(c, err)
		return
	}
	helper.SuccessWithData(c, opt)
}

// @Tags WAF
// @Summary Update site bot/probe option
// @Accept json
// @Param request body request.WAFOptionUpdate true "request"
// @Success 200
// @Security ApiKeyAuth
// @Security Timestamp
// @Router /waf/option/update [post]
func (b *BaseApi) UpdateWAFOption(c *gin.Context) {
	var req request.WAFOptionUpdate
	if err := helper.CheckBindAndValidate(&req, c); err != nil {
		return
	}
	if err := wafService.UpdateOption(req); err != nil {
		helper.InternalServer(c, err)
		return
	}
	helper.Success(c)
}

// @Tags WAF
// @Summary Get webhook push setting
// @Success 200
// @Security ApiKeyAuth
// @Security Timestamp
// @Router /waf/webhook [get]
func (b *BaseApi) GetWAFWebhookSetting(c *gin.Context) {
	res, err := wafService.GetWebhookSetting()
	if err != nil {
		helper.InternalServer(c, err)
		return
	}
	helper.SuccessWithData(c, res)
}

// @Tags WAF
// @Summary Update webhook push setting
// @Accept json
// @Param request body request.WAFWebhookUpdate true "request"
// @Success 200
// @Security ApiKeyAuth
// @Security Timestamp
// @Router /waf/webhook/update [post]
func (b *BaseApi) UpdateWAFWebhookSetting(c *gin.Context) {
	var req request.WAFWebhookUpdate
	if err := helper.CheckBindAndValidate(&req, c); err != nil {
		return
	}
	if err := wafService.UpdateWebhookSetting(req); err != nil {
		helper.InternalServer(c, err)
		return
	}
	helper.Success(c)
}

// @Tags WAF
// @Summary Search waf logs
// @Param request body request.WAFLogSearch true "request"
// @Success 200
// @Security ApiKeyAuth
// @Security Timestamp
// @Router /waf/logs/search [post]
func (b *BaseApi) SearchWAFLogs(c *gin.Context) {
	var req request.WAFLogSearch
	if err := helper.CheckBindAndValidate(&req, c); err != nil {
		return
	}
	if req.Page <= 0 {
		req.Page = 1
	}
	if req.PageSize <= 0 || req.PageSize > 200 {
		req.PageSize = 20
	}
	total, logs, err := wafService.SearchLogs(req)
	if err != nil {
		helper.InternalServer(c, err)
		return
	}
	helper.SuccessWithData(c, dto.PageResult{Items: logs, Total: total})
}

// @Tags WAF
// @Summary Stat waf logs
// @Param request body request.WAFLogSearch true "request"
// @Success 200
// @Security ApiKeyAuth
// @Security Timestamp
// @Router /waf/logs/stat [post]
func (b *BaseApi) StatWAFLogs(c *gin.Context) {
	var req request.WAFLogSearch
	if err := helper.CheckBindAndValidate(&req, c); err != nil {
		return
	}
	res, err := wafService.StatLogs(req)
	if err != nil {
		helper.InternalServer(c, err)
		return
	}
	helper.SuccessWithData(c, res)
}

// @Tags WAF
// @Summary Export waf logs (csv/json)
// @Param request body request.WAFLogSearch true "request"
// @Success 200
// @Security ApiKeyAuth
// @Security Timestamp
// @Router /waf/logs/export [post]
func (b *BaseApi) ExportWAFLogs(c *gin.Context) {
	var req request.WAFLogSearch
	if err := helper.CheckBindAndValidate(&req, c); err != nil {
		return
	}
	format, content, err := wafService.ExportLogs(req)
	if err != nil {
		helper.InternalServer(c, err)
		return
	}
	c.Header("Content-Disposition", "attachment; filename=waf_logs."+format)
	c.Data(200, "application/octet-stream", content)
}

// @Tags WAF
// @Summary Create allow/deny rule from log
// @Accept json
// @Param request body request.WAFLogRuleOp true "request"
// @Success 200
// @Security ApiKeyAuth
// @Security Timestamp
// @Router /waf/logs/rule [post]
func (b *BaseApi) CreateRuleFromWAFLog(c *gin.Context) {
	var req request.WAFLogRuleOp
	if err := helper.CheckBindAndValidate(&req, c); err != nil {
		return
	}
	if err := wafService.AddRuleFromLog(req.LogID, req.Action); err != nil {
		helper.InternalServer(c, err)
		return
	}
	helper.Success(c)
}

// @Tags WAF
// @Summary Mark a WAF log as false positive and create a temporary site allow rule
// @Accept json
// @Param request body request.WAFFalsePositiveOp true "request"
// @Success 200
// @Security ApiKeyAuth
// @Security Timestamp
// @Router /waf/logs/false-positive [post]
func (b *BaseApi) MarkWAFFalsePositive(c *gin.Context) {
	var req request.WAFFalsePositiveOp
	if err := helper.CheckBindAndValidate(&req, c); err != nil {
		return
	}
	if err := wafService.MarkFalsePositive(req); err != nil {
		helper.InternalServer(c, err)
		return
	}
	helper.Success(c)
}

// GetWAFIPListSetting 查询 IP 黑名单订阅与上报配置。
// @Tags WAF
// @Summary 查询 IP 黑名单订阅配置
// @Router /waf/iplist [get]
func (b *BaseApi) GetWAFIPListSetting(c *gin.Context) {
	st, err := wafService.GetIPListStatus()
	if err != nil {
		helper.InternalServer(c, err)
		return
	}
	helper.SuccessWithData(c, st)
}

// UpdateWAFIPListSetting 保存 IP 黑名单订阅与上报配置。
// @Tags WAF
// @Summary 保存 IP 黑名单订阅配置
// @Router /waf/iplist/update [post]
func (b *BaseApi) UpdateWAFIPListSetting(c *gin.Context) {
	var req model.WAFIPListSetting
	if err := c.ShouldBindJSON(&req); err != nil {
		helper.BadRequest(c, err)
		return
	}
	if err := wafService.UpdateIPListSetting(req); err != nil {
		helper.BadRequest(c, err)
		return
	}
	helper.Success(c)
}

// SyncWAFIPList 立即拉取一次订阅。
// @Tags WAF
// @Summary 立即更新 IP 黑名单
// @Router /waf/iplist/sync [post]
func (b *BaseApi) SyncWAFIPList(c *gin.Context) {
	result, err := wafService.SyncIPList()
	if err != nil {
		helper.InternalServer(c, err)
		return
	}
	helper.SuccessWithData(c, result)
}
