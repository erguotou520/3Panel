package service

import (
	"github.com/3panel-dev/3panel/core/buserr"
	"github.com/3panel-dev/3panel/core/utils/common"
	geo2 "github.com/3panel-dev/3panel/core/utils/geo"
	"github.com/gin-gonic/gin"

	"github.com/3panel-dev/3panel/core/app/dto"
	"github.com/3panel-dev/3panel/core/app/model"
	"github.com/3panel-dev/3panel/core/app/repo"
	"github.com/3panel-dev/3panel/core/global"
	"github.com/jinzhu/copier"
)

type LogService struct{}

type ILogService interface {
	CreateLoginLog(operation model.LoginLog) error
	PageLoginLog(ctx *gin.Context, search dto.SearchLgLogWithPage) (int64, interface{}, error)

	CreateOperationLog(operation *model.OperationLog) error
	PageOperationLog(search dto.SearchOpLogWithPage) (int64, interface{}, error)

	CleanLogs(logtype string) error
}

func NewILogService() ILogService {
	return &LogService{}
}

func (u *LogService) CreateLoginLog(operation model.LoginLog) error {
	return logRepo.CreateLoginLog(&operation)
}

func (u *LogService) PageLoginLog(ctx *gin.Context, req dto.SearchLgLogWithPage) (int64, interface{}, error) {
	options := []global.DBOption{
		repo.WithOrderDesc("created_at"),
	}
	if len(req.Info) != 0 {
		options = append(options, logRepo.WithByInfo(req.Info))
	}
	if len(req.Status) != 0 {
		options = append(options, repo.WithByStatus(req.Status))
	}
	if !req.StartTime.IsZero() && !req.EndTime.IsZero() {
		options = append(options, repo.WithByCreatedAt(req.StartTime, req.EndTime))
	}
	total, ops, err := logRepo.PageLoginLog(
		req.Page,
		req.PageSize,
		options...,
	)
	var dtoOps []dto.LoginLog
	geoDB, _ := geo2.NewGeo()
	for _, op := range ops {
		var item dto.LoginLog
		if err := copier.Copy(&item, &op); err != nil {
			return 0, nil, buserr.WithErr("ErrTransform", err)
		}
		if geoDB != nil {
			item.Address, _ = geo2.GetIPLocation(geoDB, item.IP, common.GetLang(ctx))
		}
		dtoOps = append(dtoOps, item)
	}
	return total, dtoOps, err
}

func (u *LogService) CreateOperationLog(operation *model.OperationLog) error {
	return logRepo.CreateOperationLog(operation)
}

func (u *LogService) PageOperationLog(req dto.SearchOpLogWithPage) (int64, interface{}, error) {
	options := []global.DBOption{
		repo.WithOrderDesc("created_at"),
		logRepo.WithByLikeOperation(req.Operation),
	}
	if len(req.Source) != 0 {
		options = append(options, logRepo.WithBySource(req.Source))
	}
	if len(req.Status) != 0 {
		options = append(options, repo.WithByStatus(req.Status))
	}
	if len(req.Node) != 0 {
		options = append(options, repo.WithByNode(req.Node))
	}

	total, ops, err := logRepo.PageOperationLog(
		req.Page,
		req.PageSize,
		options...,
	)
	var dtoOps []dto.OperationLog
	for _, op := range ops {
		var item dto.OperationLog
		if err := copier.Copy(&item, &op); err != nil {
			return 0, nil, buserr.WithErr("ErrTransform", err)
		}
		dtoOps = append(dtoOps, item)
	}
	return total, dtoOps, err
}

func (u *LogService) CleanLogs(logtype string) error {
	if logtype == "operation" {
		return logRepo.CleanOperation()
	}
	return logRepo.CleanLogin()
}
