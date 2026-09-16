package service

import (
	"context"

	"github.com/3panel-dev/3panel/agent/constant"
	"github.com/3panel-dev/3panel/agent/global"
	"gorm.io/gorm"
)

func getTxAndContext() (tx *gorm.DB, ctx context.Context) {
	tx = global.DB.Begin()
	ctx = context.WithValue(context.Background(), constant.DB, tx)
	return
}
