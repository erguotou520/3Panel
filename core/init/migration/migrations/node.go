package migrations

import (
	"github.com/3panel-dev/3panel/core/app/model"
	"github.com/go-gormigrate/gormigrate/v2"
	"gorm.io/gorm"
)

var AddNodeTable = &gormigrate.Migration{
	ID: "20260918-add-node-table",
	Migrate: func(tx *gorm.DB) error {
		return tx.AutoMigrate(
			&model.Node{},
			&model.NodeJoinToken{},
		)
	},
}
