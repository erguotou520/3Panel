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

// AddNodeFavoriteColumn back-fills the favorite flag for installations that
// already ran AddNodeTable before the field existed. AutoMigrate only adds the
// missing column and leaves existing rows untouched.
var AddNodeFavoriteColumn = &gormigrate.Migration{
	ID: "20260919-add-node-favorite-column",
	Migrate: func(tx *gorm.DB) error {
		return tx.AutoMigrate(&model.Node{})
	},
}
