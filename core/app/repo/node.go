package repo

import (
	"github.com/3panel-dev/3panel/core/app/model"
	"github.com/3panel-dev/3panel/core/global"
)

type NodeRepo struct{}

type INodeRepo interface {
	Get(opts ...global.DBOption) (model.Node, error)
	GetList(opts ...global.DBOption) ([]model.Node, error)
	Create(node *model.Node) error
	Update(id uint, vars map[string]interface{}) error
	Delete(opts ...global.DBOption) error
	UpdateGroup(oldGroupID, newGroupID uint) error
}

func NewINodeRepo() INodeRepo {
	return &NodeRepo{}
}

func (n *NodeRepo) Get(opts ...global.DBOption) (model.Node, error) {
	var node model.Node
	db := global.DB
	for _, opt := range opts {
		db = opt(db)
	}
	err := db.First(&node).Error
	return node, err
}

func (n *NodeRepo) GetList(opts ...global.DBOption) ([]model.Node, error) {
	var nodes []model.Node
	db := global.DB.Model(&model.Node{})
	for _, opt := range opts {
		db = opt(db)
	}
	err := db.Find(&nodes).Error
	return nodes, err
}

func (n *NodeRepo) Create(node *model.Node) error {
	return global.DB.Create(node).Error
}

func (n *NodeRepo) Update(id uint, vars map[string]interface{}) error {
	return global.DB.Model(&model.Node{}).Where("id = ?", id).Updates(vars).Error
}

func (n *NodeRepo) Delete(opts ...global.DBOption) error {
	db := global.DB
	for _, opt := range opts {
		db = opt(db)
	}
	return db.Delete(&model.Node{}).Error
}

func (n *NodeRepo) UpdateGroup(oldGroupID, newGroupID uint) error {
	return global.DB.Model(&model.Node{}).
		Where("group_id = ?", oldGroupID).
		Updates(map[string]interface{}{"group_id": newGroupID}).Error
}

type NodeTokenRepo struct{}

type INodeTokenRepo interface {
	Create(token *model.NodeJoinToken) error
	GetByToken(token string) (model.NodeJoinToken, error)
	MarkUsed(id uint) error
	DeleteByNodeName(name string) error
}

func NewINodeTokenRepo() INodeTokenRepo {
	return &NodeTokenRepo{}
}

func (n *NodeTokenRepo) Create(token *model.NodeJoinToken) error {
	return global.DB.Create(token).Error
}

func (n *NodeTokenRepo) GetByToken(token string) (model.NodeJoinToken, error) {
	var item model.NodeJoinToken
	err := global.DB.Where("token = ?", token).First(&item).Error
	return item, err
}

func (n *NodeTokenRepo) MarkUsed(id uint) error {
	return global.DB.Model(&model.NodeJoinToken{}).
		Where("id = ?", id).
		Updates(map[string]interface{}{"used": true}).Error
}

func (n *NodeTokenRepo) DeleteByNodeName(name string) error {
	return global.DB.Where("node_name = ?", name).Delete(&model.NodeJoinToken{}).Error
}
