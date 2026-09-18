package service

import (
	"fmt"
	"time"

	"github.com/3panel-dev/3panel/core/app/dto"
	"github.com/3panel-dev/3panel/core/app/model"
	"github.com/3panel-dev/3panel/core/app/repo"
	"github.com/3panel-dev/3panel/core/buserr"
	"github.com/3panel-dev/3panel/core/global"
	"github.com/3panel-dev/3panel/core/utils/common"
	"github.com/3panel-dev/3panel/core/utils/nodecert"
	"github.com/jinzhu/copier"
)

const (
	// LocalNodeName is the reserved name of the master itself.
	LocalNodeName = "local"

	joinTokenTTL     = 30 * time.Minute
	joinTokenLength  = 32
	defaultNodePort  = 9999
	nodeStatusOnline = "Online"
	// nodeStatusOffline must match what the frontend renders as unhealthy; the
	// node drawer treats anything other than 'Healthy' as a problem.
	nodeStatusOffline = "Offline"
)

type NodeService struct{}

type INodeService interface {
	List(req dto.NodeSearch) ([]dto.NodeInfo, error)
	Options() ([]dto.NodeInfo, error)
	Create(req dto.NodeCreate, masterAddr string) (*dto.NodeJoinCommand, error)
	Join(req dto.NodeJoin) (*dto.NodeJoinResult, error)
	Delete(id uint) error
	Check() ([]dto.NodeInfo, error)
}

func NewINodeService() INodeService {
	return &NodeService{}
}

func (u *NodeService) List(req dto.NodeSearch) ([]dto.NodeInfo, error) {
	options := []global.DBOption{repo.WithOrderDesc("created_at")}
	if req.Name != "" {
		options = append(options, repo.WithByLikeName(req.Name))
	}
	nodes, err := nodeRepo.GetList(options...)
	if err != nil {
		return nil, err
	}
	return u.toInfoList(nodes), nil
}

// Options feeds the frontend node switcher. The master is always offered first
// so an operator can get back to it.
func (u *NodeService) Options() ([]dto.NodeInfo, error) {
	nodes, err := nodeRepo.GetList(repo.WithOrderDesc("created_at"))
	if err != nil {
		return nil, err
	}
	result := []dto.NodeInfo{{
		Name:    LocalNodeName,
		Addr:    "127.0.0.1",
		Status:  nodeStatusOnline,
		Version: global.CONF.Base.Version,
	}}
	return append(result, u.toInfoList(nodes)...), nil
}

func (u *NodeService) toInfoList(nodes []model.Node) []dto.NodeInfo {
	var items []dto.NodeInfo
	for _, node := range nodes {
		var item dto.NodeInfo
		if err := copier.Copy(&item, &node); err != nil {
			global.LOG.Errorf("copy node %s failed, err: %v", node.Name, err)
			continue
		}
		if item.GroupID != 0 {
			if group, err := groupRepo.Get(repo.WithByID(item.GroupID)); err == nil {
				item.GroupBelong = group.Name
			}
		}
		items = append(items, item)
	}
	return items
}

// Create registers a node name and returns a single use token plus the command
// an operator runs on the target host.
func (u *NodeService) Create(req dto.NodeCreate, masterAddr string) (*dto.NodeJoinCommand, error) {
	if req.Name == LocalNodeName {
		return nil, buserr.New("ErrNodeNameReserved")
	}
	if exist, _ := nodeRepo.Get(repo.WithByName(req.Name)); exist.ID != 0 {
		return nil, buserr.New("ErrRecordExist")
	}
	if err := nodeTokenRepo.DeleteByNodeName(req.Name); err != nil {
		return nil, err
	}
	token := model.NodeJoinToken{
		Token:     common.RandStr(joinTokenLength),
		NodeName:  req.Name,
		ExpiredAt: time.Now().Add(joinTokenTTL),
	}
	if err := nodeTokenRepo.Create(&token); err != nil {
		return nil, err
	}
	node := model.Node{
		Name:        req.Name,
		Addr:        req.Addr,
		Description: req.Description,
		GroupID:     req.GroupID,
		Status:      nodeStatusOffline,
		IsBound:     false,
	}
	if err := nodeRepo.Create(&node); err != nil {
		return nil, err
	}
	return &dto.NodeJoinCommand{
		ID:        node.ID,
		Name:      node.Name,
		Token:     token.Token,
		Command:   fmt.Sprintf("3panel-agent join --master %s --token %s", masterAddr, token.Token),
		ExpiredAt: token.ExpiredAt,
	}, nil
}

// Join redeems a token: the agent proves possession of the secret and receives
// its own certificate pair plus the CA it validates the master against.
func (u *NodeService) Join(req dto.NodeJoin) (*dto.NodeJoinResult, error) {
	token, err := nodeTokenRepo.GetByToken(req.Token)
	if err != nil {
		return nil, buserr.New("ErrNodeTokenInvalid")
	}
	if token.Used {
		return nil, buserr.New("ErrNodeTokenUsed")
	}
	if time.Now().After(token.ExpiredAt) {
		return nil, buserr.New("ErrNodeTokenExpired")
	}

	name := token.NodeName
	if req.Name != "" {
		name = req.Name
	}
	addr := req.Addr
	if addr == "" {
		return nil, buserr.New("ErrNodeAddrRequired")
	}
	port := req.Port
	if port == 0 {
		port = defaultNodePort
	}

	ca, err := nodecert.EnsureCA()
	if err != nil {
		return nil, err
	}
	crt, key, err := ca.IssueServerCert(name, []string{nodecert.HostOf(addr), name})
	if err != nil {
		return nil, err
	}
	rootCrt, err := nodecert.CACertPEM()
	if err != nil {
		return nil, err
	}

	node, _ := nodeRepo.Get(repo.WithByName(name))
	now := time.Now()
	if node.ID == 0 {
		node = model.Node{Name: name}
	}
	node.Addr = addr
	node.Status = nodeStatusOnline
	node.Version = req.Version
	node.IsBound = true
	node.LastSeenAt = &now
	if node.ID == 0 {
		if err := nodeRepo.Create(&node); err != nil {
			return nil, err
		}
	} else if err := nodeRepo.Update(node.ID, map[string]interface{}{
		"addr":         node.Addr,
		"status":       node.Status,
		"version":      node.Version,
		"is_bound":     node.IsBound,
		"last_seen_at": now,
	}); err != nil {
		return nil, err
	}

	if err := nodeTokenRepo.MarkUsed(token.ID); err != nil {
		return nil, err
	}
	return &dto.NodeJoinResult{
		Name:      name,
		ServerCrt: crt,
		ServerKey: key,
		RootCrt:   rootCrt,
		NodePort:  port,
	}, nil
}

func (u *NodeService) Delete(id uint) error {
	node, err := nodeRepo.Get(repo.WithByID(id))
	if err != nil {
		return buserr.New("ErrRecordNotFound")
	}
	if err := nodeTokenRepo.DeleteByNodeName(node.Name); err != nil {
		return err
	}
	return nodeRepo.Delete(repo.WithByID(id))
}

// Check probes every registered node and returns the refreshed list. It is
// driven both by a cron job and by the "check" button in the UI.
func (u *NodeService) Check() ([]dto.NodeInfo, error) {
	nodes, err := nodeRepo.GetList(repo.WithOrderDesc("created_at"))
	if err != nil {
		return nil, err
	}
	for i := range nodes {
		u.refresh(&nodes[i])
	}
	return u.toInfoList(nodes), nil
}

// refresh updates one node's reachability. Deleting a node is what actually
// revokes it: from then on it has no address here, so nothing will ever dial
// it again even though its certificate is still technically valid.
func (u *NodeService) refresh(node *model.Node) {
	if node.Addr == "" {
		return
	}
	if err := nodecert.Dial(node.Addr); err != nil {
		global.LOG.Debugf("node %s (%s) unreachable: %v", node.Name, node.Addr, err)
		if node.Status != nodeStatusOffline {
			node.Status = nodeStatusOffline
			_ = nodeRepo.Update(node.ID, map[string]interface{}{"status": nodeStatusOffline})
		}
		return
	}
	now := time.Now()
	node.Status = nodeStatusOnline
	node.LastSeenAt = &now
	_ = nodeRepo.Update(node.ID, map[string]interface{}{
		"status":       nodeStatusOnline,
		"last_seen_at": now,
	})
}
