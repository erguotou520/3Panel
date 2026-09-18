package service

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/3panel-dev/3panel/core/app/dto"
	"github.com/3panel-dev/3panel/core/app/model"
	"github.com/3panel-dev/3panel/core/app/repo"
	"github.com/3panel-dev/3panel/core/buserr"
	"github.com/3panel-dev/3panel/core/global"
	"github.com/3panel-dev/3panel/core/init/proxy"
	"github.com/3panel-dev/3panel/core/utils/common"
	"github.com/3panel-dev/3panel/core/utils/nodecert"
	"github.com/jinzhu/copier"
)

const (
	// LocalNodeName is the reserved name of the master itself.
	LocalNodeName = "local"

	joinTokenTTL       = 30 * time.Minute
	joinTokenLength    = 32
	defaultNodePort    = 9999
	remoteProbeTimeout = 5 * time.Second
	nodeStatusOnline   = "Online"
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
	Favorite(req dto.NodeFavorite) error
	SimpleAll() ([]dto.SimpleNodeItem, error)
}

func NewINodeService() INodeService {
	return &NodeService{}
}

// Favorite pins a node on the dashboard carousel.
func (u *NodeService) Favorite(req dto.NodeFavorite) error {
	if _, err := nodeRepo.Get(repo.WithByID(req.ID)); err != nil {
		return buserr.New("ErrRecordNotFound")
	}
	return nodeRepo.Update(req.ID, map[string]interface{}{"is_favorite": req.IsFavorite})
}

// SimpleAll feeds the dashboard node carousel with one row per node plus the
// master. Unreachable nodes stay Offline; a missing local agent only blanks
// the master row instead of failing the whole call.
func (u *NodeService) SimpleAll() ([]dto.SimpleNodeItem, error) {
	items := []dto.SimpleNodeItem{u.localSimpleItem()}
	nodes, err := nodeRepo.GetList(repo.WithOrderDesc("created_at"))
	if err != nil {
		return items, nil
	}
	// Node agents only accept certificates signed by this panel's CA and
	// require core's client cert (mTLS), so the probe must use the nodecert
	// configuration rather than a plain system-roots transport.
	for _, node := range nodes {
		item := dto.SimpleNodeItem{
			ID:          node.ID,
			Name:        node.Name,
			Addr:        node.Addr,
			Description: node.Description,
			Status:      nodeStatusOffline,
		}
		if node.Addr != "" {
			if err := u.fillRemoteSimpleItem(node, &item); err != nil {
				global.LOG.Debugf("load simple info for node %s failed: %v", node.Name, err)
			}
		}
		items = append(items, item)
	}
	return items, nil
}

func (u *NodeService) localSimpleItem() dto.SimpleNodeItem {
	item := dto.SimpleNodeItem{
		Name:   LocalNodeName,
		Addr:   "127.0.0.1",
		Status: nodeStatusOffline,
	}
	client := proxy.LocalClient()
	var info agentNodeInfo
	if err := u.getJSON(client, "http://3panel.local/api/v2/dashboard/current/node", &info); err == nil {
		item.SystemVersion = info.Version
		item.SecurityEntrance = info.Scope
		item.Status = nodeStatusOnline
	}
	return item
}

func (u *NodeService) fillRemoteSimpleItem(node model.Node, item *dto.SimpleNodeItem) error {
	// Per-node TLS config: ServerName must be the host part of the dial
	// address so the node's certificate (SAN carries the same host) verifies.
	tlsCfg, err := nodecert.TLSConfig(node.Addr)
	if err != nil {
		return err
	}
	client := &http.Client{
		Timeout:   remoteProbeTimeout,
		Transport: &http.Transport{TLSClientConfig: tlsCfg},
	}
	var info agentNodeInfo
	if err := u.getJSON(client, "https://"+node.Addr+"/api/v2/dashboard/current/node", &info); err != nil {
		return err
	}
	item.Status = nodeStatusOnline
	item.SystemVersion = info.Version
	item.SecurityEntrance = info.Scope

	// The current/node payload already carries CPU/memory stats; no extra
	// dashboard call needed.
	item.CPUUsedPercent = info.CPUUsedPercent
	item.CPUTotal = info.CPUTotal
	item.MemoryTotal = info.MemoryTotal
	item.MemoryUsedPercent = info.MemoryUsedPercent
	return nil
}

func (u *NodeService) getJSON(client *http.Client, url string, out interface{}) error {
	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status %d", resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

type agentNodeInfo struct {
	Version           string  `json:"version"`
	Scope             string  `json:"scope"`
	CPUUsedPercent    float64 `json:"cpuUsedPercent"`
	CPUTotal          int     `json:"cpuTotal"`
	MemoryTotal       uint64  `json:"memoryTotal"`
	MemoryUsedPercent float64 `json:"memoryUsedPercent"`
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
		ID:           node.ID,
		Name:         node.Name,
		Token:        token.Token,
		Command:      joinBootstrapCommand(masterAddr, token.Token),
		AgentCommand: fmt.Sprintf("3panel-agent join --master %s --token %s", masterAddr, token.Token),
		ExpiredAt:    token.ExpiredAt,
	}, nil
}

// joinScriptProxy fronts every download with a regional accelerator. The panel's
// own host is Cloudflare-backed and, from mainland China, frequently stalls on
// the 25MB+ package — the same reason packaging/quick_start.sh is documented
// with this prefix.
const joinScriptProxy = "https://proxy.erguotou.me"

// joinBootstrapCommand builds the line an operator copies onto the target host.
//
// It has to be self-sufficient: a fresh host has no 3panel-agent binary and no
// way to get one, so the command fetches packaging/join.sh, which downloads the
// agent-only package and runs the packaged installer. Nothing else is required
// beyond curl.
//
// The token is single quoted because it is a credential — it must never end up
// in the URL, where it would be captured by proxy and access logs.
//
// The script is fetched through the accelerator first and straight from the
// origin when that fails: if the accelerator is down the operator is stuck at
// step zero with no agent binary to fall back on, whereas everything after this
// first fetch already retries across bases inside join.sh.
func joinBootstrapCommand(masterAddr, token string) string {
	direct := strings.TrimSuffix(global.RepoURL(), "/") + "/join.sh"
	return fmt.Sprintf(
		"PANEL3_MASTER='%s' PANEL3_TOKEN='%s' bash -c \"$(curl -sSL %s/%s || curl -sSL %s)\"",
		masterAddr, token, joinScriptProxy, direct, direct)
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
