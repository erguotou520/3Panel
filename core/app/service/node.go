package service

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
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

	joinTokenTTL    = 30 * time.Minute
	joinTokenLength = 32
	// joinScriptName lives at a fixed path on the release
	// host — publish-bootstrap.yml re-uploads them on every change, so a
	// version never appears in the URL.
	joinScriptName     = "join.sh"
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
	Upgrade(req dto.NodeUpgrade) (*dto.NodeUpgradeResult, error)
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
	var result struct {
		Code    int             `json:"code"`
		Message string          `json:"message"`
		Data    json.RawMessage `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return err
	}
	if result.Code != http.StatusOK {
		return fmt.Errorf("agent rejected request: %s", result.Message)
	}
	return json.Unmarshal(result.Data, out)
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

// joinBootstrapCommand builds the line an operator copies onto the target host.
//
// It has to be self-sufficient: a fresh host has no 3panel-agent binary and no
// way to get one, so the command fetches packaging/join.sh, which downloads the
// agent-only package and runs the packaged installer. Nothing else is required
// beyond curl.
//
// The token is single quoted because it is a credential — it must never end up
// in the URL, where it would be captured by proxy and access logs.
func joinBootstrapCommand(masterAddr, token string) string {
	direct := strings.TrimSuffix(global.RepoURL(), "/") + "/" + joinScriptName
	return fmt.Sprintf(
		"sudo env PANEL3_MASTER='%s' PANEL3_TOKEN='%s' bash -c \"$(curl -sSfL --connect-timeout 20 --max-time 60 %s)\"",
		masterAddr, token, direct)
}

func (u *NodeService) Upgrade(req dto.NodeUpgrade) (*dto.NodeUpgradeResult, error) {
	node, err := nodeRepo.Get(repo.WithByID(req.ID))
	if err != nil {
		return nil, buserr.New("ErrRecordNotFound")
	}
	if node.Addr == "" {
		return nil, fmt.Errorf("node %s has no address", node.Name)
	}

	version, err := settingRepo.GetValueByKey("SystemVersion")
	if err != nil || version == "" {
		version = global.CONF.Base.Version
	}
	payload, err := json.Marshal(map[string]string{
		"version": version,
		"channel": upgradeChannel(),
	})
	if err != nil {
		return nil, err
	}
	tlsCfg, err := nodecert.TLSConfig(node.Addr)
	if err != nil {
		return nil, err
	}
	client := &http.Client{
		Timeout:   15 * time.Second,
		Transport: &http.Transport{TLSClientConfig: tlsCfg},
	}
	resp, err := client.Post("https://"+node.Addr+"/api/v2/settings/node/upgrade", "application/json", bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("dispatch upgrade to node %s: %w", node.Name, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusNotFound {
		if err := u.upgradeLegacyNode(client, node, version); err != nil {
			return nil, err
		}
		return &dto.NodeUpgradeResult{Version: version}, nil
	}
	var result dto.Response
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("unexpected node response (status %d): %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	if result.Code != http.StatusOK {
		return nil, fmt.Errorf("node rejected upgrade: %s", result.Message)
	}
	return &dto.NodeUpgradeResult{Version: version}, nil
}

// upgradeLegacyNode bootstraps agents released before the dedicated upgrade
// endpoint existed. It uses their existing mTLS-protected cron API to start one
// fixed, detached upgrade command, then removes the temporary cron entry.
func (u *NodeService) upgradeLegacyNode(client *http.Client, node model.Node, version string) error {
	name := fmt.Sprintf("3panel-agent-upgrade-%d", time.Now().UnixNano())
	url := strings.TrimSuffix(global.RepoURL(), "/") + "/upgrade-agent.sh"
	unit := fmt.Sprintf("3panel-agent-upgrade-%d", time.Now().Unix())
	addr := nodecert.HostOf(node.Addr)
	upgrade := fmt.Sprintf("sleep 2; set -o pipefail; curl -sSfL --connect-timeout 20 --max-time 60 %s | bash", url)
	script := fmt.Sprintf("if command -v systemd-run >/dev/null 2>&1; then systemd-run --unit=%s --collect --no-block --setenv=PANEL3_CHANNEL=%s --setenv=PANEL3_VERSION=%s --setenv=PANEL3_ADDR=%s /bin/bash -c %q; else nohup env PANEL3_CHANNEL=%s PANEL3_VERSION=%s PANEL3_ADDR=%s setsid /bin/bash -c %q >/tmp/3panel-agent-upgrade.log 2>&1 </dev/null & fi", unit, upgradeChannel(), version, addr, upgrade, upgradeChannel(), version, addr, upgrade)
	create := map[string]interface{}{
		"name": name, "type": "shell", "spec": "0 0 1 1 *", "executor": "bash",
		"scriptMode": "input", "script": script, "retainCopies": 1, "retryTimes": 0, "timeout": 15,
	}
	if err := postNodeAPI(client, node.Addr, "/api/v2/cronjobs", create, nil); err != nil {
		return fmt.Errorf("bootstrap legacy node upgrade: %w", err)
	}
	var page struct {
		Items []struct {
			ID uint `json:"id"`
		} `json:"items"`
	}
	search := map[string]interface{}{"page": 1, "pageSize": 10, "info": name, "groupIDs": []uint{}, "orderBy": "name", "order": "ascending"}
	if err := postNodeAPI(client, node.Addr, "/api/v2/cronjobs/search", search, &page); err != nil {
		return fmt.Errorf("find legacy upgrade task: %w", err)
	}
	if len(page.Items) == 0 {
		return fmt.Errorf("legacy upgrade task was not created")
	}
	id := page.Items[0].ID
	if err := postNodeAPI(client, node.Addr, "/api/v2/cronjobs/handle", map[string]uint{"id": id}, nil); err != nil {
		return fmt.Errorf("start legacy upgrade task: %w", err)
	}
	time.Sleep(time.Second)
	_ = postNodeAPI(client, node.Addr, "/api/v2/cronjobs/del", map[string]interface{}{"ids": []uint{id}, "cleanData": true}, nil)
	return nil
}

func postNodeAPI(client *http.Client, addr, path string, payload, data interface{}) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	resp, err := client.Post("https://"+addr+path, "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	var result struct {
		Code    int             `json:"code"`
		Message string          `json:"message"`
		Data    json.RawMessage `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("status %d: %w", resp.StatusCode, err)
	}
	if result.Code != http.StatusOK {
		return fmt.Errorf("%s", result.Message)
	}
	if data != nil && len(result.Data) != 0 {
		return json.Unmarshal(result.Data, data)
	}
	return nil
}

// upgradeChannel mirrors the channel upgrade.go resolves its own releases from.
func upgradeChannel() string {
	if global.CONF.Base.Mode == "dev" {
		return "dev"
	}
	return "stable"
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
	tlsCfg, err := nodecert.TLSConfig(node.Addr)
	if err != nil {
		return
	}
	client := &http.Client{
		Timeout:   remoteProbeTimeout,
		Transport: &http.Transport{TLSClientConfig: tlsCfg},
	}
	var info agentNodeInfo
	if err := u.getJSON(client, "https://"+node.Addr+"/api/v2/dashboard/current/node", &info); err != nil {
		global.LOG.Debugf("node %s (%s) unreachable: %v", node.Name, node.Addr, err)
		if node.Status != nodeStatusOffline {
			node.Status = nodeStatusOffline
			_ = nodeRepo.Update(node.ID, map[string]interface{}{"status": nodeStatusOffline})
		}
		return
	}
	now := time.Now()
	node.Status = nodeStatusOnline
	if info.Version != "" {
		node.Version = info.Version
	}
	node.LastSeenAt = &now
	_ = nodeRepo.Update(node.ID, map[string]interface{}{
		"status":       nodeStatusOnline,
		"version":      node.Version,
		"last_seen_at": now,
	})
}
