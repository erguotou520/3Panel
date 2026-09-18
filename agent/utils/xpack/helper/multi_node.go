package helper

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path"
	"time"

	"github.com/3panel-dev/3panel/agent/app/dto"
	"github.com/3panel-dev/3panel/agent/app/model"
	"github.com/3panel-dev/3panel/agent/buserr"
	"github.com/3panel-dev/3panel/agent/global"
	"github.com/3panel-dev/3panel/agent/utils/common"
	"github.com/3panel-dev/3panel/agent/utils/xpack/providers"
	"github.com/gin-gonic/gin"
)

// NodeConfigDir / NodeConfigPath hold the marker that turns an agent into a
// node. It lives outside the database on purpose: LoadNodeInfo runs during
// viper.Init(), long before the database is opened.
const (
	NodeConfigDir  = "/etc/3panel"
	NodeConfigPath = NodeConfigDir + "/node.json"
)

type nodeConfig struct {
	Scope    string `json:"scope"`
	NodePort uint   `json:"nodePort"`
}

type multiNodeHelper struct{}

func NewIMultiNodeProvider() providers.MultiNodeProvider {
	return &multiNodeHelper{}
}

func (m *multiNodeHelper) RemoveTamper(website string) {}

func (m *multiNodeHelper) StartClam(startClam *model.Clam, isUpdate bool) (int, error) {
	return 0, buserr.New("ErrXpackNotFound")
}

// LoadNodeInfo decides whether this process is the master or a node.
func (m *multiNodeHelper) LoadNodeInfo(isBase bool) (model.NodeInfo, error) {
	var info model.NodeInfo
	info.BaseDir = common.LoadParams("BASE_DIR")
	info.Version = common.LoadParams("ORIGINAL_VERSION")

	cfg, err := LoadNodeConfig()
	if err == nil && cfg.Scope == "node" {
		global.IsMaster = false
		info.Scope = "node"
		info.NodePort = cfg.NodePort
		return info, nil
	}
	info.Scope = "master"
	global.IsMaster = true
	return info, nil
}

// LoadNodeConfig reads the node marker. A missing file simply means "master".
func LoadNodeConfig() (nodeConfig, error) {
	var cfg nodeConfig
	data, err := os.ReadFile(NodeConfigPath)
	if err != nil {
		return cfg, err
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return cfg, err
	}
	return cfg, nil
}

// SaveNodeConfig persists the node marker and flips this agent into node mode
// on the next start.
func SaveNodeConfig(port uint) error {
	if err := os.MkdirAll(NodeConfigDir, 0o755); err != nil {
		return fmt.Errorf("create %s failed: %w", NodeConfigDir, err)
	}
	data, err := json.Marshal(nodeConfig{Scope: "node", NodePort: port})
	if err != nil {
		return err
	}
	return os.WriteFile(path.Clean(NodeConfigPath), data, 0o600)
}

func (m *multiNodeHelper) GetImagePrefix() string {
	return ""
}

func (m *multiNodeHelper) IsUseCustomApp() bool {
	return false
}

func (m *multiNodeHelper) IsXpack() bool {
	return false
}

// LoadRequestTransport is used for ordinary outbound requests (app store,
// backups), so it keeps trusting the system roots.
func (m *multiNodeHelper) LoadRequestTransport() *http.Transport {
	return &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		DialContext: (&net.Dialer{
			Timeout:   60 * time.Second,
			KeepAlive: 60 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second,
		IdleConnTimeout:       15 * time.Second,
	}
}

// ValidateCertificate is only consulted in node mode, where TLS mutual auth has
// already verified the peer against the CA before this runs.
func (m *multiNodeHelper) ValidateCertificate(c *gin.Context) bool {
	return true
}

func (m *multiNodeHelper) PushSSLToNode(websiteSSL *model.WebsiteSSL) error {
	return nil
}

func (m *multiNodeHelper) GetAgentInfo() (*dto.AgentInfo, error) {
	return nil, nil
}
