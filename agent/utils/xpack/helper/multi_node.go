package helper

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path"
	"path/filepath"
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
//
// The directory is normally /etc/3panel, but local development and the join
// command run the agent without a system install, so BASE_DIR (or NODE_CONFIG_DIR)
// may relocate it somewhere writable.
func NodeConfigDir() string {
	if dir := os.Getenv("NODE_CONFIG_DIR"); dir != "" {
		return dir
	}
	if base := os.Getenv("BASE_DIR"); base != "" {
		return filepath.Join(base, "conf")
	}
	return "/etc/3panel"
}

func NodeConfigPath() string {
	return filepath.Join(NodeConfigDir(), "node.json")
}

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
//
// BASE_DIR and ORIGINAL_VERSION normally come from the 3pctl file written by
// the installer. A bare `go run` (local development, the join command) has no
// such file, so missing values fall back to the current directory and the
// build version instead of aborting startup.
func (m *multiNodeHelper) LoadNodeInfo(isBase bool) (model.NodeInfo, error) {
	var info model.NodeInfo
	info.BaseDir = common.LoadParamsWithoutPanic("BASE_DIR")
	if info.BaseDir == "" {
		if cwd, err := os.Getwd(); err == nil {
			info.BaseDir = cwd
		} else {
			info.BaseDir = "."
		}
	}
	info.Version = common.LoadParamsWithoutPanic("ORIGINAL_VERSION")
	if info.Version == "" {
		info.Version = global.CONF.Base.Version
	}

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
	data, err := os.ReadFile(NodeConfigPath())
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
	dir := NodeConfigDir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create %s failed: %w", dir, err)
	}
	data, err := json.Marshal(nodeConfig{Scope: "node", NodePort: port})
	if err != nil {
		return err
	}
	return os.WriteFile(path.Clean(NodeConfigPath()), data, 0o600)
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
// backups), so it trusts the system roots and verifies certificates.
func (m *multiNodeHelper) LoadRequestTransport() *http.Transport {
	return &http.Transport{
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
