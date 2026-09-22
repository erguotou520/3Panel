package multinode

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"strings"
	"sync"
	"time"

	"github.com/3panel-dev/3panel/core/app/model"
	"github.com/3panel-dev/3panel/core/global"
	"github.com/3panel-dev/3panel/core/init/proxy"
	"github.com/3panel-dev/3panel/core/utils/nodecert"
	"github.com/3panel-dev/3panel/core/utils/ssh"
	"github.com/gin-gonic/gin"
)

const (
	// localNodeName is how the master addresses itself. It is never stored in
	// the nodes table.
	localNodeName = "local"

	nodeCacheTTL         = 10 * time.Second
	nodeDialTimeout      = 10 * time.Second
	nodeKeepAlive        = 60 * time.Second
	nodeIdleConnTimeout  = 60 * time.Second
	nodeHandshakeTimeout = 10 * time.Second
)

type multiNodeHelper struct{}

func NewProvider() IProvider {
	return &multiNodeHelper{}
}

// nodeAddrCache keeps the address of a node for a few seconds. Every proxied
// request would otherwise cost a database round trip.
var (
	nodeAddrCache  sync.Map // node name -> nodeCacheItem
	nodeTransports sync.Map // name|addr -> *http.Transport
)

type nodeCacheItem struct {
	addr   string
	expire time.Time
}

/* ------------------------------------------------------------------ proxy */

func (m *multiNodeHelper) Proxy(c *gin.Context, currentNode string) {
	if currentNode == localNodeName || currentNode == "" {
		serveLocalAgent(c)
		return
	}
	transport, addr, err := nodeTransport(currentNode)
	if err != nil {
		global.LOG.Errorf("proxy to node %s failed: %v", currentNode, err)
		c.AbortWithStatusJSON(http.StatusBadGateway, gin.H{"message": err.Error()})
		return
	}
	rp := &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			if r.In.Form == nil {
				r.Out.URL.RawQuery = r.In.URL.RawQuery
			}
			r.SetXForwarded()
			r.Out.URL.Scheme = "https"
			r.Out.URL.Host = addr
		},
		Transport: transport,
		ErrorHandler: func(rw http.ResponseWriter, req *http.Request, err error) {
			rw.WriteHeader(http.StatusBadGateway)
			_, _ = rw.Write([]byte("Bad Gateway: " + err.Error()))
		},
	}
	defer func() {
		if err := recover(); err != nil && err != http.ErrAbortHandler {
			global.LOG.Debug(err)
		}
	}()
	rp.ServeHTTP(c.Writer, c.Request)
	c.Abort()
}

func serveLocalAgent(c *gin.Context) {
	defer func() {
		if err := recover(); err != nil && err != http.ErrAbortHandler {
			global.LOG.Debug(err)
		}
	}()
	proxy.LocalAgentProxy.ServeHTTP(c.Writer, c.Request)
	c.Abort()
}

/* -------------------------------------------------------------- transport */

// nodeTransport returns a cached, mutually authenticated transport for one node.
// The client certificate is presented to the agent, and the agent's server
// certificate is validated against the panel CA.
func nodeTransport(nodeName string) (*http.Transport, string, error) {
	addr, err := nodeAddr(nodeName)
	if err != nil {
		return nil, "", err
	}
	key := nodeName + "|" + addr
	if cached, ok := nodeTransports.Load(key); ok {
		return cached.(*http.Transport), addr, nil
	}
	transport, err := buildNodeTransport(addr)
	if err != nil {
		return nil, "", err
	}
	nodeTransports.Store(key, transport)
	return transport, addr, nil
}

func buildNodeTransport(addr string) (*http.Transport, error) {
	tlsConfig, err := nodecert.TLSConfig(addr)
	if err != nil {
		return nil, fmt.Errorf("build node tls config: %w", err)
	}
	return &http.Transport{
		TLSClientConfig: tlsConfig,
		DialContext: (&net.Dialer{
			Timeout:   nodeDialTimeout,
			KeepAlive: nodeKeepAlive,
		}).DialContext,
		ForceAttemptHTTP2:   false,
		MaxIdleConns:        50,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     nodeIdleConnTimeout,
		TLSHandshakeTimeout: nodeHandshakeTimeout,
	}, nil
}

// nodeAddr resolves a node name to its address, with a short cache.
func nodeAddr(nodeName string) (string, error) {
	if cached, ok := nodeAddrCache.Load(nodeName); ok {
		item := cached.(nodeCacheItem)
		if time.Now().Before(item.expire) {
			return item.addr, nil
		}
	}
	var node model.Node
	if err := global.DB.Where("name = ?", nodeName).First(&node).Error; err != nil {
		nodeAddrCache.Delete(nodeName)
		return "", fmt.Errorf("node %s is not registered", nodeName)
	}
	if node.Addr == "" {
		return "", fmt.Errorf("node %s has no address yet", nodeName)
	}
	nodeAddrCache.Store(nodeName, nodeCacheItem{addr: node.Addr, expire: time.Now().Add(nodeCacheTTL)})
	return node.Addr, nil
}

/* --------------------------------------------------------------- unused */

func (m *multiNodeHelper) ProxyDocker(proxyURL string) error { return nil }

// UpdateGroup moves every node of one group to another, so deleting a group
// never leaves nodes pointing at a group that no longer exists.
func (m *multiNodeHelper) UpdateGroup(name string, group, newGroup uint) error {
	if !strings.EqualFold(name, "node") {
		return nil
	}
	return global.DB.Model(&model.Node{}).
		Where("group_id = ?", group).
		Update("group_id", newGroup).Error
}

func (m *multiNodeHelper) CheckBackupUsed(name string) error { return nil }

func (m *multiNodeHelper) LoadNodeInfo(currentNode string) (*ssh.ConnInfo, string, error) {
	return nil, "", nil
}

// LoadRequestTransport is used for ordinary outbound requests (app store,
// upgrades, backup accounts), not for talking to nodes. It trusts the system
// roots, so certificate verification stays enabled.
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

func (m *multiNodeHelper) Sync(dataType string) error { return nil }

func (m *multiNodeHelper) AutoUpgradeWithMaster() {}
