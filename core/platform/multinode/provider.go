package multinode

import (
	"net/http"

	"github.com/3panel-dev/3panel/core/utils/ssh"
	"github.com/gin-gonic/gin"
)

type IProvider interface {
	Proxy(c *gin.Context, currentNode string)
	ProxyDocker(proxyURL string) error
	UpdateGroup(name string, group, newGroup uint) error
	CheckBackupUsed(name string) error
	LoadNodeInfo(currentNode string) (*ssh.ConnInfo, string, error)
	Sync(dataType string) error
	AutoUpgradeWithMaster()

	LoadRequestTransport() *http.Transport
}
