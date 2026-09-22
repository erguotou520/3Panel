package multinode

import (
	"net/http"

	"github.com/3panel-dev/3panel/agent/app/dto"
	"github.com/3panel-dev/3panel/agent/app/model"
	"github.com/gin-gonic/gin"
)

type MultiNodeProvider interface {
	IsXpack() bool
	IsUseCustomApp() bool
	GetImagePrefix() string
	RemoveTamper(website string)
	StartClam(startClam *model.Clam, isUpdate bool) (int, error)
	LoadNodeInfo(isBase bool) (model.NodeInfo, error)

	LoadRequestTransport() *http.Transport
	ValidateCertificate(c *gin.Context) bool
	PushSSLToNode(websiteSSL *model.WebsiteSSL) error
	GetAgentInfo() (*dto.AgentInfo, error)
}
