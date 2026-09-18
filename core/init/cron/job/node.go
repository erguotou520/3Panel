package job

import (
	"github.com/3panel-dev/3panel/core/app/service"
	"github.com/3panel-dev/3panel/core/global"
)

// NodeHealthJob keeps node reachability fresh without an operator having to hit
// the check button. Each run is a mutually authenticated handshake per node.
type NodeHealthJob struct{}

func NewNodeHealthJob() *NodeHealthJob {
	return &NodeHealthJob{}
}

func (n *NodeHealthJob) Run() {
	if _, err := service.NewINodeService().Check(); err != nil {
		global.LOG.Errorf("[core] node health check failed: %v", err)
	}
}
