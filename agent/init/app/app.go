package app

import (
	"github.com/3panel-dev/3panel/agent/utils/docker"
)

func Init() {
	go func() {
		_ = docker.CreateDefaultDockerNetwork()
	}()
}
