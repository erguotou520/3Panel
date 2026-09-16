package session

import (
	"github.com/3panel-dev/3panel/core/global"
	"github.com/3panel-dev/3panel/core/init/session/psession"
)

func Init() {
	global.SESSION = psession.NewPSession("")
	global.LOG.Info("init in-memory session successfully")
}
