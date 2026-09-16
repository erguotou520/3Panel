package cache

import (
	"github.com/3panel-dev/3panel/agent/global"
	cachedb "github.com/3panel-dev/3panel/agent/init/cache/db"
)

func Init() {
	global.CACHE = cachedb.NewCacheDB()
}
