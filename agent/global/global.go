package global

import (
	"context"
	"sync"

	badger_db "github.com/3panel-dev/3panel/agent/init/cache/db"
	"github.com/go-playground/validator/v10"
	"github.com/nicksnyder/go-i18n/v2/i18n"
	"github.com/robfig/cron/v3"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"gorm.io/gorm"
)

var (
	DB           *gorm.DB
	MonitorDB    *gorm.DB
	GPUMonitorDB *gorm.DB
	TaskDB       *gorm.DB
	CoreDB       *gorm.DB
	AlertDB      *gorm.DB

	LOG   *logrus.Logger
	CONF  ServerConfig
	VALID *validator.Validate
	CACHE *badger_db.Cache
	Viper *viper.Viper

	Dir SystemDir

	Cron          *cron.Cron
	MonitorCronID cron.EntryID

	IsMaster bool

	I18n *i18n.Localizer

	AlertBaseJobID     cron.EntryID
	AlertResourceJobID cron.EntryID

	TaskCtxMap = make(map[string]context.CancelFunc)
	taskCtxMu  sync.RWMutex
)

func RegisterTaskCancel(taskID string, cancel context.CancelFunc) {
	taskCtxMu.Lock()
	defer taskCtxMu.Unlock()
	TaskCtxMap[taskID] = cancel
}

func LoadTaskCancel(taskID string) (context.CancelFunc, bool) {
	taskCtxMu.RLock()
	defer taskCtxMu.RUnlock()
	cancel, ok := TaskCtxMap[taskID]
	return cancel, ok
}

func RemoveTaskCancel(taskID string) {
	taskCtxMu.Lock()
	defer taskCtxMu.Unlock()
	delete(TaskCtxMap, taskID)
}

func RepoURL() string {
	if CONF.Base.IsEnterprise {
		return "https://resource.3panel.pro/package/enterprise"
	}
	if CONF.Base.IsFxplay {
		return "https://resource.3panel.pro/package/fusionxplay"
	}
	if CONF.Base.Edition != "intl" {
		return "https://resource.3panel.pro/package/v2"
	}
	return "https://resource.3panel.pro/v2"
}
func ResourceURL() string {
	if CONF.Base.IsEnterprise {
		return "https://resource.3panel.pro/resource/v2"
	}
	if CONF.Base.IsFxplay {
		return "https://resource.3panel.pro/resource/v2"
	}
	if CONF.Base.Edition != "intl" {
		return "https://resource.3panel.pro/resource/v2"
	}
	return "https://resource.3panel.pro/v2/resource"
}
func AppRepoURL() string {
	if CONF.Base.IsEnterprise {
		return "https://apps.3panel.pro"
	}
	if CONF.Base.IsFxplay {
		return "https://apps.3panel.pro"
	}
	if CONF.Base.Edition != "intl" {
		return "https://apps.3panel.pro"
	}
	return "https://apps.3panel.pro"
}
