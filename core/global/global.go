package global

import (
	"github.com/3panel-dev/3panel/core/init/auth"
	"github.com/3panel-dev/3panel/core/init/session/psession"
	"github.com/go-playground/validator/v10"
	"github.com/nicksnyder/go-i18n/v2/i18n"
	"github.com/robfig/cron/v3"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"gorm.io/gorm"
)

var (
	DB      *gorm.DB
	AlertDB *gorm.DB
	TaskDB  *gorm.DB
	AgentDB *gorm.DB
	LOG     *logrus.Logger
	CONF    ServerConfig
	VALID   *validator.Validate
	SESSION *psession.PSession
	Viper   *viper.Viper

	I18n       *i18n.Localizer
	I18nForCmd *i18n.Localizer

	Cron *cron.Cron

	ScriptSyncJobID cron.EntryID

	IPTracker *auth.IPTracker
)

type DBOption func(*gorm.DB) *gorm.DB

func RepoURL() string {
	if CONF.Base.IsEnterprise {
		return "https://3panel.erguotou.me/package/enterprise"
	}
	if CONF.Base.IsFxplay {
		return "https://3panel.erguotou.me/package/fusionxplay"
	}
	if CONF.Base.Edition != "intl" {
		return "https://3panel.erguotou.me/package"
	}
	return "https://3panel.erguotou.me/package"
}
func ResourceURL() string {
	if CONF.Base.IsEnterprise {
		return "https://3panel.erguotou.me/resource"
	}
	if CONF.Base.IsFxplay {
		return "https://3panel.erguotou.me/resource"
	}
	if CONF.Base.Edition != "intl" {
		return "https://3panel.erguotou.me/resource"
	}
	return "https://3panel.erguotou.me/resource"
}
func AppRepoURL() string {
	if CONF.Base.IsEnterprise {
		return "https://3panel.erguotou.me"
	}
	if CONF.Base.IsFxplay {
		return "https://3panel.erguotou.me"
	}
	if CONF.Base.Edition != "intl" {
		return "https://3panel.erguotou.me"
	}
	return "https://3panel.erguotou.me"
}
