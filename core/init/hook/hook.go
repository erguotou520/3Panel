package hook

import (
	"os/exec"
	"strings"

	"github.com/3panel-dev/3panel/core/app/repo"
	"github.com/3panel-dev/3panel/core/app/service"
	"github.com/3panel-dev/3panel/core/constant"
	"github.com/3panel-dev/3panel/core/global"
	"github.com/3panel-dev/3panel/core/utils/common"
	"github.com/3panel-dev/3panel/core/utils/ctl_conf"
	"github.com/3panel-dev/3panel/core/utils/encrypt"
	coreauth "github.com/3panel-dev/3panel/core/platform/auth"
)

func Init() {
	settingRepo := repo.NewISettingRepo()
	storedVersion, _ := settingRepo.GetValueByKey("SystemVersion")
	if storedVersion != global.CONF.Base.Version {
		if err := settingRepo.Update("SystemVersion", global.CONF.Base.Version); err != nil {
			global.LOG.Fatalf("sync system version before start failed, err: %v", err)
		}
		global.LOG.Infof("sync system version from installed package: %s -> %s", storedVersion, global.CONF.Base.Version)
	}
	global.CONF.Conn.Port, _ = settingRepo.GetValueByKey("ServerPort")
	global.CONF.Conn.Ipv6, _ = settingRepo.GetValueByKey("Ipv6")
	global.CONF.Base.Edition, _ = settingRepo.GetValueByKey("Edition")
	global.CONF.Conn.BindAddress, _ = settingRepo.GetValueByKey("BindAddress")
	global.CONF.Conn.SSL, _ = settingRepo.GetValueByKey("SSL")
	if err := settingRepo.Update("SystemStatus", "Free"); err != nil {
		global.LOG.Fatalf("init service before start failed, err: %v", err)
	}

	handleUserInfo(global.CONF.Base.ChangeUserInfo, settingRepo)

	generateKey()
	initDockerConf()
}

func handleUserInfo(tags string, settingRepo repo.ISettingRepo) {
	if len(tags) == 0 {
		return
	}
	settingMap := make(map[string]string)
	if tags == "use_existing" {
		settingMap["ServerPort"] = ctl_conf.Load("ORIGINAL_PORT")
		global.CONF.Conn.Port = settingMap["ServerPort"]
		settingMap["UserName"] = global.CONF.Base.Username
		settingMap["Password"] = global.CONF.Base.Password
		settingMap["SecurityEntrance"] = global.CONF.Conn.Entrance
		settingMap["SystemVersion"] = ctl_conf.Load("ORIGINAL_VERSION")
		global.CONF.Base.Version = settingMap["SystemVersion"]
		settingMap["Language"] = global.CONF.Base.Language
	}
	if tags == "all" {
		settingMap["UserName"] = common.RandStrAndNum(10)
		settingMap["Password"] = common.RandStrAndNum(10)
		settingMap["SecurityEntrance"] = common.RandStrAndNum(10)
	}
	if strings.Contains(global.CONF.Base.ChangeUserInfo, "username") {
		settingMap["UserName"] = common.RandStrAndNum(10)
	}
	if strings.Contains(global.CONF.Base.ChangeUserInfo, "password") {
		settingMap["Password"] = common.RandStrAndNum(10)
	}
	if strings.Contains(global.CONF.Base.ChangeUserInfo, "entrance") {
		settingMap["SecurityEntrance"] = common.RandStrAndNum(10)
	}
	if global.CONF.Base.IsEnterprise {
		if len(settingMap["UserName"]) != 0 || len(settingMap["Password"]) != 0 {
			if err := coreauth.Provider.ResetSuperAdminUser(settingMap["UserName"], settingMap["Password"]); err != nil {
				global.LOG.Fatalf("reset enterprise super admin failed, err: %v", err)
				return
			}
		}
	} else {
		for key, val := range settingMap {
			if len(val) == 0 {
				continue
			}
			if key == "Password" {
				val, _ = encrypt.StringEncrypt(val)
			}
			if err := settingRepo.Update(key, val); err != nil {
				global.LOG.Errorf("update %s before start failed, err: %v", key, err)
			}
		}
	}

	_ = ctl_conf.RemoveValueFromFile("/usr/local/bin/3pctl", "CHANGE_USER_INFO", global.CONF.Base.ChangeUserInfo)
	_ = ctl_conf.UpdateInFile("/usr/local/bin/3pctl", "ORIGINAL_PASSWORD", "**********")
}

func generateKey() {
	if err := service.NewISettingService().GenerateRSAKey(); err != nil {
		global.LOG.Errorf("generate rsa key error : %s", err.Error())
	}
}

func initDockerConf() {
	dockerPath, err := exec.LookPath("docker")
	if err != nil {
		return
	}
	if strings.Contains(dockerPath, "snap") {
		constant.DaemonJsonPath = "/var/snap/docker/current/config/daemon.json"
	}
}
