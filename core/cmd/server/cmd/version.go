package cmd

import (
	"fmt"

	"github.com/3panel-dev/3panel/core/cmd/server/conf"
	"github.com/3panel-dev/3panel/core/global"
	"github.com/3panel-dev/3panel/core/i18n"
	"gopkg.in/yaml.v3"

	"github.com/spf13/cobra"
)

func init() {
	RootCmd.AddCommand(versionCmd)
}

var versionCmd = &cobra.Command{
	Use: "version",
	RunE: func(cmd *cobra.Command, args []string) error {
		i18n.UseI18nForCmd(language)
		if !isRoot() {
			fmt.Println(i18n.GetMsgWithMapForCmd("SudoHelper", map[string]interface{}{"cmd": "sudo 3pctl version"}))
			return nil
		}
		db, err := loadDBConn("core.db")
		if err != nil {
			return err
		}
		version := getSettingByKey(db, "SystemVersion")

		fmt.Println(i18n.GetMsgByKeyForCmd("SystemVersion") + version)
		config := global.ServerConfig{}
		if err := yaml.Unmarshal(conf.AppYaml, &config); err != nil {
			return fmt.Errorf("unmarshal conf.App.Yaml failed, err: %v", err)
		} else {
			fmt.Println(i18n.GetMsgByKeyForCmd("SystemMode") + config.Base.Mode)
		}
		return nil
	},
}
