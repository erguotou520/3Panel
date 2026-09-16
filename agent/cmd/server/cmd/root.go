package cmd

import (
	"github.com/3panel-dev/3panel/agent/server"
	"github.com/spf13/cobra"
)

var RootCmd = &cobra.Command{
	Use: "3panel-agent",
	RunE: func(cmd *cobra.Command, args []string) error {
		server.Start()
		return nil
	},
}
