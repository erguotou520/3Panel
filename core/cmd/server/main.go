package main

import (
	"fmt"
	"os"

	"github.com/3panel-dev/3panel/core/cmd/server/cmd"
	_ "github.com/3panel-dev/3panel/core/cmd/server/docs"
)

// @title 3Panel
// @version 2.0
// @description Top-Rated Web-based Linux Server Management Tool
// @termsOfService http://swagger.io/terms/
// @license.name GPL-3.0
// @license.url https://www.gnu.org/licenses/gpl-3.0.html
// @BasePath /api/v2
// @schemes http https

// @securityDefinitions.apikey ApiKeyAuth
// @description Custom Token Format, Format: md5('3panel' + API-Key + UnixTimestamp).
// @description ```
// @description eg:
// @description curl -X GET "http://{host}:{port}/api/v2/toolbox/device/base" \
// @description -H "3Panel-Token: <3panel_token>" \
// @description -H "3Panel-Timestamp: <current_unix_timestamp>"
// @description ```
// @description - `3Panel-Token` is the key for the panel API Key.
// @type apiKey
// @in Header
// @name 3Panel-Token
// @securityDefinitions.apikey Timestamp
// @type apiKey
// @in header
// @name 3Panel-Timestamp
// @description - `3Panel-Timestamp` is the Unix timestamp of the current time in seconds.

func main() {
	if err := cmd.RootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
