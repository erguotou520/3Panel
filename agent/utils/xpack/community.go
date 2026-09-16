//go:build !xpack && !enterprise

package xpack

import "github.com/3panel-dev/3panel/agent/utils/xpack/helper"

var AlertProvider = helper.NewIAlertProvider()

var MultiNodeProvider = helper.NewIMultiNodeProvider()
