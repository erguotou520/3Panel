//go:build !xpack && !enterprise

package xpack

import "github.com/3panel-dev/3panel/core/utils/xpack/helper"

var AuthProvider = helper.NewIAuthProvider()

var MultiNodeProvider = helper.NewIMultiNodeProvider()
