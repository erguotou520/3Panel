package utils

import (
	"github.com/3panel-dev/3panel/agent/utils/localssh"
)

// CandidateLocalSSHPorts returns the loopback TCP ports that are most likely to
// serve SSH, ordered by likelihood, with port 22 always kept as a final
// fallback.
//
// Kept as a thin delegating wrapper for the migration layer: the implementation
// lives in agent/utils/localssh so the runtime (on-demand self-heal of the local
// SSH connection) and the install-time migrations share one port discovery.
func CandidateLocalSSHPorts() []int {
	return localssh.CandidatePorts()
}
