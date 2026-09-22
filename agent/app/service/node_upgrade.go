package service

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/3panel-dev/3panel/agent/app/dto"
	"github.com/3panel-dev/3panel/agent/global"
)

var (
	nodeUpgradeRunning atomic.Bool
	nodeVersionPattern = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$`)
)

func StartNodeUpgrade(req dto.NodeUpgrade) error {
	if global.IsMaster {
		return fmt.Errorf("node upgrade is only available in node mode")
	}
	if !nodeVersionPattern.MatchString(req.Version) {
		return fmt.Errorf("invalid target version %q", req.Version)
	}
	if req.Channel != "stable" && req.Channel != "dev" {
		return fmt.Errorf("invalid upgrade channel %q", req.Channel)
	}
	if !nodeUpgradeRunning.CompareAndSwap(false, true) {
		return fmt.Errorf("node upgrade is already running")
	}
	if err := startDetachedNodeUpgrade(req); err != nil {
		nodeUpgradeRunning.Store(false)
		return err
	}
	// If the upgrade fails before restarting the agent, allow a later retry.
	time.AfterFunc(15*time.Minute, func() { nodeUpgradeRunning.Store(false) })
	return nil
}

func startDetachedNodeUpgrade(req dto.NodeUpgrade) error {
	url := strings.TrimSuffix(global.RepoURL(), "/") + "/upgrade-agent.sh"
	shellCommand := fmt.Sprintf("sleep 2; set -o pipefail; curl -sSfL --connect-timeout 20 --max-time 60 %s | bash", url)
	env := append(os.Environ(),
		"PANEL3_CHANNEL="+req.Channel,
		"PANEL3_VERSION="+req.Version,
	)
	nodeAddr := outboundIP()
	if nodeAddr != "" {
		env = append(env, "PANEL3_ADDR="+nodeAddr)
	}

	if _, err := os.Stat("/run/systemd/system"); err == nil {
		if systemdRun, lookErr := exec.LookPath("systemd-run"); lookErr == nil {
			unit := "3panel-agent-upgrade-" + strconv.FormatInt(time.Now().Unix(), 10)
			args := []string{
				"--unit=" + unit,
				"--collect",
				"--no-block",
				"--setenv=PANEL3_CHANNEL=" + req.Channel,
				"--setenv=PANEL3_VERSION=" + req.Version,
			}
			if nodeAddr != "" {
				args = append(args, "--setenv=PANEL3_ADDR="+nodeAddr)
			}
			args = append(args, "/bin/bash", "-c", shellCommand)
			cmd := exec.Command(systemdRun, args...)
			if output, runErr := cmd.CombinedOutput(); runErr != nil {
				return fmt.Errorf("schedule systemd upgrade: %w: %s", runErr, strings.TrimSpace(string(output)))
			}
			return nil
		}
	}

	logFile, err := os.OpenFile("/tmp/3panel-agent-upgrade.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("open upgrade log: %w", err)
	}
	cmd := exec.Command("/bin/bash", "-c", shellCommand)
	cmd.Env = env
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		_ = logFile.Close()
		return fmt.Errorf("start detached upgrade: %w", err)
	}
	_ = logFile.Close()
	return nil
}

func outboundIP() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return ""
	}
	defer conn.Close()
	if addr, ok := conn.LocalAddr().(*net.UDPAddr); ok && addr.IP != nil {
		return addr.IP.String()
	}
	return ""
}
