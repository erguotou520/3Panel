package utils

import (
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	defaultSSHPort = 22
	probeTimeout   = 300 * time.Millisecond
	sshdConfigPath = "/etc/ssh/sshd_config"
	sshdConfigDir  = "/etc/ssh/sshd_config.d"
)

// CandidateLocalSSHPorts returns the loopback TCP ports that are most likely to
// serve SSH, ordered by likelihood. Ports are collected from the command lines of
// running sshd processes and from sshd_config, with the ones that already accept
// loopback connections first. Port 22 is always kept as a final fallback.
//
// The panel configures its own key for the local connection, so a host whose sshd
// listens on a non-default port (containers, hardened installs, sshd_config.d
// overrides) can never be reached through a hardcoded port.
func CandidateLocalSSHPorts() []int {
	var ports []int
	seen := make(map[int]bool)
	add := func(port int) {
		if port < 1 || port > 65535 || seen[port] {
			return
		}
		seen[port] = true
		ports = append(ports, port)
	}

	detected := append(sshdProcessPorts(), sshdConfigPorts()...)
	for _, port := range detected {
		if isLoopbackListening(port) {
			add(port)
		}
	}
	for _, port := range detected {
		add(port)
	}
	add(defaultSSHPort)
	return ports
}

// sshdProcessPorts reads the -p / Port= arguments of every running sshd process.
func sshdProcessPorts() []int {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	var ports []int
	for _, entry := range entries {
		name := entry.Name()
		if len(name) == 0 || name[0] < '0' || name[0] > '9' {
			continue
		}
		raw, err := os.ReadFile(filepath.Join("/proc", name, "cmdline"))
		if err != nil || len(raw) == 0 {
			continue
		}
		// Arguments are NUL separated, but some launchers (container supervisors
		// included) collapse the whole command line into argv[0], so normalize the
		// raw buffer into a single space separated line before parsing.
		line := strings.ReplaceAll(string(raw), "\x00", " ")
		ports = append(ports, portsFromSSHDCommandLine(line)...)
	}
	return ports
}

// portsFromSSHDCommandLine extracts the ports from an sshd command line such as
// "/usr/sbin/sshd -e -p 36000 -o PermitRootLogin=yes". It only accepts lines that
// really belong to sshd, and ignores unrelated numbers (listener counters,
// version strings, ...).
func portsFromSSHDCommandLine(line string) []int {
	fields := strings.Fields(line)
	if !isSSHDCommandLine(fields) {
		return nil
	}
	var ports []int
	for i, field := range fields {
		value := strings.Trim(field, `"'`)
		switch {
		case value == "-p" && i+1 < len(fields):
			if port, err := strconv.Atoi(strings.Trim(fields[i+1], `"'`)); err == nil {
				ports = append(ports, port)
			}
		case strings.HasPrefix(value, "-p") && len(value) > 2:
			if port, err := strconv.Atoi(strings.Trim(value[2:], `"'`)); err == nil {
				ports = append(ports, port)
			}
		case strings.HasPrefix(value, "Port="):
			if port, err := strconv.Atoi(strings.TrimPrefix(value, "Port=")); err == nil {
				ports = append(ports, port)
			}
		}
	}
	return ports
}

func isSSHDCommandLine(fields []string) bool {
	for _, field := range fields {
		switch filepath.Base(strings.Trim(field, `"'`)) {
		case "sshd", "sshd:":
			return true
		}
	}
	return false
}

// sshdConfigPorts reads Port directives from sshd_config and its conf.d drop-ins.
func sshdConfigPorts() []int {
	files := []string{sshdConfigPath}
	if entries, err := os.ReadDir(sshdConfigDir); err == nil {
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".conf") {
				continue
			}
			files = append(files, filepath.Join(sshdConfigDir, entry.Name()))
		}
	}
	var ports []int
	for _, file := range files {
		ports = append(ports, portsFromSSHDConfig(file)...)
	}
	return ports
}

func portsFromSSHDConfig(file string) []int {
	raw, err := os.ReadFile(file)
	if err != nil {
		return nil
	}
	var ports []int
	for _, line := range strings.Split(string(raw), "\n") {
		if idx := strings.IndexByte(line, '#'); idx >= 0 {
			line = line[:idx]
		}
		fields := strings.Fields(line)
		if len(fields) != 2 || !strings.EqualFold(fields[0], "Port") {
			continue
		}
		if port, err := strconv.Atoi(fields[1]); err == nil {
			ports = append(ports, port)
		}
	}
	return ports
}

func isLoopbackListening(port int) bool {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), probeTimeout)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}
