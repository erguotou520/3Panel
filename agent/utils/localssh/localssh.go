// Package localssh owns the runtime helpers for the panel's master-local SSH
// connection: candidate port discovery, the panel-owned key, probing, and the
// stored connection plus its diagnostic note.
//
// The install-time migrations keep their own transaction-scoped copies of the
// probe and the save (they must not touch the live global.DB), but the pure
// helpers (port discovery, key location, error classification) live here so
// both sides stay consistent.
package localssh

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/user"
	"path"
	"strconv"
	"strings"
	"time"

	"gorm.io/gorm"

	"github.com/3panel-dev/3panel/agent/app/model"
	"github.com/3panel-dev/3panel/agent/global"
	"github.com/3panel-dev/3panel/agent/utils/copier"
	"github.com/3panel-dev/3panel/agent/utils/encrypt"
	"github.com/3panel-dev/3panel/agent/utils/ssh"
)

const (
	// PanelKeyName is the private key file the panel owns for the local terminal.
	PanelKeyName = "id_ed25519_3panel"
	// PanelKeyDescription is shown in the certificate list when the panel key
	// is (re)generated.
	PanelKeyDescription = "3Panel Terminal"
	// ConnSettingKey is the settings key of the stored local ssh connection.
	ConnSettingKey = "LocalSSHConn"
	// DiagSettingKey is the settings key of the human readable probe diagnostic.
	DiagSettingKey = "LocalSSHConnDiag"

	defaultSSHPort       = 22
	loopbackAddr         = "127.0.0.1"
	localSSHUser         = "root"
	portScanTimeout      = 300 * time.Millisecond
	localSSHProbeTimeout = 3 * time.Second

	sshdConfigPath = "/etc/ssh/sshd_config"
	sshdConfigDir  = "/etc/ssh/sshd_config.d"
)

// KeyPath returns the absolute path of the panel-owned private key.
func KeyPath() string {
	itemPath := path.Join("/root", ".ssh", PanelKeyName)
	if currentUser, err := user.Current(); err == nil && len(currentUser.HomeDir) != 0 {
		itemPath = path.Join(currentUser.HomeDir, ".ssh", PanelKeyName)
	}
	return itemPath
}

// KeyExists reports whether the panel private key file is on disk.
func KeyExists() bool {
	_, err := os.Stat(KeyPath())
	return err == nil
}

// ReadKey returns the panel private key file.
func ReadKey() ([]byte, error) {
	return os.ReadFile(KeyPath())
}

// Probe dials the candidate loopback ports until the given private key is
// accepted by sshd. It returns the working connection, the ports that were
// tried and the last dial error (non-nil when no port worked).
func Probe(privateKey []byte) (ssh.ConnInfo, []int, error) {
	var (
		portsTried []int
		lastErr    error
	)
	for _, port := range CandidatePorts() {
		conn := ssh.ConnInfo{
			Addr:       loopbackAddr,
			User:       localSSHUser,
			Port:       port,
			AuthMode:   "key",
			PrivateKey: privateKey,
		}
		probe := conn
		probe.DialTimeOut = localSSHProbeTimeout
		client, err := ssh.NewClient(probe)
		if err != nil {
			portsTried = append(portsTried, port)
			lastErr = err
			continue
		}
		client.Close()
		return conn, portsTried, nil
	}
	return ssh.ConnInfo{}, portsTried, lastErr
}

// BuildDiag turns a failed Probe into an actionable, human readable note.
func BuildDiag(portsTried []int, probeErr error) string {
	if probeErr == nil {
		return ""
	}
	ports := strconv.Itoa(defaultSSHPort)
	if len(portsTried) > 0 {
		parts := make([]string, 0, len(portsTried))
		for _, p := range portsTried {
			parts = append(parts, strconv.Itoa(p))
		}
		ports = strings.Join(parts, "、")
	}

	var opErr *net.OpError
	switch {
	case errors.As(probeErr, &opErr):
		return fmt.Sprintf("本机 sshd 端口不可达（sshd 未监听或防火墙拦截）。请确认 sshd 正在监听对应端口。已尝试端口：%s", ports)
	case strings.Contains(probeErr.Error(), "unable to authenticate"):
		return fmt.Sprintf("本机 SSH 服务可达，但 root 的密钥认证被 sshd 拒绝。常见原因：sshd 的 AllowUsers/AllowGroups 未放行本机地址（如 *@127.0.0.1）、PermitRootLogin 禁止密钥登录、或 authorized_keys 缺少 3Panel 公钥（%s.pub）。请修正 sshd 配置后重试。已尝试端口：%s", PanelKeyName, ports)
	case strings.Contains(probeErr.Error(), "passphrase"):
		return fmt.Sprintf("本机 SSH 密钥无法解析（私钥口令不正确或未提供）。请确认终端密钥的口令。已尝试端口：%s", ports)
	default:
		return fmt.Sprintf("本机 SSH 探测失败：%v。已尝试端口：%s", probeErr, ports)
	}
}

// DiagKeyMissing explains why the panel key could not be prepared.
func DiagKeyMissing(err error) string {
	return fmt.Sprintf("无法读取或生成本机终端密钥 %s：%v。请确认当前用户可写 ~/.ssh 目录。", KeyPath(), err)
}

// Save stores the local ssh connection using the same encrypted JSON shape the
// migrations write. The setting row is created when it does not exist yet.
func Save(conn ssh.ConnInfo) error {
	var item model.LocalConnInfo
	_ = copier.Copy(&item, &conn)
	item.PrivateKey = string(conn.PrivateKey)
	item.PassPhrase = ""
	localConn, err := json.Marshal(&item)
	if err != nil {
		return err
	}
	connAfterEncrypt, err := encrypt.StringEncrypt(string(localConn))
	if err != nil {
		return err
	}
	var setting model.Setting
	result := global.DB.Where("key = ?", ConnSettingKey).First(&setting)
	if errors.Is(result.Error, gorm.ErrRecordNotFound) {
		return global.DB.Create(&model.Setting{Key: ConnSettingKey, Value: connAfterEncrypt}).Error
	}
	if result.Error != nil {
		return result.Error
	}
	return global.DB.Model(&setting).UpdateColumn("value", connAfterEncrypt).Error
}

// GetDiag returns the stored diagnostic note ("" when none or unreadable).
func GetDiag() string {
	var setting model.Setting
	if err := global.DB.Where("key = ?", DiagSettingKey).First(&setting).Error; err != nil {
		return ""
	}
	return setting.Value
}

// SetDiag stores the diagnostic note, creating the setting row when missing.
func SetDiag(diag string) error {
	var setting model.Setting
	result := global.DB.Where("key = ?", DiagSettingKey).First(&setting)
	if errors.Is(result.Error, gorm.ErrRecordNotFound) {
		return global.DB.Create(&model.Setting{Key: DiagSettingKey, Value: diag}).Error
	}
	if result.Error != nil {
		return result.Error
	}
	return global.DB.Model(&setting).UpdateColumn("value", diag).Error
}

// ClearDiag removes the stored diagnostic note.
func ClearDiag() error {
	return SetDiag("")
}

// CandidatePorts returns the loopback TCP ports that are most likely to serve
// SSH, ordered by likelihood. Ports are collected from the command lines of
// running sshd processes and from sshd_config, with the ones that already
// accept loopback connections first. Port 22 is always kept as a final
// fallback.
//
// The panel configures its own key for the local connection, so a host whose
// sshd listens on a non-default port (containers, hardened installs,
// sshd_config.d overrides) can never be reached through a hardcoded port.
func CandidatePorts() []int {
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
		raw, err := os.ReadFile(path.Join("/proc", name, "cmdline"))
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
		switch path.Base(strings.Trim(field, `"'`)) {
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
			files = append(files, path.Join(sshdConfigDir, entry.Name()))
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
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(loopbackAddr, strconv.Itoa(port)), portScanTimeout)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}
