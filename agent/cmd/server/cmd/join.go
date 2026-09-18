package cmd

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/3panel-dev/3panel/agent/app/repo"
	"github.com/3panel-dev/3panel/agent/init/db"
	"github.com/3panel-dev/3panel/agent/init/dir"
	"github.com/3panel-dev/3panel/agent/init/log"
	"github.com/3panel-dev/3panel/agent/init/migration"
	"github.com/3panel-dev/3panel/agent/init/viper"
	"github.com/3panel-dev/3panel/agent/utils/common"
	"github.com/3panel-dev/3panel/agent/utils/encrypt"
	"github.com/3panel-dev/3panel/agent/utils/xpack/helper"
	"github.com/spf13/cobra"
)

const (
	joinRequestTimeout = 30 * time.Second
	defaultNodePort    = 9999
)

var (
	joinMaster string
	joinToken  string
	joinAddr   string
	joinPort   uint
)

var joinCmd = &cobra.Command{
	Use:   "join",
	Short: "Join this host to a 3Panel master as a managed node",
	Long: "Exchanges a one time token for the certificates this agent needs, then\n" +
		"switches it into node mode. Restart the agent afterwards.",
	RunE: runJoin,
}

func init() {
	joinCmd.Flags().StringVar(&joinMaster, "master", "", "master url, e.g. https://10.0.0.1:9999")
	joinCmd.Flags().StringVar(&joinToken, "token", "", "one time join token issued by the master")
	joinCmd.Flags().StringVar(&joinAddr, "addr", "", "address the master should use to reach this host (auto detected when empty)")
	joinCmd.Flags().UintVar(&joinPort, "port", defaultNodePort, "port this node listens on")
	_ = joinCmd.MarkFlagRequired("master")
	_ = joinCmd.MarkFlagRequired("token")
	RootCmd.AddCommand(joinCmd)
}

func runJoin(cmd *cobra.Command, args []string) error {
	if joinPort == 0 {
		joinPort = defaultNodePort
	}
	host := joinAddr
	if host == "" {
		detected, err := detectOutboundIP()
		if err != nil {
			return fmt.Errorf("could not detect this host's address, pass --addr explicitly: %w", err)
		}
		host = detected
	}
	// The master reaches this node on the node's own port, so the port is part
	// of the stored address while the certificate SANs only carry the host.
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", joinPort))

	result, err := requestCertificates(addr)
	if err != nil {
		return err
	}

	viper.Init()
	dir.Init()
	log.Init()
	db.Init()
	migration.Init()

	settingRepo := repo.NewISettingRepo()
	for key, value := range map[string]string{
		"ServerCrt": result.Data.ServerCrt,
		"ServerKey": result.Data.ServerKey,
		"RootCrt":   result.Data.RootCrt,
	} {
		encrypted, encErr := encrypt.StringEncrypt(value)
		if encErr != nil {
			return fmt.Errorf("encrypt %s failed: %w", key, encErr)
		}
		if err := settingRepo.UpdateOrCreate(key, encrypted); err != nil {
			return fmt.Errorf("save %s failed: %w", key, err)
		}
	}

	port := result.Data.NodePort
	if port == 0 {
		port = joinPort
	}
	if err := helper.SaveNodeConfig(port); err != nil {
		return fmt.Errorf("write node config failed: %w", err)
	}

	fmt.Printf("joined master %s as node %q (%s)\n", joinMaster, result.Data.Name, addr)
	fmt.Println("restart the agent to serve in node mode: systemctl restart 3panel-agent")
	return nil
}

type joinResponse struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    struct {
		Name      string `json:"name"`
		ServerCrt string `json:"serverCrt"`
		ServerKey string `json:"serverKey"`
		RootCrt   string `json:"rootCrt"`
		NodePort  uint   `json:"nodePort"`
	} `json:"data"`
}

func requestCertificates(addr string) (*joinResponse, error) {
	payload, err := json.Marshal(map[string]interface{}{
		"token":   joinToken,
		"addr":    addr,
		"port":    joinPort,
		"baseDir": common.LoadParamsWithoutPanic("BASE_DIR"),
		"version": common.LoadParamsWithoutPanic("ORIGINAL_VERSION"),
	})
	if err != nil {
		return nil, err
	}
	url := strings.TrimSuffix(joinMaster, "/") + "/api/v2/core/nodes/join"

	// The master very likely serves a self signed certificate and we have no CA
	// yet, so this one request skips verification. The token in the body is the
	// credential; nothing else about the master is trusted here.
	client := &http.Client{
		Timeout: joinRequestTimeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	resp, err := client.Post(url, "application/json", bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("call master failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var res joinResponse
	if err := json.Unmarshal(body, &res); err != nil {
		return nil, fmt.Errorf("unexpected master response: %w", err)
	}
	if res.Code != http.StatusOK {
		msg := res.Message
		if msg == "" {
			msg = string(body)
		}
		return nil, fmt.Errorf("master rejected the join: %s", msg)
	}
	if res.Data.ServerCrt == "" || res.Data.ServerKey == "" {
		return nil, fmt.Errorf("master did not return a certificate pair")
	}
	return &res, nil
}

// detectOutboundIP asks the routing table which local address would be used to
// reach the internet. No packet is actually sent.
func detectOutboundIP() (string, error) {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return "", err
	}
	defer conn.Close()
	host, _, err := net.SplitHostPort(conn.LocalAddr().String())
	if err != nil {
		return "", err
	}
	return host, nil
}
