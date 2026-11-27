package service

import (
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"
)

func TestGetJSONUnwrapsAgentResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"code":200,"message":"success","data":{"version":"v2.0.12","scope":"node"}}`))
	}))
	defer server.Close()

	var info agentNodeInfo
	if err := (&NodeService{}).getJSON(server.Client(), server.URL, &info); err != nil {
		t.Fatal(err)
	}
	if info.Version != "v2.0.12" || info.Scope != "node" {
		t.Fatalf("unexpected node info: %#v", info)
	}
}

func TestJoinBootstrapCommandUsesCloudsmithDirectly(t *testing.T) {
	command := joinBootstrapCommand("https://panel.example.com:9543", "test-token")

	for _, expected := range []string{
		"sudo env PANEL3_MASTER='https://panel.example.com:9543' PANEL3_TOKEN='test-token' bash -c",
		"https://generic.cloudsmith.io/3panel/3panel/package/join.sh",
		"--connect-timeout 20 --max-time 60",
	} {
		if !strings.Contains(command, expected) {
			t.Fatalf("join command does not contain %q: %s", expected, command)
		}
	}
	if strings.Contains(command, "mktemp") || strings.Contains(command, " & ") {
		t.Fatalf("join command must not use race requests: %s", command)
	}
	if strings.HasPrefix(command, "PANEL3_MASTER=") {
		t.Fatalf("environment variables before sudo would be removed: %s", command)
	}
	check := exec.Command("bash", "-n")
	check.Stdin = strings.NewReader(command)
	if output, err := check.CombinedOutput(); err != nil {
		t.Fatalf("generated command is not valid Bash: %v\n%s\n%s", err, output, command)
	}
}

type countingListener struct {
	net.Listener
	conns *int32
}

func (l *countingListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err == nil {
		atomic.AddInt32(l.conns, 1)
	}
	return conn, err
}

// TestNodeProbeTransportConfig guards against the production connection leak:
// every probe must go through one pooled transport whose idle keep-alive
// connections are reaped, not a fresh zero-value transport per request.
func TestNodeProbeTransportConfig(t *testing.T) {
	transport, ok := nodeProbeClient.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("nodeProbeClient.Transport is %T, want *http.Transport", nodeProbeClient.Transport)
	}
	if transport.IdleConnTimeout <= 0 {
		t.Errorf("IdleConnTimeout = %v; a zero value never reaps idle keep-alive connections (one leak per probe)", transport.IdleConnTimeout)
	}
	if transport.DialTLSContext == nil {
		t.Error("DialTLSContext is nil, per-node mTLS configuration would not be applied")
	}
	if nodeProbeClient.Timeout != remoteProbeTimeout {
		t.Errorf("nodeProbeClient.Timeout = %v, want %v", nodeProbeClient.Timeout, remoteProbeTimeout)
	}
}

// TestNodeProbeClientReusesConnections proves consecutive health probes reuse
// a single keep-alive connection instead of opening one per probe, which is
// what exhausted the master's ephemeral ports and reported healthy nodes as
// Offline.
func TestNodeProbeClientReusesConnections(t *testing.T) {
	origTLSConfig := nodeTLSConfig
	nodeTLSConfig = func(string) (*tls.Config, error) {
		return &tls.Config{InsecureSkipVerify: true}, nil
	}
	defer func() { nodeTLSConfig = origTLSConfig }()

	var conns int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"code":200,"message":"success","data":{"version":"v2.0.12","scope":"node"}}`))
	}))
	// Count accepted TCP connections; StartTLS wraps this listener, so each
	// new connection is counted once.
	server.Listener = &countingListener{Listener: server.Listener, conns: &conns}
	server.StartTLS()
	defer server.Close()

	addr := strings.TrimPrefix(server.URL, "https://")
	var info agentNodeInfo
	for i := 0; i < 5; i++ {
		if err := (&NodeService{}).getJSON(nodeProbeClient, "https://"+addr+"/api/v2/dashboard/current/node", &info); err != nil {
			t.Fatalf("probe %d failed: %v", i, err)
		}
		if info.Version != "v2.0.12" {
			t.Fatalf("unexpected node info: %#v", info)
		}
	}
	if got := atomic.LoadInt32(&conns); got != 1 {
		t.Errorf("5 sequential probes opened %d connections, want 1 (keep-alive reuse)", got)
	}
}
