package service

import (
	"strings"
	"testing"
)

func TestJoinBootstrapCommandUsesProxyWithDirectFallback(t *testing.T) {
	command := joinBootstrapCommand("https://panel.example.com:9543", "test-token")

	for _, expected := range []string{
		"https://proxy.erguotou.me/https://3panel.erguotou.me/package/join.sh",
		"https://3panel.erguotou.me/package/join.sh",
		"--connect-timeout 5 --max-time 15",
		" || curl ",
	} {
		if !strings.Contains(command, expected) {
			t.Fatalf("join command does not contain %q: %s", expected, command)
		}
	}
}
