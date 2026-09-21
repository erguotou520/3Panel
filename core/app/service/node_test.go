package service

import (
	"os/exec"
	"strings"
	"testing"
)

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
