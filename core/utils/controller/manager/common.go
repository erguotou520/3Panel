package manager

import (
	"errors"
	"strings"
	"time"

	"github.com/3panel-dev/3panel/core/utils/cmd"
	"github.com/3panel-dev/3panel/core/utils/ssh"
)

func handlerErr(out string, err error) error {
	if err != nil {
		if out != "" {
			return errors.New(out)
		}
		return err
	}
	return nil
}

func run(client *ssh.SSHClient, name string, args ...string) (string, error) {
	if client == nil {
		return cmd.NewCommandMgr(cmd.WithTimeout(10*time.Second), cmd.WithEnv("LANGUAGE=en_US:en")).RunWithStdout(name, args...)
	}
	return client.Runf("LANGUAGE=en_US:en %s %s", name, strings.Join(args, " "))
}
