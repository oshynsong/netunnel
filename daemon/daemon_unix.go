//go:build darwin || linux
// +build darwin linux

package daemon

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
)

func Create(appName string, args []string) error {
	app, err := locateAppFullPath(appName)
	if err != nil {
		return err
	}

	fullExec := strings.Join(append([]string{app}, args...), " ")
	cmd := exec.Command("/bin/bash", "-c", fullExec)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setsid:     true,
		Foreground: false,
	}
	cmd.Stdin = strings.NewReader("")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Dir = filepath.Dir(app)
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("unable to start daemon app(%s) %w", app, err)
	}
	if cmd.Process != nil {
		defer cmd.Process.Release() //nolint:errcheck
	}
	if RunningChecker != nil {
		return RunningChecker(appName)
	}
	return nil
}
