//go:build darwin || linux
// +build darwin linux

package daemon

import (
	"bufio"
	"bytes"
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

func GetPid(appName string) ([]string, error) {
	out, err := exec.Command("pgrep", "-l", "-f", appName).CombinedOutput()
	if err != nil {
		return nil, err
	}

	var pidList []string
	s := bufio.NewScanner(bytes.NewReader(out))
	for s.Scan() {
		line := s.Text()
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		pid, name := fields[0], fields[1]
		name = strings.ToLower(strings.TrimSpace(name))
		if !strings.HasSuffix(name, strings.ToLower(appName)) {
			continue
		}
		pidList = append(pidList, pid)
	}
	return pidList, nil
}
