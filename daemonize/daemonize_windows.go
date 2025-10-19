package daemonize

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/windows"
)

func Create(appName string, args []string) error {
	app, err := locateAppFullPath(appName)
	if err != nil {
		return err
	}

	params := []string{"/c", app}
	cmd := exec.Command("cmd.exe", append(params, args...)...)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: windows.CREATE_NEW_PROCESS_GROUP | windows.CREATE_NO_WINDOW,
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
