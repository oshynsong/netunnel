package daemon

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

type CheckRunningFunc = func(appName string) error

var RunningChecker CheckRunningFunc

func init() {
	RunningChecker = defaultRunningChecker
}

func defaultRunningChecker(appName string) error {
	pidList, err := GetPid(appName)
	if err != nil {
		return fmt.Errorf("get pid of app %s failed: %w", appName, err)
	}
	if len(pidList) == 0 {
		return fmt.Errorf("app %s has no running process", appName)
	}
	return nil
}

func locateAppFullPath(appName string) (string, error) {
	// Try to locate the app from current executable path.
	execPath, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("get executable path failed: %w", err)
	}
	execPath, err = filepath.EvalSymlinks(execPath)
	if err != nil {
		return "", fmt.Errorf("eval synlinks %s failed: %w", execPath, err)
	}
	app := filepath.Join(filepath.Dir(execPath), appName)

	// Try to locate the app from system paths.
	if info, statErr := os.Stat(app); statErr != nil || info.IsDir() {
		execPath, err = exec.LookPath(appName)
		if err != nil {
			return "", fmt.Errorf("can not found %s from system: %w", appName, err)
		}
		app, _ = filepath.Abs(execPath)
	}

	return app, nil
}
