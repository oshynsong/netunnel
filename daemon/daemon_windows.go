//go:build windows
// +build windows

package daemon

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
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

func GetPid(appName string) ([]string, error) {
	pidList := make([]uint32, 2048)
	var ret uint32
	if err := windows.EnumProcesses(pidList, &ret); err != nil || ret == 0 {
		return nil, fmt.Errorf("get process list failed: %w", err)
	}
	if ret > uint32(len(pidList)) {
		pidList = make([]uint32, ret+10)
		if err := windows.EnumProcesses(pidList, &ret); err != nil || ret == 0 {
			return nil, fmt.Errorf("retry get process list failed: %w", err)
		}
	}
	if ret < uint32(len(pidList)) {
		pidList = pidList[:ret]
	}
	var matches []string
	for _, pid := range pidList {
		if pid == 0 {
			continue
		}
		hProcess, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ, false, pid)
		if err != nil {
			continue
		}
		defer windows.CloseHandle(hProcess)
		var module windows.Handle
		var cbNeeded uint32
		cb := (uint32)(unsafe.Sizeof(module))
		if err := windows.EnumProcessModules(hProcess, &module, cb, &cbNeeded); err != nil {
			continue
		}
		var sz uint32 = 1024 * 8
		moduleName := make([]uint16, sz)
		cb = uint32(len(moduleName)) * (uint32)(unsafe.Sizeof(uint16(0)))
		if err := windows.GetModuleBaseName(hProcess, module, &moduleName[0], cb); err != nil && err != syscall.ERROR_INSUFFICIENT_BUFFER {
			continue
		}
		exeFile := path.Base(strings.ToLower(syscall.UTF16ToString(moduleName)))
		if strings.EqualFold(exeFile, procName) {
			matches = append(matches, strconv.FormatUint(uint64(pid), 10))
		}
	}
	return matches, nil
}
