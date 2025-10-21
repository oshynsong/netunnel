//go:build !windows && !darwin && !linux
// +build !windows,!darwin,!linux

package daemon

func Create(appName string, args []string) error {
	panic("not implemented")
}

func GetPid(appName string) ([]string, error) {
	panic("not implemented")
}
