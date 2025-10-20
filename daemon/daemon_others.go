//go:build !windows && !darwin && !linux
// +build !windows,!darwin,!linux

package daemon

func Create(appName string, args []string) error {
	panic("not implemented")
}
