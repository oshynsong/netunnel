//go:build !windows && !darwin
// +build !windows,!darwin

package daemonize

func Create(appName string, args []string) error {
	panic("not implemented")
}
