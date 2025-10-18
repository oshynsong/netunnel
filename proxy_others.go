//go:build !windows && !linux && !darwin
// +build !windows,!linux,!darwin

package netunnel

func SetupProxy(addrport string) (*ProxySetting, error) {
	panic("not implemented")
}

func ResetProxy(old *ProxySetting) error {
	panic("not implemented")
}
