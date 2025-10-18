//go:build linux
// +build linux

package netunnel

func SetupProxy(addrport string) (*ProxySetting, error) {
	panic("not implemented")
}

func ResetProxy(old *ProxySetting) error {
	panic("not implemented")
}
