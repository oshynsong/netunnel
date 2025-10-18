//go:build darwin
// +build darwin

package netunnel

func SetupProxy(addrport string) (*ProxySetting, error) {
	panic("not implemented")
}

func ResetProxy(old *ProxySetting) error {
	panic("not implemented")
}
