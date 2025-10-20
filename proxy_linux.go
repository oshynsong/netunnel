//go:build linux
// +build linux

package netunnel

import "context"

func SetupProxy(ctx context.Context, proxyType, addrPort string) (*ProxySetting, error) {
	panic("not implemented")
}

func ResetProxy(ctx context.Context, old *ProxySetting) error {
	panic("not implemented")
}
