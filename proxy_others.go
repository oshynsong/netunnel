//go:build !windows && !linux && !darwin
// +build !windows,!linux,!darwin

package netunnel

import "context"

func SetupProxy(ctx context.Context, addrport string) (*ProxySetting, error) {
	panic("not implemented")
}

func ResetProxy(ctx context.Context, old *ProxySetting) error {
	panic("not implemented")
}
