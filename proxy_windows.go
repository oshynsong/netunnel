//go:build windows
// +build windows

package netunnel

import (
	"context"

	"golang.org/x/sys/windows/registry"
)

const regPath = `Software\Microsoft\Windows\CurrentVersion\Internet Settings`

func SetupProxy(ctx context.Context, proxyType, addrPort string) (*ProxySetting, error) {
	k, err := registry.OpenKey(registry.CURRENT_USER, regPath, registry.READ|registry.WRITE|registry.SET_VALUE)
	if err != nil {
		return nil, err
	}
	defer k.Close()

	enabled, _, err := k.GetIntegerValue("ProxyEnable")
	if err != nil {
		return nil, err
	}
	server, _, err := k.GetStringValue("ProxyServer")
	if err != nil {
		return nil, err
	}

	if err := k.SetDWordValue("ProxyEnable", 1); err != nil {
		return nil, err
	}
	if err := k.SetStringValue("ProxyServer", addrPort); err != nil {
		k.SetDWordValue("ProxyEnable", uint32(enabled))
		return nil, err
	}
	LogInfo(ctx, "setup proxy with address %s success", addrPort)
	return &ProxySetting{proxyType: proxyType, enabled: uint32(enabled), address: server}, nil
}

func ResetProxy(ctx context.Context, old *ProxySetting) error {
	k, err := registry.OpenKey(registry.CURRENT_USER, regPath, registry.WRITE|registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()

	if err := k.SetDWordValue("ProxyEnable", old.enabled); err != nil {
		return err
	}
	if err := k.SetStringValue("ProxyServer", old.address); err != nil {
		return err
	}
	LogInfo(ctx, "reset proxy to original success")
	return nil
}
