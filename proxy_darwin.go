//go:build darwin
// +build darwin

package netunnel

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
)

func SetupProxy(ctx context.Context, proxyType, addrPort string) (*ProxySetting, error) {
	parts := strings.Split(addrPort, ":")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid proxy address %s", addrPort)
	}
	server, port := parts[0], parts[1]

	service, err := getActiveNetworkService(ctx)
	if err != nil {
		return nil, err
	}
	var getAction, setAction string
	switch proxyType {
	case ProxyTypeHttp:
		getAction, setAction = "-getwebproxy", "-setwebproxy"
	case ProxyTypeHttps:
		getAction, setAction = "-getsecurewebproxy", "-setsecurewebproxy"
	case ProxyTypeSocks4, ProxyTypeSocks5:
		getAction, setAction = "-getsocksfirewallproxy", "-setsocksfirewallproxy"
	default:
		return nil, fmt.Errorf("unsupported proxy type %s", proxyType)
	}

	get := exec.CommandContext(ctx, "networksetup", getAction, service)
	info, infoErr := get.CombinedOutput()
	if infoErr != nil {
		return nil, fmt.Errorf("get network service %s info failed: %w", service, infoErr)
	}
	old := &ProxySetting{serviceName: service, proxyType: proxyType}
	var oldServer, oldPort string
	s := bufio.NewScanner(bytes.NewReader(info))
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if strings.HasPrefix(line, "Enabled:") {
			enabled := strings.TrimSpace(strings.TrimPrefix(line, "Enabled:"))
			if enabled == "Yes" {
				old.enabled = 1
			}
		}
		if strings.HasPrefix(line, "Server:") {
			oldServer = strings.TrimSpace(strings.TrimPrefix(line, "Server:"))
		}
		if strings.HasPrefix(line, "Port:") {
			oldPort = strings.TrimSpace(strings.TrimPrefix(line, "Port:"))
		}
	}
	old.address = oldServer + ":" + oldPort

	set := exec.CommandContext(ctx, "networksetup", setAction, service, server, port)
	if _, err = set.Output(); err != nil {
		return nil, fmt.Errorf("setup proxy failed: %v", err)
	}
	enable := exec.CommandContext(ctx, "networksetup", setAction+"state", service, "on")
	if _, err = enable.Output(); err != nil {
		return nil, fmt.Errorf("enable proxy failed: %v", err)
	}
	LogInfo(ctx, "setup proxy with address %s for service(%s) success", addrPort, service)
	return old, nil
}

func ResetProxy(ctx context.Context, old *ProxySetting) error {
	var setAction string
	switch old.proxyType {
	case ProxyTypeHttp:
		setAction = "-setwebproxy"
	case ProxyTypeHttps:
		setAction = "-setsecurewebproxy"
	case ProxyTypeSocks4, ProxyTypeSocks5:
		setAction = "-setsocksfirewallproxy"
	default:
		return fmt.Errorf("unsupported proxy type %s", &old.proxyType)
	}

	if old.enabled != 0 {
		parts := strings.Split(old.address, ":")
		if len(parts) != 2 {
			return fmt.Errorf("invalid old proxy address %s", old.address)
		}
		server, port := parts[0], parts[1]

		set := exec.CommandContext(ctx, "networksetup", setAction, old.serviceName, server, port)
		if _, err := set.Output(); err != nil {
			return fmt.Errorf("reset proxy failed: %v", err)
		}
	}

	var action string
	if old.enabled != 0 {
		action = "on"
	} else {
		action = "off"
	}
	enable := exec.CommandContext(ctx, "networksetup", setAction+"state", old.serviceName, action)
	if _, err := enable.Output(); err != nil {
		return fmt.Errorf("reset proxy state failed: %v", err)
	}
	LogInfo(ctx, "reset proxy of service(%v) to original success", old.serviceName)
	return nil
}

func getActiveNetworkService(ctx context.Context) (string, error) {
	cmd := exec.CommandContext(ctx, "networksetup", "-listallnetworkservices")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("list all network services failed: err=%v output=%v", err, string(output))
	}

	s := bufio.NewScanner(bytes.NewReader(output))
	s.Split(bufio.ScanLines)
	for s.Scan() {
		service := strings.TrimSpace(s.Text())
		if service == "" || service == "An asterisk (*) denotes that a network service is disabled." {
			continue
		}

		if isNetworkServiceActive(ctx, service) {
			return service, nil
		}
	}
	return "", fmt.Errorf("no active network service found")
}

func isNetworkServiceActive(ctx context.Context, networkService string) bool {
	cmd := exec.CommandContext(ctx, "networksetup", "-getinfo", networkService)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return false
	}
	s := bufio.NewScanner(bytes.NewReader(output))
	s.Split(bufio.ScanLines)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if !strings.HasPrefix(line, "IP address:") {
			continue
		}

		fields := strings.Split(line, ":")
		addr := strings.TrimSpace(fields[1])
		if addr != "" && addr != "0.0.0.0" && !strings.HasPrefix(addr, "169.254") {
			return true
		}
	}
	return false
}
