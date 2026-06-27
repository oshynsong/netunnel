package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/oshynsong/netunnel"
)

var (
	gLogFile        string
	gClientConfig   ClientConfig
	gClientEndpoint *netunnel.Endpoint
	gClientRunning  bool
)

type ClientConfig struct {
	ServerAddr string   `json:"server_addr"`
	ClientAddr string   `json:"client_addr"`
	PrivateKey string   `json:"private_key"`
	PublicKeys []string `json:"public_keys"`
}

func main() {
	ctx := context.Background()
	execPath, err := os.Executable()
	if err != nil {
		fmt.Fprintf(os.Stderr, "app executable path got failed: %v", err)
		os.Exit(1)
	}

	gLogFile = filepath.Join(filepath.Dir(execPath), "netunnel.log")
	logger, logErr := netunnel.NewSysFileLogger(gLogFile)
	if logErr != nil {
		fmt.Fprintf(os.Stderr, "create file logger failed: %v", logErr)
		os.Exit(2)
	}
	netunnel.SetLogger(logger)

	configPath := filepath.Join(filepath.Dir(execPath), "config.json")
	configBytes, confErr := os.ReadFile(configPath)
	if confErr != nil {
		fmt.Fprintf(os.Stderr, "read config.json from %s failed: %v", configPath, confErr)
		os.Exit(3)
	}
	if confErr = json.Unmarshal(configBytes, &gClientConfig); confErr != nil {
		fmt.Fprintf(os.Stderr, "parse client config failed: %v", confErr)
		os.Exit(4)
	}
	netunnel.LogInfo(ctx, "parse config from %s success", configPath)

	gClientEndpoint, err = createClientEndpoint()
	if err != nil {
		fmt.Fprintf(os.Stderr, "create client endpoint failed: %v", err)
		os.Exit(5)
	}

	if err := RunApp(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "RunApp error: %v", err)
	}
}

func createClientEndpoint() (*netunnel.Endpoint, error) {
	transCreator := func(key []byte) (netunnel.Transformer, error) {
		return netunnel.NewAEADTransformer(netunnel.AEADNameCHACHA20, key)
	}
	tunnel, err := netunnel.NewTCPTunnel(
		netunnel.WithTCPTunnelTransformer(transCreator),
		netunnel.WithTCPTunnelPrivateKeyBytes([]byte(gClientConfig.PrivateKey)),
		netunnel.WithTCPTunnelPublicKeysBytes([]byte(strings.Join(gClientConfig.PublicKeys, "\n"))),
	)
	if err != nil {
		return nil, err
	}

	proxy := netunnel.NewSystemProxy(netunnel.ProxyTypeHttp, netunnel.NewHttpProxyProto("", ""))
	return netunnel.NewEndpoint(
		netunnel.EndpointClient,
		"tcp",
		gClientConfig.ClientAddr,
		tunnel,
		netunnel.WithEndpointServerAddr(gClientConfig.ServerAddr),
		netunnel.WithEndpointLocalProxy(proxy),
	)
}

func startClientEndpoint() {
	if gClientRunning || gClientEndpoint == nil {
		return
	}
	gClientRunning = true
	go gClientEndpoint.Serve(context.Background())
}

func stopClientEndpoint() {
	if !gClientRunning || gClientEndpoint == nil {
		return
	}
	gClientRunning = false
	gClientEndpoint.Close(context.Background())
}
