package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path"
	"strings"
	"syscall"

	"github.com/oshynsong/netunnel"
	"github.com/oshynsong/netunnel/app/tray"
	"github.com/oshynsong/netunnel/app/tray/menu"
	"github.com/oshynsong/netunnel/statics"
)

const (
	iconName       = "app.ico"
	serviceName    = "netunnel"
	localProxyAddr = "localhost:1080"
	serverAddr     = "65.49.223.169:8765"
)

func AppRun() {
	iconBytes, err := statics.Get(iconName)
	if err != nil {
		slog.Error(fmt.Sprintf("get app icon failed: %v", err))
		return
	}

	var s tray.Service
	s, err = tray.New(serviceName, iconBytes)
	if err != nil {
		slog.Error(fmt.Sprintf("create tray service error: %v", err))
		return
	}

	if err := setupLayout(s); err != nil {
		slog.Error(fmt.Sprintf("setup layout error: %v", err))
		return
	}
	s.Run()
}

var (
	tunnelType     string = "TCP"
	proxyProto     string = "http1.1"
	transformer    string = netunnel.AEADNameCHACHA20
	clientEndpoint *netunnel.Endpoint
)

func setupLayout(s tray.Service) error {
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
	closed := make(chan struct{})

	clientMenu := menu.Add("Client Endpoint", "start or stop current client endpoint", nil)
	proxyMenu := menu.Add("System Proxy", "start or stop the system proxy", nil)

	settings := menu.Add("Settings", "set the options for netunnel", nil)
	setTunnelType := settings.AddSubItem("Tunnel Type", "")
	setTunnelTypeTCP := setTunnelType.AddSubItem("TCP", "use tcp tunnel").WithChecked()
	setTunnelTypeSSH := setTunnelType.AddSubItem("SSH", "use ssh tunnel")
	setProxy := settings.AddSubItem("Proxy Protocol", "")
	setProxyHTTP := setProxy.AddSubItem("Http", "use http proxy").WithChecked()
	setProxySocksv5 := setProxy.AddSubItem("SocksV5", "use socksV5 proxy")
	setProxySocksv4 := setProxy.AddSubItem("SocksV4", "use socksV4 proxy")
	setTrans := settings.AddSubItem("Transformer", "")
	setTransChaCha20 := setTrans.AddSubItem("CHACHA20", "CHACHA20").WithChecked()
	setTransAES256 := setTrans.AddSubItem("AES256GCM", "AES256GCM")
	setTransAES128 := setTrans.AddSubItem("AES128GCM", "AES128GCM")

	if err := s.UpsertMenuItem(
		clientMenu,
		proxyMenu,
		settings,
		setTunnelType, setTunnelTypeTCP, setTunnelTypeSSH,
		setProxy, setProxyHTTP, setProxySocksv5, setProxySocksv4,
		setTrans, setTransChaCha20, setTransAES256, setTransAES128,
	); err != nil {
		return err
	}
	if err := s.AddSeperator(); err != nil {
		return err
	}
	quitMetu := menu.Add("Quit", "quit netunnel", nil)
	if err := s.UpsertMenuItem(quitMetu); err != nil {
		return err
	}

	// Handle tunnel type selection.
	go func() {
		for {
			select {
			case <-setTunnelTypeTCP.Event():
				tunnelType = "TCP"
				setTunnelTypeTCP.Checked, setTunnelTypeSSH.Checked = true, false
			case <-setTunnelTypeSSH.Event():
				tunnelType = "SSH"
				setTunnelTypeTCP.Checked, setTunnelTypeSSH.Checked = false, true
			case <-closed:
				return
			}
			s.UpsertMenuItem(setTunnelTypeTCP, setTunnelTypeSSH)
		}
	}()

	// Handle proxy protocol selection.
	go func() {
		for {
			select {
			case <-setProxyHTTP.Event():
				proxyProto = "http1.1"
				setProxyHTTP.Checked, setProxySocksv5.Checked, setProxySocksv4.Checked = true, false, false
			case <-setProxySocksv5.Event():
				proxyProto = "socksv5"
				setProxyHTTP.Checked, setProxySocksv5.Checked, setProxySocksv4.Checked = false, true, false
			case <-setProxySocksv4.Event():
				proxyProto = "socksv4"
				setProxyHTTP.Checked, setProxySocksv5.Checked, setProxySocksv4.Checked = false, false, true
			case <-closed:
				return
			}
			s.UpsertMenuItem(setProxyHTTP, setProxySocksv5, setProxySocksv4)
		}
	}()

	// Handle transformer type selection.
	go func() {
		for {
			select {
			case <-setTransChaCha20.Event():
				transformer = netunnel.AEADNameCHACHA20
				setTransChaCha20.Checked, setTransAES256.Checked, setTransAES128.Checked = true, false, false
			case <-setTransAES256.Event():
				transformer = netunnel.AEADNameAES256GCM
				setTransChaCha20.Checked, setTransAES256.Checked, setTransAES128.Checked = false, true, false
			case <-setTransAES128.Event():
				transformer = netunnel.AEADNameAES128GCM
				setTransChaCha20.Checked, setTransAES256.Checked, setTransAES128.Checked = false, false, true
			case <-closed:
				return
			}
			s.UpsertMenuItem(setTransChaCha20, setTransAES256, setTransAES128)
		}
	}()

	// Handle main lifecycle actions.
	go func() {
		for {
			select {
			case <-s.OnClicked():
				s.ShowMainWindow()

			case <-clientMenu.Event():
				slog.Info(fmt.Sprintf("client event got, current checked=%v", clientMenu.Checked))
				if clientMenu.Checked {
					clientMenu.Checked = false
				} else {
					clientMenu.Checked = true
				}
				if err := handleClientEvent(clientMenu.Checked); err != nil {
					slog.Error(fmt.Sprintf("handle client event failed: %v", err))
					continue
				}
				s.UpsertMenuItem(clientMenu)

			case <-proxyMenu.Event():
				slog.Info(fmt.Sprintf("proxy event got, current checked=%v", proxyMenu.Checked))
				if proxyMenu.Checked {
					proxyMenu.Checked = false
				} else {
					proxyMenu.Checked = true
				}
				if err := handleProxyEvent(proxyMenu.Checked); err != nil {
					slog.Error(fmt.Sprintf("handle proxy event failed: %v", err))
					continue
				}
				s.UpsertMenuItem(proxyMenu)

			case <-signals:
				slog.Info("exit signal got")
				s.Quit()
				close(closed)
			case <-quitMetu.Event():
				slog.Info("quit event got")
				s.Quit()
				close(closed)
			}
		}
	}()
	return nil
}

func handleClientEvent(start bool) error {
	var err error
	if start {
		tunnel, err := createTunnel()
		if err != nil {
			return err
		}

		var pp netunnel.ProxyProto
		cproto := strings.ToUpper(proxyProto)
		switch cproto {
		case netunnel.ProxyTypeSocks4:
			pp = netunnel.NewSocksV4ProxyProto()
		case netunnel.ProxyTypeSocks5:
			pp = netunnel.NewSocksV5ProxyProto("", "")
		case netunnel.ProxyTypeHttp:
			pp = netunnel.NewHttpProxyProto("", "")
		}

		clientEndpoint, err = netunnel.NewEndpoint(
			netunnel.EndpointClient,
			"tcp",
			localProxyAddr,
			tunnel,
			// netunnel.WithEndpointConcurrent(flagConcurrent),
			// netunnel.WithEndpointMaxAcceptDelay(flagAcceptMaxDelay),
			netunnel.WithEndpointServerAddr(serverAddr),
			netunnel.WithEndpointProxyProto(pp),
		)
		if err != nil {
			return err
		}
		go clientEndpoint.Serve(context.Background())
	} else {
		clientEndpoint.Close()
		clientEndpoint = nil
	}
	return err
}

func createTunnel() (netunnel.Tunnel, error) {
	pwd, err := os.Getwd()
	if err != nil {
		return nil, err
	}
	private := path.Join(pwd, "key")
	publics := path.Join(pwd, "publics")

	tt := strings.ToUpper(tunnelType)
	switch tt {
	case "TCP":
		transCreator := func(key []byte) (netunnel.Transformer, error) {
			name := strings.ToUpper(transformer)
			switch name {
			case "NULL":
				return netunnel.NewNullTransformer(), nil
			case netunnel.AEADNameAES128GCM, netunnel.AEADNameAES256GCM, netunnel.AEADNameCHACHA20:
				return netunnel.NewAEADTransformer(name, key)
			}
			return nil, fmt.Errorf("invalid transformer name: %s", name)
		}
		return netunnel.NewTCPTunnel(
			netunnel.WithTCPTunnelTransformer(transCreator),
			// netunnel.WithTCPTunnelConnTimeout(flagTransConnTimeout),
			// netunnel.WithTCPTunnelAcceptTimeout(flagTransAcceptTimeout),
			netunnel.WithTCPTunnelPrivateKeyFile(private),
			netunnel.WithTCPTunnelPublicKeyFile(publics),
		)
	case "SSH":
		/*return netunnel.NewSSHTunnel(
			netunnel.WithSSHTunnelUser(flagSSHTunnelUser),
			netunnel.WithSSHTunnelPassword(flagSSHTunnelPass),
			netunnel.WithSSHTunnelKey(flagSSHTunnelKeyFile, flagSSHTunnelKeyPass),
			netunnel.WithSSHTunnelAuthorizedKey(flagSSHTunnelAuthKey),
			netunnel.WithSSHTunnelTimeout(flagTransConnTimeout, flagTransAcceptTimeout),
		), nil*/
	}
	return nil, fmt.Errorf("tunnel type not supported: %v", tunnelType)
}

func handleProxyEvent(start bool) error {
	dir, err := os.Getwd()
	slog.Info(fmt.Sprintf("%v %v", dir, err))

	return nil
}
