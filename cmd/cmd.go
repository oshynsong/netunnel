package main

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/crypto/ssh"

	"github.com/oshynsong/netunnel"
	"github.com/oshynsong/netunnel/daemon"
)

var (
	rootCmd = &cobra.Command{
		Use:   "netunnel",
		Short: "A network tunnel to ensure secure communication",
		Long: `
The tunnel type(--type flag) tells the low-level implementation of the tunnel, such as TCP or SSH.
A TCP tunnel uses TCP connections to communicate with each other, and a SSH tunnel uses a custom
SSH channel type to communicate with each other. More types of tunnel will be added gradually. For
SSH tunnel, all flags with ssh prefix can be specified by environment varibles NETUNNEL_SSH_KEY_
FILE, NETUNNEL_SSH_KEY_PASS, NETUNNEL_SSH_AUTH_KEY, NETUNNEL_SSH_USER, NETUNNEL_SSH_PASS.

The transformer(--trans-name flag) tells how to transform the raw bytes pass through the tunnel. If
the NULL name is given, no transformation will be performed through the tunnel, otherwise raw bytes
will be wrapped and unwrapped with a session key to provide the corresponding secure guarantee.
`,
		RunE: func(cmd *cobra.Command, args []string) error { return cmd.Usage() },
	}

	serverCmd = &cobra.Command{
		Use:   "server",
		Short: "Run at the tunnel server-side",
		Long: `
As for server-side endpoint, it listens on the server addr(--saddr flag), waits for the client-side
to dial. A typical setup with required flags will be like follows:
	netunnel server --saddr x.x.x.x:port
`,
		RunE: runServerCmd,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			return chainCheck(checkServerAddr, checkKeyFile, checkTunnelType)
		},
	}

	clientCmd = &cobra.Command{
		Use:   "client",
		Short: "Run at the tunnel client-side",
		Long: `
As for client-side endpoint, it opens the tunnel to the remote server-side which means the server
MUST be available to connect when starting. It also listens on the client addr(--caddr flag) acting
as a proxy to wait for applications connecting it, and the proxy protocol(--cproto flag) can also be
specified with enhanced security guarantee by user/passowrd(--proxy-auth-user/--proxy-auth-pass). To
ensure safety, the proxy auth user/password can be specified by environment varibles NETUNNEL_PROXY_
AUTH_USER and NETUNNEL_PROXY_AUTH_PASS. A typical setup with required flag will be like follows:
	netunnel client --caddr x.x.x.x:port --cproto http1.1 --saddr x.x.x.x:port
`,
		RunE: runClientCmd,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			return chainCheck(checkServerAddr, checkKeyFile, checkTunnelType, checkClientAddr, checkClientProtocol)
		},
	}

	webappCmd = &cobra.Command{
		Use:   "webapp",
		Short: "Run the netunnel as an web application server",
		RunE:  runWebappCmd,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			// return chainCheck(checkServerAddr, checkKeyFile, checkTunnelType, checkClientAddr, checkLocalAddr)
			return nil
		},
	}

	toolCmd = &cobra.Command{
		Use:   "tool",
		Short: "Provide util tools",
		RunE:  runToolCmd,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			return chainCheck(checkToolName)
		},
	}
)

func init() {
	viper.AutomaticEnv()
	viper.SetEnvPrefix("NETUNNEL")

	rootFlags := rootCmd.PersistentFlags()
	rootFlags.BoolVarP(&flagDaemonize, "daemon", "d", false, "run the service as a daemon")
	rootFlags.Uint32Var(&flagLogLevel, "log-level", netunnel.LogLevelInfo, "set log output level 1 to 4, bigger value means less")
	rootFlags.IntVar(&flagConcurrent, "concurrent", 0, "max concurrent goroutine count")
	rootFlags.DurationVar(&flagAcceptMaxDelay, "accept-max-delay", time.Second, "max delay time when accept error occurs")
	rootFlags.StringVar(&flagTunnelType, "type", netunnel.TypeTCP, "specify the netunnel type: TCP or SSH")
	rootFlags.StringVar(&flagNetwork, "network", "tcp", "specify the netunnel network: tcp/tcp4/tcp6/udp/udp4/udp6/ip")
	rootFlags.StringVar(&flagServerAddr, "saddr", "", "specify the server-side address")
	viper.BindEnv("private_key", "public_key")
	rootFlags.StringVar(&flagPrivateKeyFile, "private-key", viper.GetString("private_key"), "specify the private key file for authentication")
	rootFlags.StringVar(&flagPublicKeyFile, "public-key", viper.GetString("public_key"), "the file of public keys for all authenticated clients")

	rootFlags.StringVar(&flagTransformerName, "trans-name", netunnel.AEADNameCHACHA20, "specify the transformer name: "+
		strings.Join([]string{"NULL", netunnel.AEADNameAES128GCM, netunnel.AEADNameAES256GCM, netunnel.AEADNameCHACHA20}, "/"))
	rootFlags.DurationVar(&flagTransConnTimeout, "trans-conn-timeout", time.Second*5, "connection timeout at client-side of the tunnel")
	rootFlags.DurationVar(&flagTransAcceptTimeout, "trans-accept-timeout", time.Second*10, "accept timeout at server-side of the tunnel")

	viper.BindEnv("ssh_user", "ssh_pass", "ssh_key_file", "ssh_key_pass", "ssh_auth_key")
	rootFlags.StringVar(&flagSSHTunnelUser, "ssh-user", viper.GetString("ssh_user"), "username to create the ssh tunnel")
	rootFlags.StringVar(&flagSSHTunnelPass, "ssh-pass", viper.GetString("ssh_pass"), "password to login the ssh tunnel")
	rootFlags.StringVar(&flagSSHTunnelKeyFile, "ssh-key-file", viper.GetString("ssh_key_file"), "key file path to create the ssh tunnel")
	rootFlags.StringVar(&flagSSHTunnelKeyPass, "ssh-key-pass", viper.GetString("ssh_key_pass"), "key password to parse the key file")
	rootFlags.StringVar(&flagSSHTunnelAuthKey, "ssh-auth-key", viper.GetString("ssh_auth_key"), "authorized public key file for the ssh tunnel server")

	clientFlags := clientCmd.PersistentFlags()
	clientFlags.StringVar(&flagClientAddr, "caddr", "", "specify the client-side address")
	clientFlags.StringVar(&flagClientProtocol, "cproto", netunnel.ProxyTypeHttp, "specify the netunnel client protocol: "+
		strings.Join([]string{netunnel.ProxyTypeHttp, netunnel.ProxyTypeSocks5, netunnel.ProxyTypeSocks4}, ", "))
	viper.BindEnv("proxy_auth_user", "proxy_auth_pass")
	clientFlags.StringVar(&flagProxyAuthUser, "proxy-auth-user", viper.GetString("proxy_auth_user"), "specify the proxy authenticate username")
	clientFlags.StringVar(&flagProxyAuthPass, "proxy-auth-pass", viper.GetString("proxy_auth_pass"), "specify the proxy authenticate password")
	clientFlags.BoolVar(&flagWithRemote, "with-remote", false, "setup and reset the remote server")

	webappFlags := webappCmd.PersistentFlags()
	webappFlags.StringVar(&flagLocalAddr, "local-addr", ":8080", "specify the local address")

	toolFlags := toolCmd.PersistentFlags()
	toolFlags.StringVar(&flagToolName, "name", "", "specify the name of the tool")

	rootCmd.AddCommand(serverCmd)
	rootCmd.AddCommand(clientCmd)
	rootCmd.AddCommand(webappCmd)
	rootCmd.AddCommand(toolCmd)
}

func runServerCmd(cmd *cobra.Command, args []string) error {
	netunnel.SetLogLevel(flagLogLevel)
	if flagDaemonize {
		appName, subArgs := removeDaemonizeFlag()
		cmd.Printf("run %s as a daemon: %v\n", appName, subArgs)
		return daemon.Create(appName, subArgs)
	}

	tunnel, err := createTunnel()
	if err != nil {
		return err
	}
	endpoint, err := netunnel.NewEndpoint(
		netunnel.EndpointServer,
		flagNetwork,
		flagServerAddr,
		tunnel,
		netunnel.WithEndpointConcurrent(flagConcurrent),
		netunnel.WithEndpointMaxAcceptDelay(flagAcceptMaxDelay),
	)
	if err != nil {
		return err
	}
	go endpoint.Serve(cmd.Context())
	select {
	case <-cmd.Context().Done():
	case <-netunnel.ExitNotify():
	}
	endpoint.Close(cmd.Context())
	return nil
}

func runClientCmd(cmd *cobra.Command, args []string) error {
	netunnel.SetLogLevel(flagLogLevel)
	if flagDaemonize {
		appName, subArgs := removeDaemonizeFlag()
		cmd.Printf("run %s as a daemon: %v\n", appName, subArgs)
		return daemon.Create(appName, subArgs)
	}

	if flagWithRemote {
		conf, err := netunnel.BuildSSHClientConfig(
			flagSSHTunnelUser,
			flagSSHTunnelPass,
			flagSSHTunnelKeyFile,
			flagTransConnTimeout,
			flagSSHTunnelKeyPass)
		if err != nil {
			return err
		}
		addr := strings.Split(flagServerAddr, ":")[0] + ":22"
		client, err := ssh.Dial(flagNetwork, addr, conf)
		if err != nil {
			return err
		}
		defer client.Close()
		cmd.Printf("client endpoint setup remote with %s success", addr)

		sess, sessErr := client.NewSession()
		if sessErr != nil {
			return sessErr
		}
		if _, err = sess.CombinedOutput("sh /root/run.sh"); err != nil {
			return err
		}
		defer func() {
			if _, err = sess.CombinedOutput("pkill netunnel"); err != nil {
				cmd.PrintErrf("reset remote failed: %v", err)
			}
		}()
	}

	tunnel, err := createTunnel()
	if err != nil {
		return err
	}
	var proxyProto netunnel.ProxyProto
	proto := strings.ToUpper(flagClientProtocol)
	switch proto {
	case netunnel.ProxyTypeSocks4:
		proxyProto = netunnel.NewSocksV4ProxyProto()
	case netunnel.ProxyTypeSocks5:
		proxyProto = netunnel.NewSocksV5ProxyProto(flagProxyAuthUser, flagProxyAuthPass)
	case netunnel.ProxyTypeHttp:
		proxyProto = netunnel.NewHttpProxyProto(flagProxyAuthUser, flagProxyAuthPass)
	case netunnel.ProxyTypeHttps:
		return fmt.Errorf("to be implemented later")
	default:
		return fmt.Errorf("invalid proxy protocol: %s", proto)
	}
	endpoint, err := netunnel.NewEndpoint(
		netunnel.EndpointClient,
		flagNetwork,
		flagClientAddr,
		tunnel,
		netunnel.WithEndpointConcurrent(flagConcurrent),
		netunnel.WithEndpointMaxAcceptDelay(flagAcceptMaxDelay),
		netunnel.WithEndpointServerAddr(flagServerAddr),
		netunnel.WithEndpointProxyProto(proto, proxyProto),
	)
	if err != nil {
		return err
	}
	go endpoint.Serve(cmd.Context())
	select {
	case <-cmd.Context().Done():
	case <-netunnel.ExitNotify():
	}
	endpoint.Close(cmd.Context())
	return nil
}

func createTunnel() (netunnel.Tunnel, error) {
	tt := strings.ToUpper(flagTunnelType)
	switch tt {
	case netunnel.TypeTCP:
		transCreator := func(key []byte) (netunnel.Transformer, error) {
			name := strings.ToUpper(flagTransformerName)
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
			netunnel.WithTCPTunnelConnTimeout(flagTransConnTimeout),
			netunnel.WithTCPTunnelAcceptTimeout(flagTransAcceptTimeout),
			netunnel.WithTCPTunnelPrivateKeyFile(flagPrivateKeyFile),
			netunnel.WithTCPTunnelPublicKeyFile(flagPublicKeyFile),
		)
	case netunnel.TypeSSH:
		return netunnel.NewSSHTunnel(
			netunnel.WithSSHTunnelUser(flagSSHTunnelUser),
			netunnel.WithSSHTunnelPassword(flagSSHTunnelPass),
			netunnel.WithSSHTunnelKey(flagSSHTunnelKeyFile, flagSSHTunnelKeyPass),
			netunnel.WithSSHTunnelAuthorizedKey(flagSSHTunnelAuthKey),
			netunnel.WithSSHTunnelTimeout(flagTransConnTimeout, flagTransAcceptTimeout),
		), nil
	}
	return nil, fmt.Errorf("tunnel type not supported: %v", flagTunnelType)
}

func runWebappCmd(cmd *cobra.Command, args []string) error {
	public, private := netunnel.GenAuthKey()
	netunnel.LogInfo(cmd.Context(), "start server with listening on %s: user=%s pass=%s", flagLocalAddr, public, private)
	mux := createWebappMux(public, private)
	s := &http.Server{
		Addr:         flagLocalAddr,
		Handler:      mux,
		ReadTimeout:  time.Second * 10,
		WriteTimeout: time.Second * 10,
		IdleTimeout:  time.Second * 30,
	}
	return s.ListenAndServe()
}

func runToolCmd(cmd *cobra.Command, args []string) error {
	name := strings.ToUpper(flagToolName)
	switch name {
	case "GEN-AUTH-KEY":
		public, private := netunnel.GenAuthKey()
		fmt.Printf("public:\n%s\n", public)
		fmt.Printf("private:\n%s\n", private)
	}
	return nil
}
