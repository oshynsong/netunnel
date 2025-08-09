package main

import (
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/oshynsong/netunnel"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
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
will be wrapped and unwrapped with the key(--trans-key flag) or password(--trans-pass flag) to pro-
vide the corresponding secure guarantee. To ensure safety, the key or password can be specified by
environment varibles NETUNNEL_TRANS_KEY and NETUNNEL_TRANS_PASS.
`,
		Run: runRootCmd,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			switch strings.ToUpper(flagTunnelType) {
			case "TCP":
				if flagTransformerName != "NULL" && len(flagTransformerKey) == 0 && len(flagTransformerPass) == 0 {
					return fmt.Errorf("no transformer key or password given for non-NULL transformers")
				}
			case "SSH":
				if len(flagSSHTunnelKeyFile) == 0 {
					return fmt.Errorf("no key file provided for SSH tunnel")
				}
			}

			return nil
		},
	}

	serverCmd = &cobra.Command{
		Use:   "server",
		Short: "Run at the tunnel server-side",
		Long: `
As for server-side endpoint, it listens on the server addr(--saddr flag), waits for the client-side
to dial. A typical setup with required flags will be like follows:
	netunnel server --saddr x.x.x.x:port --trans-pass xxx
`,
		RunE: runServerCmd,
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
	netunnel client --caddr x.x.x.x:port --cproto http1.1 --saddr x.x.x.x:port --trans-pass xxx
`,
		RunE: runClientCmd,
	}
)

var (
	flagLogLevel       netunnel.LogLevelType
	flagConcurrent     int
	flagAcceptMaxDelay time.Duration
	flagTunnelType     string
	flagNetwork        string
	flagServerAddr     string

	flagTransformerName    string
	flagTransConnTimeout   time.Duration
	flagTransAcceptTimeout time.Duration
	flagTransformerKey     string
	flagTransformerPass    string

	flagSSHTunnelUser    string
	flagSSHTunnelPass    string
	flagSSHTunnelKeyFile string
	flagSSHTunnelKeyPass string
	flagSSHTunnelAuthKey string

	flagClientAddr     string
	flagClientProtocol string
	flagProxyAuthUser  string
	flagProxyAuthPass  string
)

func init() {
	viper.AutomaticEnv()
	viper.SetEnvPrefix("NETUNNEL")

	rootFlags := rootCmd.PersistentFlags()
	rootFlags.Uint32Var(&flagLogLevel, "log-level", netunnel.LogLevelInfo, "set log output level 1 to 4, bigger value means less")
	rootFlags.IntVar(&flagConcurrent, "concurrent", 0, "max concurrent goroutine count")
	rootFlags.DurationVar(&flagAcceptMaxDelay, "accept-max-delay", time.Second, "max delay time when accept error occurs")
	rootFlags.StringVar(&flagTunnelType, "type", "tcp", "specify the netunnel type: tcp or ssh")
	rootFlags.StringVar(&flagNetwork, "network", "tcp", "specify the netunnel network: tcp/tcp4/tcp6/udp/udp4/udp6/ip")
	rootFlags.StringVar(&flagServerAddr, "saddr", "", "specify the server-side address")
	rootCmd.MarkPersistentFlagRequired("saddr")

	rootFlags.StringVar(&flagTransformerName, "trans-name", netunnel.AEADNameCHACHA20, "specify the transformer name: "+
		strings.Join([]string{"NULL", netunnel.AEADNameAES128GCM, netunnel.AEADNameAES256GCM, netunnel.AEADNameCHACHA20}, "/"))
	rootFlags.DurationVar(&flagTransConnTimeout, "trans-conn-timeout", time.Second*5, "connection timeout at client-side of the tunnel")
	rootFlags.DurationVar(&flagTransAcceptTimeout, "trans-accept-timeout", time.Second*10, "accept timeout at server-side of the tunnel")
	viper.BindEnv("trans_key", "trans_pass")
	rootFlags.StringVar(&flagTransformerKey, "trans-key", viper.GetString("trans_key"), "base64 encoded transformer key")
	rootFlags.StringVar(&flagTransformerPass, "trans-pass", viper.GetString("trans_pass"), "ascii string transformer password")

	viper.BindEnv("ssh_user", "ssh_pass", "ssh_key_file", "ssh_key_pass", "ssh_auth_key")
	rootFlags.StringVar(&flagSSHTunnelUser, "ssh-user", viper.GetString("ssh_user"), "username to create the ssh tunnel")
	rootFlags.StringVar(&flagSSHTunnelPass, "ssh-pass", viper.GetString("ssh_pass"), "password to login the ssh tunnel")
	rootFlags.StringVar(&flagSSHTunnelKeyFile, "ssh-key-file", viper.GetString("ssh_key_file"), "key file path to create the ssh tunnel")
	rootFlags.StringVar(&flagSSHTunnelKeyPass, "ssh-key-pass", viper.GetString("ssh_key_pass"), "key password to parse the key file")
	rootFlags.StringVar(&flagSSHTunnelAuthKey, "ssh-auth-key", viper.GetString("ssh_auth_key"), "authorized public key file for the ssh tunnel server")

	clientFlags := clientCmd.PersistentFlags()
	clientFlags.StringVar(&flagClientAddr, "caddr", "", "specify the client-side address")
	clientCmd.MarkPersistentFlagRequired("caddr")
	clientFlags.StringVar(&flagClientProtocol, "cproto", "socksv5", "specify the netunnel client protocol: socksv4, socksv5, http1.1")
	viper.BindEnv("proxy_auth_user", "proxy_auth_pass")
	clientFlags.StringVar(&flagProxyAuthUser, "proxy-auth-user", viper.GetString("proxy_auth_user"), "specify the proxy authenticate username")
	clientFlags.StringVar(&flagProxyAuthPass, "proxy-auth-pass", viper.GetString("proxy_auth_pass"), "specify the proxy authenticate password")

	rootCmd.AddCommand(serverCmd)
	rootCmd.AddCommand(clientCmd)
}

func runRootCmd(cmd *cobra.Command, args []string) {
	if flagLogLevel == netunnel.LogLevelDebug {
		fmt.Println("netunnel called")
	}
}

func runServerCmd(cmd *cobra.Command, args []string) error {
	netunnel.SetLogLevel(flagLogLevel)

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
	defer endpoint.Close()
	return endpoint.Serve(cmd.Context())
}

func runClientCmd(cmd *cobra.Command, args []string) error {
	netunnel.SetLogLevel(flagLogLevel)

	tunnel, err := createTunnel()
	if err != nil {
		return err
	}
	var proxyProto netunnel.ProxyProto
	cproto := strings.ToUpper(flagClientProtocol)
	switch cproto {
	case "SOCKSV4":
		proxyProto = netunnel.NewSocksV4ProxyProto()
	case "SOCKSV5":
		proxyProto = netunnel.NewSocksV5ProxyProto(flagProxyAuthUser, flagProxyAuthPass)
	case "HTTP1.1":
		proxyProto = netunnel.NewHttp11ProxyProto(flagProxyAuthUser, flagProxyAuthPass)
	}
	endpoint, err := netunnel.NewEndpoint(
		netunnel.EndpointClient,
		flagNetwork,
		flagClientAddr,
		tunnel,
		netunnel.WithEndpointConcurrent(flagConcurrent),
		netunnel.WithEndpointMaxAcceptDelay(flagAcceptMaxDelay),
		netunnel.WithEndpointServerAddr(flagServerAddr),
		netunnel.WithEndpointProxyProto(proxyProto),
	)
	if err != nil {
		return err
	}
	defer endpoint.Close()
	return endpoint.Serve(cmd.Context())
}

func createTunnel() (netunnel.Tunnel, error) {
	tt := strings.ToUpper(flagTunnelType)
	switch tt {
	case "TCP":
		transCreator := func() (netunnel.Transformer, error) {
			name := strings.ToUpper(flagTransformerName)
			switch name {
			case "NULL":
				return netunnel.NewNullTransformer(), nil
			case netunnel.AEADNameAES128GCM, netunnel.AEADNameAES256GCM, netunnel.AEADNameCHACHA20:
				if len(flagTransformerKey) > 0 {
					key, err := base64.StdEncoding.DecodeString(flagTransformerKey)
					if err != nil {
						if len(flagTransformerPass) > 0 {
							netunnel.NewAEADTransformerPassword(name, flagTransformerPass)
						}
						return nil, fmt.Errorf("decode transformer key failed: %w", err)
					}
					return netunnel.NewAEADTransformer(name, key)
				}
				return netunnel.NewAEADTransformerPassword(name, flagTransformerPass)
			}
			return nil, fmt.Errorf("invalid transformer name: %s", name)
		}
		return netunnel.NewTCPTunnel(transCreator, flagTransConnTimeout, flagTransAcceptTimeout), nil
	case "SSH":
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
