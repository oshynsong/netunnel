package main

import (
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/oshynsong/netunnel"
	"github.com/spf13/cobra"
)

var (
	rootCmd = &cobra.Command{
		Use:   "netunnel",
		Short: "A network tunnel to ensure secure communication",
		Run:   runRootCmd,
	}

	serverCmd = &cobra.Command{
		Use:   "server",
		Short: "Run at the tunnel server-side",
		RunE:  runServerCmd,
	}

	clientCmd = &cobra.Command{
		Use:   "client",
		Short: "Run at the tunnel client-side",
		RunE:  runClientCmd,
	}
)

var (
	flagLogLevel         netunnel.LogLevelType
	flagConcurrent       int
	flagAcceptMaxDelay   time.Duration
	flagTunnelType       string
	flagNetwork          string
	flagServerAddr       string
	flagClientAddr       string
	flagClientProtocol   string
	flagSSHTunnelUser    string
	flagSSHTunnelPass    string
	flagSSHTunnelKeyFile string
	flagSSHTunnelKeyPass string
	flagSSHTunnelAuthKey string
	flagSSHConnTimeout   time.Duration

	flagTransformerName string
	flagTransformerKey  string
	flagTransformerPass string
)

func init() {
	rootFlags := rootCmd.PersistentFlags()
	rootFlags.Uint32Var(&flagLogLevel, "log-level", netunnel.LogLevelInfo, "set log output level 1 to 4, bigger value means less")
	rootFlags.IntVar(&flagConcurrent, "concurrent", 0, "max concurrent goroutine count")
	rootFlags.DurationVar(&flagAcceptMaxDelay, "accept-max-delay", time.Second, "max delay time when accept error occurs")
	rootFlags.StringVar(&flagTunnelType, "type", "tcp", "specify the netunnel type: tcp or ssh")
	rootFlags.StringVar(&flagNetwork, "network", "tcp", "specify the netunnel network: tcp/tcp4/tcp6/udp/udp4/udp6/ip")
	rootFlags.StringVar(&flagServerAddr, "saddr", "", "specify the server-side address")
	rootCmd.MarkPersistentFlagRequired("saddr")

	rootFlags.StringVar(&flagSSHTunnelUser, "ssh-user", "root", "username to create the ssh tunnel")
	rootFlags.StringVar(&flagSSHTunnelPass, "ssh-pass", "", "password to login the ssh tunnel")
	rootFlags.StringVar(&flagSSHTunnelKeyFile, "ssh-key-file", "", "key file path to create the ssh tunnel")
	rootFlags.StringVar(&flagSSHTunnelKeyPass, "ssh-key-pass", "", "key password to parse the key file")
	rootFlags.StringVar(&flagSSHTunnelAuthKey, "ssh-auth-key", "", "authorized public key file for the ssh tunnel server")
	rootFlags.DurationVar(&flagSSHConnTimeout, "ssh-conn-timeout", 0, "connection timeout when open ssh tunnel")

	rootFlags.StringVar(&flagTransformerName, "trans-name", netunnel.AEADNameCHACHA20, "specify the transformer name: "+
		strings.Join([]string{"NULL", netunnel.AEADNameAES128GCM, netunnel.AEADNameAES256GCM, netunnel.AEADNameCHACHA20}, "/"))
	rootFlags.StringVar(&flagTransformerKey, "trans-key", "", "base64 encoded transformer key")
	rootFlags.StringVar(&flagTransformerPass, "trans-pass", "", "ascii string transformer password")

	clientFlags := clientCmd.PersistentFlags()
	clientFlags.StringVar(&flagClientProtocol, "cproto", "socksv5", "specify the netunnel client protocol: socksv4 or socksv5")
	clientFlags.StringVar(&flagClientAddr, "caddr", "", "specify the client-side address")
	clientCmd.MarkPersistentFlagRequired("caddr")

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

	var socksOpt []netunnel.SocksOpt
	cproto := strings.ToUpper(flagClientProtocol)
	switch cproto {
	case "SOCKSV4":
		socksOpt = append(socksOpt, netunnel.WithSocksVersion(netunnel.SocksV4))
	case "SOCKSV5":
		socksOpt = append(socksOpt, netunnel.WithSocksVersion(netunnel.SocksV5))
	}
	endpoint, err := netunnel.NewEndpoint(
		netunnel.EndpointClient,
		flagNetwork,
		flagClientAddr,
		tunnel,
		netunnel.WithEndpointConcurrent(flagConcurrent),
		netunnel.WithEndpointMaxAcceptDelay(flagAcceptMaxDelay),
		netunnel.WithEndpointServerAddr(flagServerAddr),
		netunnel.WithEndpointClientSocksOpt(socksOpt...),
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
		return netunnel.NewTCPTunnel(createTransformer), nil
	case "SSH":
		return netunnel.NewSSHTunnel(
			netunnel.WithSSHTunnelUser(flagSSHTunnelUser),
			netunnel.WithSSHTunnelPassword(flagSSHTunnelPass),
			netunnel.WithSSHTunnelKey(flagSSHTunnelKeyFile, flagSSHTunnelKeyPass),
			netunnel.WithSSHTunnelAuthorizedKey(flagSSHTunnelAuthKey),
			netunnel.WithSSHTunnelConnTimeout(flagSSHConnTimeout),
		), nil
	}
	return nil, fmt.Errorf("tunnel type not supported: %v", flagTunnelType)
}

func createTransformer() (netunnel.Transformer, error) {
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
