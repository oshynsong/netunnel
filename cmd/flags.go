package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/oshynsong/netunnel"
)

var (
	flagLogLevel       netunnel.LogLevelType
	flagConcurrent     int
	flagAcceptMaxDelay time.Duration
	flagTunnelType     string
	flagNetwork        string
	flagServerAddr     string
	flagPrivateKeyFile string
	flagPublicKeyFile  string

	flagTransformerName    string
	flagTransConnTimeout   time.Duration
	flagTransAcceptTimeout time.Duration

	flagSSHTunnelUser    string
	flagSSHTunnelPass    string
	flagSSHTunnelKeyFile string
	flagSSHTunnelKeyPass string
	flagSSHTunnelAuthKey string

	flagClientAddr     string
	flagClientProtocol string
	flagProxyAuthUser  string
	flagProxyAuthPass  string

	flagLocalAddr string

	flagToolName string
)

func chainCheck(checks ...func() error) error {
	for _, check := range checks {
		if err := check(); err != nil {
			return err
		}
	}
	return nil
}

func checkServerAddr() error {
	if len(flagServerAddr) == 0 {
		return fmt.Errorf("server addr is required")
	}
	return nil
}

func checkClientAddr() error {
	if len(flagClientAddr) == 0 {
		return fmt.Errorf("client addr is required")
	}
	return nil
}

func checkClientProtocol() error {
	if len(flagClientProtocol) == 0 {
		return fmt.Errorf("client protocol is required")
	}
	return nil
}

func checkTunnelType() error {
	switch strings.ToUpper(flagTunnelType) {
	case netunnel.TypeTCP:
	case netunnel.TypeSSH:
		if len(flagSSHTunnelKeyFile) == 0 {
			return fmt.Errorf("no key file provided for SSH tunnel")
		}
		if len(flagSSHTunnelUser) == 0 && len(flagSSHTunnelPass) == 0 && len(flagSSHTunnelAuthKey) == 0 {
			return fmt.Errorf("no user/password and auth key file provided for SSH tunnel")
		}
	default:
		return fmt.Errorf("tunnel type not supported %s", flagTunnelType)
	}
	return nil
}

func checkKeyFile() error {
	if len(flagPrivateKeyFile) == 0 {
		return fmt.Errorf("no private key file provided")
	}
	if len(flagPublicKeyFile) == 0 {
		return fmt.Errorf("no public key file provided")
	}
	return nil
}

func checkToolName() error {
	if len(flagToolName) == 0 {
		return fmt.Errorf("tool name is required")
	}
	return nil
}

func checkLocalAddr() error {
	if len(flagLocalAddr) == 0 {
		return fmt.Errorf("local addr is required")
	}
	return nil
}
