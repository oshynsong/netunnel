package netunnel

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

// TCPTunnel implements a tunnel based on tcp protocol with client and server sides.
type TCPTunnel struct {
	clientAddr  string
	keepAlive   time.Duration
	connTimeout time.Duration

	serverAddr    string
	serverHandle  net.Listener
	acceptTimeout time.Duration

	transformerMaker func(key []byte) (Transformer, error)
	privateKeyFile   string
	publicKeyFile    string
	authPrivateKey   ed25519.PrivateKey
	authPublicKeys   []ed25519.PublicKey
}

type TCPTunnelOpt = func(*TCPTunnel)

func WithTCPTunnelTransformer(tm func(key []byte) (Transformer, error)) TCPTunnelOpt {
	return func(t *TCPTunnel) {
		t.transformerMaker = tm
	}
}

func WithTCPTunnelConnTimeout(d time.Duration) TCPTunnelOpt {
	return func(t *TCPTunnel) {
		t.connTimeout = d
	}
}

func WithTCPTunnelAcceptTimeout(d time.Duration) TCPTunnelOpt {
	return func(t *TCPTunnel) {
		t.acceptTimeout = d
	}
}

func WithTCPTunnelPrivateKeyFile(k string) TCPTunnelOpt {
	return func(t *TCPTunnel) {
		t.privateKeyFile = k
	}
}

func WithTCPTunnelPublicKeyFile(k string) TCPTunnelOpt {
	return func(t *TCPTunnel) {
		t.publicKeyFile = k
	}
}

func NewTCPTunnel(opts ...TCPTunnelOpt) (Tunnel, error) {
	t := &TCPTunnel{}
	for _, opt := range opts {
		opt(t)
	}
	if t.transformerMaker == nil {
		t.transformerMaker = func([]byte) (Transformer, error) {
			return NewNullTransformer(), nil
		}
	}
	if t.connTimeout == 0 {
		t.connTimeout = defaultTunnelConnTimeout
	}
	if t.acceptTimeout == 0 {
		t.acceptTimeout = defaultTunnelAcceptTimeout
	}

	// Parse private key with hex encoded string.
	rawBytes, err := os.ReadFile(t.privateKeyFile)
	if err != nil {
		return nil, fmt.Errorf("read private key file error: %w", err)
	}
	rawBytes, err = hex.DecodeString(string(rawBytes))
	if err != nil || len(rawBytes) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("decode private key error: %w, size=%d", err, len(rawBytes))
	}
	t.authPrivateKey = ed25519.PrivateKey(rawBytes)
	LogInfo(context.Background(), "TCPTunnel: parse private key %d bytes success", len(rawBytes))

	// Parse multiple public keys with hex encoded string each line.
	raw, err := os.ReadFile(t.publicKeyFile)
	if err != nil {
		return nil, fmt.Errorf("read public key file error: %w", err)
	}
	bs := bufio.NewScanner(bytes.NewReader(raw))
	for bs.Scan() {
		raw, err = hex.DecodeString(bs.Text())
		if err != nil || len(raw) != ed25519.PublicKeySize {
			LogError(context.Background(), "TCPTunnel: parse public key failed %v, size=%d", err, len(raw))
			continue
		}
		t.authPublicKeys = append(t.authPublicKeys, ed25519.PublicKey(raw))
	}
	if len(t.authPublicKeys) == 0 {
		return nil, fmt.Errorf("no auth public key given")
	}
	LogInfo(context.Background(), "TCPTunnel: parse %d public keys success", len(t.authPublicKeys))
	return t, nil
}

func (t *TCPTunnel) Open(ctx context.Context, network, remoteAddr string) error {
	if !strings.Contains(network, "tcp") {
		return ErrInvalidNetwork
	}
	t.serverAddr = remoteAddr
	return nil
}

func (t *TCPTunnel) Close() error {
	if t.serverHandle != nil {
		return t.serverHandle.Close()
	}
	return nil
}

func (t *TCPTunnel) KeepAlive(ctx context.Context, interval time.Duration) {
	t.keepAlive = interval
}

func (t *TCPTunnel) Dial(ctx context.Context, network, targetAddr string) (*TunnelConn, error) {
	if !strings.Contains(network, "tcp") {
		return nil, ErrInvalidNetwork
	}

	conn, err := net.DialTimeout(network, t.serverAddr, t.connTimeout)
	if err != nil {
		return nil, err
	}
	realConn := conn.(*net.TCPConn)
	realConn.SetKeepAlive(true)
	realConn.SetKeepAlivePeriod(t.keepAlive)

	LogDebug(ctx, "TCPTunnel.Accept: start to gen session key for %s", targetAddr)
	sessionKey, keyErr := NewSessionKey(conn, true)
	if keyErr != nil {
		return nil, keyErr
	}
	if err = sessionKey.Process(ctx, t.authPrivateKey, t.authPublicKeys); err != nil {
		return nil, err
	}
	LogDebug(ctx, "TCPTunnel.Dial: create session key success for %s", targetAddr)

	transformer, err := t.transformerMaker(sessionKey.Get())
	if err != nil {
		return nil, err
	}
	tc := NewTunnelConn(ctx, conn, transformer)
	LogInfo(ctx, "TCPTunnel.Dail: start to dial %s with id %s", targetAddr, tc.ID())

	sa, err := NewSocksAddrString(targetAddr)
	if err != nil {
		return nil, err
	}
	if _, err := tc.Write(sa); err != nil {
		return nil, err
	}
	LogInfo(ctx, "TCPTunnel.Dail: dial target %s success id %s", targetAddr, tc.ID())
	return tc, nil
}

func (t *TCPTunnel) Listen(ctx context.Context, network, serverAddr string) error {
	if !strings.Contains(network, "tcp") {
		return ErrInvalidNetwork
	}
	listener, err := net.Listen(network, serverAddr)
	if err != nil {
		return err
	}
	t.serverHandle = listener
	return nil
}

func (t *TCPTunnel) Accept(ctx context.Context) (tc *TunnelConn, targetAddr string, err error) {
	conn, err := t.serverHandle.Accept()
	if err != nil {
		return nil, targetAddr, err
	}
	if err = conn.SetDeadline(time.Now().Add(t.acceptTimeout)); err != nil {
		return nil, targetAddr, err
	}

	LogDebug(ctx, "TCPTunnel.Accept: start to gen session key from %s", conn.RemoteAddr())
	sessionKey, keyErr := NewSessionKey(conn, false)
	if keyErr != nil {
		return nil, targetAddr, keyErr
	}
	if err = sessionKey.Process(ctx, t.authPrivateKey, t.authPublicKeys); err != nil {
		return nil, targetAddr, err
	}
	LogDebug(ctx, "TCPTunnel.Accept: create session key success from %s", conn.RemoteAddr())

	transformer, err := t.transformerMaker(sessionKey.Get())
	if err != nil {
		return nil, targetAddr, err
	}
	tc = NewTunnelConn(ctx, conn, transformer)
	LogInfo(ctx, "TCPTunnel.Accept: start to accept addr with id %s", tc.ID())

	sa, err := NewSocksAddrStream(tc)
	if err != nil {
		return nil, targetAddr, err
	}
	defer conn.SetDeadline(time.Time{}) // accept success within the timeout, set no-timeout for later read/writes
	targetAddr = sa.String()
	LogInfo(ctx, "TCPTunnel.Accept: accept and get target addr %s with id %s", targetAddr, tc.ID())
	return tc, targetAddr, nil
}
