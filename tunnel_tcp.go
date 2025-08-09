package netunnel

import (
	"context"
	"net"
	"strings"
	"time"
)

type TCPTunnel struct {
	clientAddr   string
	clientHandle net.Conn
	connTimeout  time.Duration

	serverAddr    string
	serverHandle  net.Listener
	acceptTimeout time.Duration

	transformerMaker func() (Transformer, error)
}

func NewTCPTunnel(tm func() (Transformer, error), connTm, acceptTm time.Duration) Tunnel {
	if tm == nil {
		tm = func() (Transformer, error) {
			return NewNullTransformer(), nil
		}
	}
	tt := &TCPTunnel{
		connTimeout:      connTm,
		acceptTimeout:    acceptTm,
		transformerMaker: tm,
	}
	if tt.connTimeout == 0 {
		tt.connTimeout = defaultTunnelConnTimeout
	}
	if tt.acceptTimeout == 0 {
		tt.acceptTimeout = defaultTunnelAcceptTimeout
	}
	return tt
}

func (t *TCPTunnel) Open(ctx context.Context, network, remoteAddr string) error {
	if !strings.Contains(network, "tcp") {
		return ErrInvalidNetwork
	}

	conn, err := net.DialTimeout(network, remoteAddr, t.connTimeout)
	if err != nil {
		return err
	}
	t.clientHandle = conn
	t.serverAddr = remoteAddr

	// Send the remote server addr for the tunnel keepalive connection.
	transformer, err := t.transformerMaker()
	if err != nil {
		return err
	}
	tc := NewTunnelConn(ctx, conn, transformer)
	sa, err := NewSocksAddrString(remoteAddr)
	if err != nil {
		return err
	}
	if _, err := tc.Write(sa); err != nil {
		return err
	}
	return nil
}

func (t *TCPTunnel) Close() error {
	if t.clientHandle != nil {
		return t.clientHandle.Close()
	} else if t.serverHandle != nil {
		return t.serverHandle.Close()
	}
	return nil
}

func (t *TCPTunnel) KeepAlive(ctx context.Context, interval time.Duration) {
	if t.clientHandle == nil {
		return
	}
	switch realConn := t.clientHandle.(type) {
	case *net.TCPConn:
		realConn.SetKeepAlive(true)
		realConn.SetKeepAlivePeriod(interval)
	case *net.UDPConn, *net.IPConn:
		return
	}
}

func (t *TCPTunnel) Dial(ctx context.Context, network, targetAddr string) (*TunnelConn, error) {
	if !strings.Contains(network, "tcp") {
		return nil, ErrInvalidNetwork
	}

	conn, err := net.DialTimeout(network, t.serverAddr, t.connTimeout)
	if err != nil {
		return nil, err
	}

	transformer, err := t.transformerMaker()
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

	transformer, err := t.transformerMaker()
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
