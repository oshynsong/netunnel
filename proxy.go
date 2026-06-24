package netunnel

import (
	"context"
	"fmt"
	"net"
)

const (
	ProxyTypeHttp   = "HTTP"
	ProxyTypeHttps  = "HTTPS"
	ProxyTypeSocks5 = "SOCKS5"
	ProxyTypeSocks4 = "SOCKS4"
)

type ProxySetting struct {
	enabled     uint32
	address     string
	serviceName string
	proxyType   string
}

// ProxyProto defines how to handshake and get the target addr to build the proxy.
type ProxyProto = func(ctx context.Context, local net.Conn) (addr string, err error)

func NewSocksV4ProxyProto() ProxyProto {
	return func(ctx context.Context, local net.Conn) (addr string, err error) {
		sp := NewSocksProcessor(local, WithSocksVersion(SocksV4))
		if err = sp.Process(ctx); err != nil {
			return
		}
		return sp.RequestAddr.String(), nil
	}
}

func NewSocksV5ProxyProto(user, pass string) ProxyProto {
	return func(ctx context.Context, local net.Conn) (addr string, err error) {
		opts := []SocksOpt{WithSocksVersion(SocksV5)}
		if len(user) != 0 && len(pass) != 0 {
			opts = append(opts, WithSocksAuthMethod([]byte{SocksAuthMethodUserPass}, SocksAuthMethodUserPass))
			opts = append(opts, WithSocksAuthUserPass(user, pass))
		}
		sp := NewSocksProcessor(local, opts...)
		if err = sp.Process(ctx); err != nil {
			return
		}
		return sp.RequestAddr.String(), nil
	}
}

func NewHttpProxyProto(user, pass string) ProxyProto {
	return func(ctx context.Context, local net.Conn) (addr string, err error) {
		opts := []HttpOpt{WithHttpVersion(HttpProxyDefaultVersion)}
		if len(user) != 0 && len(pass) != 0 {
			opts = append(opts, WithHttpAuthUserPass(user, pass))
		}
		hp := NewHttpProcessor(local, opts...)
		if err = hp.Process(ctx); err != nil {
			return
		}
		return hp.RequestAddr, nil
	}
}

func NewSystemProxy(pt string, pp ProxyProto) LocalProxy {
	return &systemProxy{
		proxyType:  pt,
		proxyProto: pp,
	}
}

type systemProxy struct {
	proxyType  string
	proxyProto ProxyProto
	settings   *ProxySetting
}

func (s *systemProxy) Setup(ctx context.Context, network, localAddr string) (net.Listener, error) {
	var lc net.ListenConfig
	listener, err := lc.Listen(ctx, network, localAddr)
	if err != nil {
		return nil, fmt.Errorf("proxy listen %s:%s error: %w", network, localAddr, err)
	}
	s.settings, err = SetupProxy(ctx, s.proxyType, localAddr)
	if err != nil {
		return nil, fmt.Errorf("proxy setup failed: %v", err)
	}
	return listener, nil
}

func (s *systemProxy) Handshake(ctx context.Context, localConn net.Conn) (string, error) {
	return s.proxyProto(ctx, localConn)
}

func (s *systemProxy) Reset(ctx context.Context) error {
	return ResetProxy(ctx, s.settings)
}
