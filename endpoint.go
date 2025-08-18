package netunnel

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"
)

// EndpointType defines different type of endpoint.
type EndpointType = byte

// The server and client side endpoint enum.
const (
	EndpointServer EndpointType = iota
	EndpointClient
)

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

func NewHttp11ProxyProto(user, pass string) ProxyProto {
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

// Endpoint implements the core logic of a endpoint program which runs
// as a server-side or client-side of a tunnel respectively.
type Endpoint struct {
	typ            EndpointType
	tunnel         Tunnel
	network        string
	serverAddr     string
	clientAddr     string
	proxyProto     ProxyProto
	concurrent     chan struct{}
	maxAcceptDelay time.Duration
	done           chan struct{}
	exitWg         sync.WaitGroup
}

func NewEndpoint(t EndpointType, network, runAddr string, tun Tunnel, opts ...EndpointOpt) (*Endpoint, error) {
	obj := &Endpoint{
		typ:            t,
		tunnel:         tun,
		network:        network,
		maxAcceptDelay: time.Second,
		done:           make(chan struct{}),
	}
	switch t {
	case EndpointServer:
		obj.serverAddr = runAddr
	case EndpointClient:
		obj.clientAddr = runAddr
	default:
		return nil, ErrInvalidEndpointType
	}

	for _, opt := range opts {
		opt(obj)
	}
	if obj.proxyProto == nil {
		obj.proxyProto = NewSocksV5ProxyProto("", "")
	}
	return obj, nil
}

// EndpointOpt is the optional params setter.
type EndpointOpt = func(e *Endpoint)

func WithEndpointServerAddr(addr string) EndpointOpt {
	return func(e *Endpoint) {
		e.serverAddr = addr
	}
}

func WithEndpointConcurrent(n int) EndpointOpt {
	return func(e *Endpoint) {
		if n <= 0 {
			return
		}
		e.concurrent = make(chan struct{}, n)
	}
}

func WithEndpointMaxAcceptDelay(delay time.Duration) EndpointOpt {
	return func(e *Endpoint) {
		e.maxAcceptDelay = delay
	}
}

func WithEndpointProxyProto(pp ProxyProto) EndpointOpt {
	return func(e *Endpoint) {
		e.proxyProto = pp
	}
}

func (e *Endpoint) Serve(ctx context.Context) (err error) {
	if e.typ == EndpointServer {
		return e.serveServer(ctx)
	}
	if e.typ == EndpointClient {
		return e.serveClient(ctx)
	}
	return ErrInvalidEndpointType
}

func (e *Endpoint) serveServer(ctx context.Context) (err error) {
	if err = e.tunnel.Listen(ctx, e.network, e.serverAddr); err != nil {
		return fmt.Errorf("server endpoint listen error %w", err)
	}
	LogInfo(ctx, "server endpoint listen success at %s", e.serverAddr)

	var acceptDelay time.Duration
	for {
		conn, target, err := e.tunnel.Accept(ctx)
		if err != nil {
			select {
			case <-e.done:
				return ErrEndpointClosed
			default:
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				if acceptDelay == 0 {
					acceptDelay = 5 * time.Millisecond
				} else {
					acceptDelay *= 2
				}
				if acceptDelay > e.maxAcceptDelay {
					acceptDelay = e.maxAcceptDelay
				}
				time.Sleep(acceptDelay)
				continue
			}
			return err
		}

		reqCtx := NewLogID(ctx)
		LogInfo(reqCtx, "server endpoint accept %s with target addr %v", conn.RemoteAddr(), target)
		if target == e.serverAddr {
			LogInfo(reqCtx, "server endpoint skip process self target")
			continue
		}

		if e.concurrent != nil {
			e.concurrent <- struct{}{} // acquire a position if concurrent limited
		}
		e.exitWg.Add(1)
		go func(c context.Context, ac *TunnelConn, tgt string) {
			var err error
			defer func() {
				ac.Close()
				if e.concurrent != nil {
					<-e.concurrent // release a position if concurrent limited
				}
				if r := recover(); r != nil {
					LogError(c, "server endpoiint panic at %s: %v", ac.ID(), r)
				}
				LogInfo(c, "server endpoint process finished for %s: %v", ac.ID(), err)
				e.exitWg.Done()
			}()

			rc, err := net.Dial(e.network, tgt)
			if err != nil {
				return
			}
			defer rc.Close()
			LogInfo(c, "server endpoint relay: %s <=> {%s | %s} <=> %s",
				ac.RemoteAddr(), ac.LocalAddr(), rc.LocalAddr(), rc.RemoteAddr())
			err = Relay(ac, rc)
		}(reqCtx, conn, target)
	}
}

func (e *Endpoint) serveClient(ctx context.Context) (err error) {
	var listener net.Listener
	if listener, err = net.Listen(e.network, e.clientAddr); err != nil {
		return fmt.Errorf("client endpoint listen error %w", err)
	}
	LogInfo(ctx, "client endpoint listen success at %s", e.clientAddr)
	defer listener.Close()

	if err := e.tunnel.Open(ctx, e.network, e.serverAddr); err != nil {
		return fmt.Errorf("open tunnel error %w", err)
	}
	go e.tunnel.KeepAlive(ctx, time.Second*10)
	LogInfo(ctx, "client endpoint open tunnel success to %s", e.serverAddr)

	var acceptDelay time.Duration
	for {
		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-e.done:
				return ErrEndpointClosed
			default:
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				if acceptDelay == 0 {
					acceptDelay = 5 * time.Millisecond
				} else {
					acceptDelay *= 2
				}
				if acceptDelay > e.maxAcceptDelay {
					acceptDelay = e.maxAcceptDelay
				}
				time.Sleep(acceptDelay)
				continue
			}
			return err
		}

		reqCtx := NewLogID(ctx)
		LogInfo(reqCtx, "client endpoint accept connection from %s", conn.RemoteAddr())

		if e.concurrent != nil {
			e.concurrent <- struct{}{} // acquire a position if concurrent limited
		}
		e.exitWg.Add(1)
		go func(c context.Context, lc net.Conn) {
			var err error
			defer func() {
				lc.Close()
				if e.concurrent != nil {
					<-e.concurrent // release a position if concurrent limited
				}
				if r := recover(); r != nil {
					LogError(c, "client endpoiint panic for %s: %v", conn.RemoteAddr(), r)
				}
				LogInfo(c, "client endpoint process finished for %s: %v", conn.RemoteAddr(), err)
				e.exitWg.Done()
			}()

			target, err := e.proxyProto(c, lc)
			if err != nil {
				return
			}

			rc, err := e.tunnel.Dial(c, e.network, target)
			if err != nil {
				return
			}
			defer rc.Close()

			LogInfo(c, "client endpoint relay: %s <=> {%s | %s} <=> %s",
				lc.RemoteAddr(), lc.LocalAddr(), rc.LocalAddr(), rc.RemoteAddr())
			err = Relay(lc, rc)
		}(reqCtx, conn)
	}
}

func (e *Endpoint) Close() {
	if e.tunnel != nil {
		_ = e.tunnel.Close()
	}
	close(e.done)
	e.exitWg.Wait()
}
