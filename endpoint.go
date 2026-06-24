package netunnel

import (
	"context"
	"errors"
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

// Endpoint implements the core logic of an endpoint program which runs
// as a server-side or client-side of a tunnel respectively.
type Endpoint struct {
	typ            EndpointType
	tunnel         Tunnel
	proxy          LocalProxy
	remoteDialer   RemoteDialer
	network        string
	serverAddr     string
	clientAddr     string
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
	if obj.proxy == nil {
		obj.proxy = NewSystemProxy(ProxyTypeHttp, NewHttpProxyProto("", ""))
	}
	if obj.remoteDialer == nil {
		obj.remoteDialer = &defaultDialer{}
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

func WithEndpointLocalProxy(proxy LocalProxy) EndpointOpt {
	return func(e *Endpoint) {
		e.proxy = proxy
	}
}

func WithEndpointRemoteDialer(dialer RemoteDialer) EndpointOpt {
	return func(e *Endpoint) {
		e.remoteDialer = dialer
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
		conn, target, ae := e.tunnel.Accept(ctx)
		if ae != nil {
			select {
			case <-e.done:
				return ErrEndpointClosed
			default:
			}
			var ne net.Error
			if errors.As(ae, &ne) && ne != nil && ne.Timeout() {
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
			return ae
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
					LogError(c, "server endpoint panic at %s: %v", ac.ID(), r)
				}
				e.exitWg.Done()
			}()

			rc, err := e.remoteDialer.DialRemote(c, e.network, tgt)
			if err != nil {
				return
			}
			defer rc.Close()
			LogInfo(c, "server endpoint relay: %s <=> {%s | %s} <=> %s",
				ac.RemoteAddr(), ac.LocalAddr(), rc.LocalAddr(), rc.RemoteAddr())
			err = Relay(c, ac, rc, e.done)
		}(reqCtx, conn, target)
	}
}

func (e *Endpoint) serveClient(ctx context.Context) (err error) {
	var listener net.Listener
	if listener, err = e.proxy.Setup(ctx, e.network, e.clientAddr); err != nil {
		return fmt.Errorf("client endpoint setup proxy error %w", err)
	}
	LogInfo(ctx, "client endpoint setup proxy success at %s:%s", e.network, e.clientAddr)
	defer listener.Close()

	if err := e.tunnel.Open(ctx, e.network, e.serverAddr); err != nil {
		return fmt.Errorf("open tunnel error %w", err)
	}
	go e.tunnel.KeepAlive(ctx, time.Second*10)
	LogInfo(ctx, "client endpoint open tunnel success to %s", e.serverAddr)

	var acceptDelay time.Duration
	for {
		conn, ae := listener.Accept()
		if ae != nil {
			select {
			case <-e.done:
				return ErrEndpointClosed
			default:
			}
			var ne net.Error
			if errors.As(ae, &ne) && ne != nil && ne.Timeout() {
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
			return ae
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
					LogError(c, "client endpoint panic for %s: %v", conn.RemoteAddr(), r)
				}
				e.exitWg.Done()
			}()

			target, err := e.proxy.Handshake(c, lc)
			if err != nil {
				return
			}

			rc, err := e.tunnel.Dial(c, e.network, target)
			if err != nil {
				return
			}
			defer rc.Close()

			LogInfo(c, "client endpoint relay started: %s <=> {%s | %s} <=> %s",
				lc.RemoteAddr(), lc.LocalAddr(), rc.LocalAddr(), rc.RemoteAddr())
			err = Relay(c, lc, rc, e.done)
		}(reqCtx, conn)
	}
}

func (e *Endpoint) Close(ctx context.Context) {
	if e.tunnel != nil {
		_ = e.tunnel.Close()
	}
	if e.typ == EndpointClient {
		if err := e.proxy.Reset(ctx); err != nil {
			LogError(ctx, "reset proxy failed: %v", err)
		}
	}
	close(e.done)
	e.exitWg.Wait()
}
