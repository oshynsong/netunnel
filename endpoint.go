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

const (
	EndpointServer EndpointType = iota
	EndpointClient
)

// Endpoint implements the core logic of a endpoint program which runs
// as a server-side or client-side of a tunnel respectively.
type Endpoint struct {
	typ            EndpointType
	tunnel         Tunnel
	network        string
	serverAddr     string
	clientAddr     string
	clientSocksOpt []SocksOpt
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
		maxAcceptDelay: time.Second, // default 1s
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

func WithEndpointClientSocksOpt(opt ...SocksOpt) EndpointOpt {
	return func(e *Endpoint) {
		e.clientSocksOpt = opt
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
	defer e.tunnel.Close()

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
			LogError(ctx, "server endpoint accept non-timeout error: %v", err)
			continue
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
	defer e.tunnel.Close()
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

			sp := NewSocksProcessor(lc, e.clientSocksOpt...)
			if err = sp.Process(c); err != nil {
				return
			}
			target := sp.RequestAddr.String()

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
	close(e.done)
	e.exitWg.Wait()
}
