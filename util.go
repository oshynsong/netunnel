package netunnel

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"
)

const (
	TypeTCP = "TCP"
	TypeSSH = "SSH"
)

const (
	ProxyTypeHttp   = "HTTP"
	ProxyTypeSocks5 = "SOCKS5"
	ProxyTypeSocks4 = "SOCKS4"
)

var (
	ErrUnknown                = errors.New("netunnel: unknown error")
	ErrNotImplemented         = errors.New("netunnel: not implemented")
	ErrInvalidTransformerName = errors.New("netunnel: invalid transformer name")
	ErrKeySizeError           = errors.New("netunnel: key size error")
	ErrSaltCorrupt            = errors.New("netunnel: salt corrupt")
	ErrInvalidEndpointType    = errors.New("netunnel: invalid endpoint type")
	ErrInvalidNetwork         = errors.New("netunnel: invalid network")
	ErrEndpointClosed         = errors.New("netunnel: endpoint closed")
)

func ExitNotify() <-chan os.Signal {
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)
	return signalChan
}

func Relay(ctx context.Context, left, right net.Conn, done <-chan struct{}) error {
	const wait = 10 * time.Second

	errCh := make(chan error)
	go func() {
		_, err := io.Copy(right, left)
		right.SetReadDeadline(time.Now().Add(wait))
		errCh <- err
	}()
	go func() {
		_, err := io.Copy(left, right)
		left.SetReadDeadline(time.Now().Add(wait))
		errCh <- err
	}()

	var err error
	select {
	case err = <-errCh:
	case <-done:
		err = os.ErrClosed
	}
	LogInfo(ctx, "relay finished: %s <=> {%s | %s} <=> %s", left.RemoteAddr(), left.LocalAddr(), right.LocalAddr(), right.RemoteAddr())
	if err != nil && !errors.Is(err, os.ErrDeadlineExceeded) && !errors.Is(err, os.ErrClosed) {
		return err
	}
	return nil
}

// MemAddr is a custom network addr used to build the memory conn.
type MemAddr struct {
	network string
	addr    string
}

// NewMemAddr creates a memory address instance.
func NewMemAddr(val string) *MemAddr {
	return &MemAddr{
		network: "mem",
		addr:    val,
	}
}

func (m *MemAddr) Network() string { return m.network }
func (m *MemAddr) String() string  { return m.addr }

// unidirectionalMemConn builds a blocking memory connection with timeout support. It Only
// provides an one-way direction connection. Use both to support bidirectional connection
type unidirectionalMemConn struct {
	dataCh     chan []byte
	lastUnread []byte
	rtimeout   time.Duration
	wtimeout   time.Duration
	rtimer     *time.Timer
	wtimer     *time.Timer
	closed     chan struct{}
}

func (m *unidirectionalMemConn) Read(buf []byte) (n int, e error) {
	if len(m.lastUnread) > 0 {
		nr := copy(buf, m.lastUnread)
		m.lastUnread = m.lastUnread[nr:]
		if len(m.lastUnread) == 0 {
			m.lastUnread = nil
		}
		return nr, nil
	}

	var got []byte
	if m.rtimer == nil {
		select {
		case got = <-m.dataCh:
		case <-m.closed:
			e = os.ErrClosed
		}
	} else {
		select {
		case got = <-m.dataCh:
		case <-m.rtimer.C:
			e = os.ErrDeadlineExceeded
			m.rtimer = time.NewTimer(m.rtimeout)
		case <-m.closed:
			e = os.ErrClosed
		}
	}
	if e != nil {
		return
	}
	n = copy(buf, got)
	if n < len(got) {
		m.lastUnread = append(m.lastUnread, got[n:]...)
	}
	return n, nil
}

func (m *unidirectionalMemConn) Write(buf []byte) (n int, e error) {
	if m.wtimer == nil {
		select {
		case m.dataCh <- buf:
			n = len(buf)
		case <-m.closed:
			e = os.ErrClosed
		}
	} else {
		select {
		case m.dataCh <- buf:
			n = len(buf)
		case <-m.wtimer.C:
			e = os.ErrDeadlineExceeded
			m.wtimer = time.NewTimer(m.wtimeout)
		case <-m.closed:
			e = os.ErrClosed
		}
	}
	return
}

func (m *unidirectionalMemConn) Close() error {
	if m.closed != nil {
		close(m.closed)
		m.closed = nil
	}
	return nil
}

func (m *unidirectionalMemConn) SetDeadline(t time.Time) error {
	duration := time.Until(t)
	m.rtimeout, m.wtimeout = duration, duration
	m.rtimer = time.NewTimer(duration)
	m.wtimer = time.NewTimer(duration)
	return nil
}

func (m *unidirectionalMemConn) SetReadDeadline(t time.Time) error {
	m.rtimeout = time.Until(t)
	m.rtimer = time.NewTimer(m.rtimeout)
	return nil
}

func (m *unidirectionalMemConn) SetWriteDeadline(t time.Time) error {
	m.wtimeout = time.Until(t)
	m.wtimer = time.NewTimer(m.wtimeout)
	return nil
}

// MemConn provides a bidirectional memory connection functionalitiy.
type MemConn struct {
	addr   net.Addr
	reader *unidirectionalMemConn
	writer *unidirectionalMemConn
}

// NewMemConn creates an instance of MemConn with given address.
func NewMemConn(addr string) (client, server net.Conn) {
	reader := &unidirectionalMemConn{
		dataCh: make(chan []byte),
		closed: make(chan struct{}),
	}
	writer := &unidirectionalMemConn{
		dataCh: make(chan []byte),
		closed: make(chan struct{}),
	}
	ma := NewMemAddr(addr)
	client = &MemConn{addr: ma, reader: reader, writer: writer}
	server = &MemConn{addr: ma, reader: writer, writer: reader}
	return client, server
}

func (m *MemConn) LocalAddr() net.Addr           { return m.addr }
func (m *MemConn) RemoteAddr() net.Addr          { return m.addr }
func (m *MemConn) Read(buf []byte) (int, error)  { return m.reader.Read(buf) }
func (m *MemConn) Write(buf []byte) (int, error) { return m.writer.Write(buf) }

func (m *MemConn) Close() error {
	_ = m.reader.Close()
	_ = m.writer.Close()
	return nil
}

func (m *MemConn) SetDeadline(t time.Time) error {
	_ = m.reader.SetDeadline(t)
	_ = m.writer.SetDeadline(t)
	return nil
}

func (m *MemConn) SetReadDeadline(t time.Time) error {
	return m.reader.SetReadDeadline(t)
}

func (m *MemConn) SetWriteDeadline(t time.Time) error {
	return m.writer.SetWriteDeadline(t)
}
