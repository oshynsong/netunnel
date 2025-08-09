package netunnel

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"io"
	"net"
	"time"
)

// Tunnel is an abstraction of a network tunnel to build security communication
// between two endpoints over the unsecure network. It can be divided into the
// client-side and server-side functions to build program run respectively.
type Tunnel interface {
	// Open builds a new connection tunnel from local side to remote side.
	// Different authentication strategies should be concerned by the specific
	// low-level implementation such as SSH, SSL, IPSec etc.
	Open(ctx context.Context, network, remoteAddr string) error
	// Close shutdowns the tunnel created by the Open method to release resources.
	Close() error
	// KeepAlive performs a special operation to keep the tunnel alive. It should
	// be called in a background goroutine to prevent hang the main process.
	KeepAlive(ctx context.Context, interval time.Duration)
	// Dial creates a new connection to the target address based on the current
	// tunnel at the client-side to provide security communication.
	Dial(ctx context.Context, network, targetAddr string) (*TunnelConn, error)

	// Listen creates a server-side endpoint to serve for the tunnel.
	Listen(ctx context.Context, network, serverAddr string) error
	// Accept returns the new connection to the target address at the server-side
	// to provide security communication.
	Accept(ctx context.Context) (*TunnelConn, string, error)
}

// TunnelConnID represents a identity of a tunnel connection.
type TunnelConnID []byte

// NewTunnelConnID creates a new tunnel connection ID.
func NewTunnelConnID() TunnelConnID {
	data := make([]byte, 16)
	io.ReadFull(rand.Reader, data)
	return TunnelConnID(data)
}

func (t TunnelConnID) String() string {
	return hex.EncodeToString([]byte(t))
}

const (
	defaultTunnelConnTimeout   = time.Second * 5
	defaultTunnelAcceptTimeout = time.Second * 10
)

// TunnelConn represents a actual connection created on the Tunnel facility.
type TunnelConn struct {
	net.Conn
	Transformer
	id         TunnelConnID
	createdAt  time.Time
	lastUnread []byte
}

// NewTunnelConn creates a new TunnelConn instance based on the given low-level
// network connection and payload transformer to provide safety.
func NewTunnelConn(ctx context.Context, conn net.Conn, t Transformer) *TunnelConn {
	if conn == nil {
		return nil
	}
	if t == nil {
		t = NewNullTransformer()
	}
	tc := &TunnelConn{
		Conn:        conn,
		Transformer: t,
		id:          NewTunnelConnID(),
		createdAt:   time.Now(),
	}
	return tc
}

func (t *TunnelConn) ID() TunnelConnID {
	return t.id
}

func (t *TunnelConn) CreatedAt() *time.Time {
	return &t.createdAt
}

func (t *TunnelConn) Read(b []byte) (int, error) {
	if len(t.lastUnread) > 0 {
		n := copy(b, t.lastUnread)
		t.lastUnread = t.lastUnread[n:]
		if len(t.lastUnread) == 0 {
			t.lastUnread = nil
		}
		return n, nil
	}

	var buf bytes.Buffer
	size, err := t.Unwrap(t.Conn, &buf)
	if err != nil {
		return 0, err
	}
	rb := buf.Bytes()
	n := copy(b, rb[:size])
	if int64(n) < size {
		t.lastUnread = append(t.lastUnread, rb[n:size]...)
	}
	return n, nil
}

func (t *TunnelConn) WriteTo(w io.Writer) (n int64, err error) {
	for len(t.lastUnread) > 0 {
		nw, ew := w.Write(t.lastUnread)
		t.lastUnread = t.lastUnread[nw:]
		n += int64(nw)
		if ew != nil {
			return n, ew
		}
		if len(t.lastUnread) == 0 {
			t.lastUnread = nil
		}
	}

	for {
		nw, ew := t.Unwrap(t.Conn, w)
		if ew != nil {
			err = ew
			break
		}
		n += nw
	}
	if err == io.EOF {
		err = nil // treat EOF as nil error
	}
	return n, err
}

func (t *TunnelConn) Write(b []byte) (int, error) {
	size, err := t.ReadFrom(bytes.NewReader(b))
	return int(size), err
}

func (t *TunnelConn) ReadFrom(r io.Reader) (n int64, err error) {
	for {
		nr, ne := t.Wrap(r, t.Conn)
		if ne != nil {
			err = ne
			break
		}
		n += nr
		if nr == 0 {
			break
		}
	}
	if err == io.EOF {
		err = nil // treat EOF as nil error
	}
	return n, err
}
