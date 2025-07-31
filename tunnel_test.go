package netunnel

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

type testConn struct {
	buf bytes.Buffer
}

func (t *testConn) Read(b []byte) (n int, err error) {
	return t.buf.Read(b)
}

func (t *testConn) Write(b []byte) (n int, err error) {
	return t.buf.Write(b)
}

func (t *testConn) Close() error {
	t.buf.Reset()
	return nil
}

func (t *testConn) LocalAddr() net.Addr              { return nil }
func (t *testConn) RemoteAddr() net.Addr             { return nil }
func (t *testConn) SetDeadline(time.Time) error      { return nil }
func (t *testConn) SetReadDeadline(time.Time) error  { return nil }
func (t *testConn) SetWriteDeadline(time.Time) error { return nil }

func TestTunnelConn(t *testing.T) {
	key := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	trans, err := NewAEADTransformer("AEAD_AES_128_GCM", key)
	assert.Nil(t, err)
	assert.NotNil(t, trans)

	c := NewTunnelConn(context.TODO(), &testConn{}, trans)
	data := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}

	n, e := c.Write(data)
	assert.Nil(t, e)
	assert.True(t, n > 0)
	t.Logf("tunnel connection write %d bytes, err=%v", n, e)

	buf := make([]byte, 5)
	n, e = c.Read(buf)
	t.Logf("tunnel connection read %d bytes %x, err=%v", n, buf[:n], e)
	n, e = c.Read(buf)
	t.Logf("tunnel connection read %d bytes %x, err=%v", n, buf[:n], e)
}
