package netunnel

import (
	"bytes"
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSocksAddr(t *testing.T) {
	sa, err := NewSocksAddrString("1.2.3.4:1111")
	assert.Nil(t, err)
	assert.NotNil(t, sa)
	sas, err := NewSocksAddrStream(bytes.NewReader(sa))
	assert.Nil(t, err)
	assert.True(t, bytes.Equal(sa, sas))
	t.Logf("1.2.3.4:1111 => %x | %x", []byte(sa), []byte(sas))

	sa, err = NewSocksAddrString("[2409:8a56:3213:fe84:c589:5e44:e6d6:6df3]:8080")
	assert.Nil(t, err)
	assert.NotNil(t, sa)
	sas, err = NewSocksAddrStream(bytes.NewReader(sa))
	assert.Nil(t, err)
	assert.True(t, bytes.Equal(sa, sas))
	t.Logf("[2409:8a56:3213:fe84:c589:5e44:e6d6:6df3]:8080 => %x | %x", []byte(sa), []byte(sas))

	sa, err = NewSocksAddrString("www.baidu.com:443")
	assert.Nil(t, err)
	assert.NotNil(t, sa)
	sas, err = NewSocksAddrStream(bytes.NewReader(sa))
	assert.Nil(t, err)
	assert.True(t, bytes.Equal(sa, sas))
	t.Logf("www.baidu.com:443 => %x | %x", []byte(sa), []byte(sas))

	atyp, addr, port, err := sa.Parts()
	assert.Nil(t, err)
	t.Logf("atyp=%x addr=%x port=%x", atyp, addr, port)
	nsa, err := NewSocksAddr(atyp, addr, port)
	assert.Nil(t, err)
	assert.True(t, bytes.Equal(sa, nsa))
	t.Logf("%x <=> %x", []byte(sa), []byte(nsa))

	portNumber := sa.PortNumber()
	min, max := sa.LengthRange()
	assert.True(t, portNumber == 443)
	assert.True(t, min == 7)
	assert.True(t, max == 259)
	t.Logf("%v %v %v", sa.PortNumber(), min, max)
}

func TestSocksProcessorV4(t *testing.T) {
	clientConn, serverConn := NewMemConn("localhost")
	defer clientConn.Close()
	defer serverConn.Close()

	clientV4 := NewSocksProcessor(clientConn, WithSocksClientSide(), WithSocksVersion(SocksV4))
	serverV4 := NewSocksProcessor(serverConn, WithSocksVersion(SocksV4))
	assert.NotNil(t, clientV4)
	assert.NotNil(t, serverV4)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		clientV4.RequestAddr, _ = NewSocksAddrString("127.0.0.1:1234")
		fmt.Println("clientV4:", clientV4.Process(context.TODO()))
	}()
	go func() {
		defer wg.Done()
		fmt.Println("serverV4:", serverV4.Process(context.TODO()))
	}()
	wg.Wait()
}

func TestSocksProcessorV5(t *testing.T) {
	user, pass := "admin", "123456"
	clientConn, serverConn := NewMemConn("localhost")
	defer clientConn.Close()
	defer serverConn.Close()
	clientV5 := NewSocksProcessor(clientConn, WithSocksClientSide(), WithSocksVersion(SocksV5),
		WithSocksAuthMethod([]byte{SocksAuthMethodUserPass}, SocksAuthMethodUserPass), WithSocksAuthUserPass(user, pass))
	serverV5 := NewSocksProcessor(serverConn, WithSocksVersion(SocksV5),
		WithSocksAuthMethod([]byte{SocksAuthMethodUserPass}, SocksAuthMethodUserPass), WithSocksAuthUserPass(user, pass))
	assert.NotNil(t, clientV5)
	assert.NotNil(t, serverV5)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		clientV5.RequestAddr, _ = NewSocksAddrString("127.0.0.1:1234")
		fmt.Println("clientV5:", clientV5.Process(context.TODO(), SocksCmdConnect))
	}()
	go func() {
		defer wg.Done()
		fmt.Println("serverV5:", serverV5.Process(context.TODO()))
	}()
	wg.Wait()
}
