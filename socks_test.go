package netunnel

import (
	"bytes"
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
}
