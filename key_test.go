package netunnel

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSessionKey(t *testing.T) {
	clientConn, serverConn := NewMemConn("localhost")
	defer clientConn.Close()
	defer serverConn.Close()

	pubKey1, priKey1, err := ed25519.GenerateKey(rand.Reader)
	assert.Nil(t, err)
	pubKey2, priKey2, err := ed25519.GenerateKey(rand.Reader)
	assert.Nil(t, err)

	sk1, err1 := NewSessionKey(serverConn, false)
	assert.Nil(t, err1)
	assert.NotNil(t, sk1)
	sk2, err2 := NewSessionKey(clientConn, true)
	assert.Nil(t, err2)
	assert.NotNil(t, sk2)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		fmt.Println(sk1.Process(context.TODO(), priKey1, []ed25519.PublicKey{pubKey2}))
	}()
	go func() {
		defer wg.Done()
		fmt.Println(sk2.Process(context.TODO(), priKey2, []ed25519.PublicKey{pubKey1}))
	}()
	wg.Wait()

	assert.EqualValues(t, sk1.Get(), sk2.Get())
	t.Logf("session key: %x", sk1.Get())
}
