package netunnel

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSessionKey(t *testing.T) {
	clientConn, serverConn := NewMemConn("localhost")
	defer clientConn.Close()
	defer serverConn.Close()

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
		fmt.Println(sk1.Process(context.TODO()))
	}()
	go func() {
		defer wg.Done()
		fmt.Println(sk2.Process(context.TODO()))
	}()
	wg.Wait()

	assert.EqualValues(t, sk1.Get(), sk2.Get())
	t.Logf("session key: %x", sk1.Get())
}
