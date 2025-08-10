package netunnel

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHttpProcessor(t *testing.T) {
	version := "HTTP/1.0"
	authUser, authPass := "admin", "123456"
	clientConn, serverConn := NewMemConn("localhost")
	defer clientConn.Close()
	defer serverConn.Close()

	client1 := NewHttpProcessor(clientConn, WithHttpVersion(version), WithHttpClientSide())
	client2 := NewHttpProcessor(clientConn, WithHttpVersion(version), WithHttpClientSide(), WithHttpAuthUserPass(authUser, authPass))
	assert.NotNil(t, client1)
	assert.NotNil(t, client2)

	server := NewHttpProcessor(serverConn, WithHttpVersion(version), WithHttpAuthUserPass(authUser, authPass))
	assert.NotNil(t, server)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		client1.RequestAddr = "127.0.0.1:1234"
		fmt.Println("client1:", client1.Process(context.TODO()))

		client2.RequestAddr = "127.0.0.1:1234"
		fmt.Println("client2:", client2.Process(context.TODO()))
	}()
	go func() {
		defer wg.Done()
		fmt.Println("server process client1:", server.Process(context.TODO()))

		fmt.Println("server process client2:", server.Process(context.TODO()))
	}()
	wg.Wait()
}
