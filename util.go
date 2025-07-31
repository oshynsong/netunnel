package netunnel

import (
	"errors"
	"io"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"
)

var (
	ErrUnknown                = errors.New("netunnel: unknown error")
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

func Relay(left, right net.Conn) error {
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

	err := <-errCh
	if err != nil && !errors.Is(err, os.ErrDeadlineExceeded) {
		return err
	}
	return nil
}
