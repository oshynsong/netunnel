package netunnel

import (
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"io"
)

type SessionKey struct {
	io.ReadWriter
	isClient   bool
	buf        []byte
	sessionKey []byte
	serverPri  *ecdh.PrivateKey
	clientPri  *ecdh.PrivateKey
	signPub    []byte
	signPri    []byte
}

// NewSessionKey creates a SessionKey to be used by each communication.
func NewSessionKey(rw io.ReadWriter, isClient bool) (*SessionKey, error) {
	sk := &SessionKey{
		ReadWriter: rw,
		isClient:   isClient,
		buf:        make([]byte, ed25519.PublicKeySize),
	}
	privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	if isClient {
		sk.clientPri = privateKey
	} else {
		sk.serverPri = privateKey
	}
	return sk, nil
}

func (s *SessionKey) Get() []byte {
	return s.sessionKey
}

func (s *SessionKey) Process(ctx context.Context) (err error) {
	if s.isClient {
		return s.clientProcess(ctx)
	}

	n, e := io.ReadFull(s, s.buf)
	LogDebug(ctx, "server-side: read client %d bytes, error %v", n, e)
	if e != nil {
		return fmt.Errorf("server-side: read client public key failed: %v", e)
	}
	if n != len(s.buf) {
		return fmt.Errorf("server-side: read client public key failed: expected %d bytes, got %d", len(s.buf), n)
	}
	LogInfo(ctx, "server-side: read client public key %d bytes success", n)

	remotePub, keyErr := ecdh.X25519().NewPublicKey(s.buf)
	if keyErr != nil {
		return fmt.Errorf("server-side: create client public key failed: %v", keyErr)
	}
	s.sessionKey, err = s.serverPri.ECDH(remotePub)
	if err != nil {
		return fmt.Errorf("server-side: create session key key failed: %v", err)
	}
	LogInfo(ctx, "server-side: create session key %d bytes success", len(s.sessionKey))

	pubKey := s.serverPri.PublicKey().Bytes()
	if _, err = s.Write(pubKey); err != nil {
		return fmt.Errorf("server-side: write public key failed: %v", err)
	}
	LogInfo(ctx, "server-side: write public key %d bytes success", len(pubKey))
	return nil
}

func (s *SessionKey) clientProcess(ctx context.Context) (err error) {
	publicKey := s.clientPri.PublicKey().Bytes()
	if _, err = s.Write(publicKey); err != nil {
		return fmt.Errorf("client-side: write public key failed: %v", err)
	}
	LogInfo(ctx, "client-side: write public key %d bytes success", len(publicKey))

	n, e := io.ReadFull(s, s.buf)
	LogDebug(ctx, "client-side: read client %d bytes, error %v", n, e)
	if e != nil {
		return fmt.Errorf("client-side: read server public key failed: %v", e)
	}
	if n != len(s.buf) {
		return fmt.Errorf("client-side: read server public key failed: expected %d bytes, got %d", len(s.buf), n)
	}
	LogInfo(ctx, "client-side: read server public key %d bytes success", n)

	remotePub, keyErr := ecdh.X25519().NewPublicKey(s.buf)
	if keyErr != nil {
		return fmt.Errorf("client-side: create server public key failed: %v", keyErr)
	}
	s.sessionKey, err = s.clientPri.ECDH(remotePub)
	if err != nil {
		return fmt.Errorf("client-side: create session key key failed: %v", err)
	}
	LogInfo(ctx, "client-side: create session key %d bytes success", len(s.sessionKey))
	return nil
}
