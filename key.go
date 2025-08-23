package netunnel

import (
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
)

// SessionKey uses the X25519 ECDH algorithm to generate a session key for each
// communication session to encrypt/decrypt data stream.
type SessionKey struct {
	io.ReadWriter
	isClient   bool
	buf        []byte
	sessionKey []byte
	serverPri  *ecdh.PrivateKey
	clientPri  *ecdh.PrivateKey
}

// NewSessionKey creates a SessionKey to be used by each communication.
func NewSessionKey(rw io.ReadWriter, isClient bool) (*SessionKey, error) {
	sk := &SessionKey{
		ReadWriter: rw,
		isClient:   isClient,
		buf:        make([]byte, ed25519.PublicKeySize+ed25519.SignatureSize),
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

func (s *SessionKey) Process(ctx context.Context, signKey ed25519.PrivateKey, verifyKeys []ed25519.PublicKey) (err error) {
	if s.isClient {
		return s.clientProcess(ctx, signKey, verifyKeys)
	}

	n, e := io.ReadFull(s, s.buf)
	LogDebug(ctx, "SessionKey: server-side read %d bytes, error %v", n, e)
	if e != nil {
		return fmt.Errorf("server-side: read client public key and signature failed: %v", e)
	}
	if n != len(s.buf) {
		return fmt.Errorf("server-side: read client public key and signature failed: expected %d bytes, got %d", len(s.buf), n)
	}
	LogInfo(ctx, "SessionKey: server-side read public key and signature %d bytes success", n)

	publicKey, signature := s.buf[:ed25519.PublicKeySize], s.buf[ed25519.PublicKeySize:]
	if !s.verify(verifyKeys, publicKey, signature) {
		return fmt.Errorf("server-side: verify public key signature error")
	}
	remotePub, keyErr := ecdh.X25519().NewPublicKey(publicKey)
	if keyErr != nil {
		return fmt.Errorf("server-side: create client public key failed: %v", keyErr)
	}
	s.sessionKey, err = s.serverPri.ECDH(remotePub)
	if err != nil {
		return fmt.Errorf("server-side: create session key key failed: %v", err)
	}
	LogInfo(ctx, "server-side: create session key %d bytes success", len(s.sessionKey))

	publicKey = s.serverPri.PublicKey().Bytes()
	signature, err = s.sign(signKey, publicKey)
	if err != nil {
		return fmt.Errorf("server-side: sign public key failed: %w", err)
	}
	if _, err = s.Write(publicKey); err != nil {
		return fmt.Errorf("server-side: write public key failed: %v", err)
	}
	if _, err = s.Write(signature); err != nil {
		return fmt.Errorf("server-side: write public key signature failed: %w", err)
	}
	LogInfo(ctx, "Session: server-side write public key %d bytes and signature %d bytes success", len(publicKey), len(signature))
	return nil
}

func (s *SessionKey) clientProcess(ctx context.Context, signKey ed25519.PrivateKey, verifyKeys []ed25519.PublicKey) (err error) {
	publicKey := s.clientPri.PublicKey().Bytes()
	signature, err := s.sign(signKey, publicKey)
	if err != nil {
		return fmt.Errorf("client-side: sign public key failed: %w", err)
	}
	if _, err = s.Write(publicKey); err != nil {
		return fmt.Errorf("client-side: write public key failed: %w", err)
	}
	if _, err = s.Write(signature); err != nil {
		return fmt.Errorf("client-side: write public key signature failed: %w", err)
	}
	LogInfo(ctx, "SessionKey: client-side write public key %d bytes, signature %d bytes success", len(publicKey), len(signature))

	n, e := io.ReadFull(s, s.buf)
	LogDebug(ctx, "SessionKey: client-side read %d bytes, error %v", n, e)
	if e != nil {
		return fmt.Errorf("client-side: read server public key and signature failed: %w", e)
	}
	if n != len(s.buf) {
		return fmt.Errorf("client-side: read server public key and signature failed: expected %d bytes, got %d", len(s.buf), n)
	}
	LogInfo(ctx, "SessionKey: client-side read server public key and signature %d bytes success", n)

	publicKey, signature = s.buf[:ed25519.PublicKeySize], s.buf[ed25519.PublicKeySize:]
	if !s.verify(verifyKeys, publicKey, signature) {
		return fmt.Errorf("client-side: verify public key signature error")
	}
	remotePub, keyErr := ecdh.X25519().NewPublicKey(publicKey)
	if keyErr != nil {
		return fmt.Errorf("client-side: create server public key failed: %w", keyErr)
	}
	s.sessionKey, err = s.clientPri.ECDH(remotePub)
	if err != nil {
		return fmt.Errorf("client-side: create session key key failed: %w", err)
	}
	LogInfo(ctx, "SessionKey: client-side create session key %d bytes success", len(s.sessionKey))
	return nil
}

func (s *SessionKey) sign(key ed25519.PrivateKey, msg []byte) ([]byte, error) {
	if len(key) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid key size for ed25519 sign")
	}
	signature := ed25519.Sign(key, msg)
	return signature, nil
}

func (s *SessionKey) verify(verifyKeys []ed25519.PublicKey, msg, signature []byte) bool {
	for _, key := range verifyKeys {
		if ok := ed25519.Verify(key, msg, signature); ok {
			return true
		}
	}
	return false
}

func GenAuthKey() (pub, pri string) {
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	pub = hex.EncodeToString(public)
	pri = hex.EncodeToString(private)
	return
}
