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
	privateKey *ecdh.PrivateKey
}

// NewClientSessionKey creates a client session key to be used at client-side.
func NewClientSessionKey(rw io.ReadWriter) (*SessionKey, error) {
	sk := &SessionKey{
		ReadWriter: rw,
		isClient:   true,
		buf:        make([]byte, ed25519.PublicKeySize+ed25519.SignatureSize),
	}
	privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	sk.privateKey = privateKey
	return sk, nil
}

// NewServerSessionKey creates a server session key to be used at server-side.
func NewServerSessionKey(rw io.ReadWriter) (*SessionKey, error) {
	sk := &SessionKey{
		ReadWriter: rw,
		isClient:   false,
		buf:        make([]byte, ed25519.PublicKeySize+ed25519.SignatureSize),
	}
	privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	sk.privateKey = privateKey
	return sk, nil
}

func (s *SessionKey) Get() []byte {
	return s.sessionKey
}

func (s *SessionKey) String() string {
	return hex.EncodeToString(s.sessionKey)
}

func (s *SessionKey) ServerProcess(ctx context.Context, signKey ed25519.PrivateKey, verifyKeys []ed25519.PublicKey) (err error) {
	if err = s.receiveSessionPublicKey(verifyKeys); err != nil {
		return fmt.Errorf("server-side: %w", err)
	}
	LogInfo(ctx, "SessionKey: server-side create session key %d bytes success", len(s.sessionKey))

	if err = s.sendSessionPublicKey(signKey); err != nil {
		return fmt.Errorf("server-side: %w", err)
	}
	LogInfo(ctx, "SessionKey: server-side write public key and signature success")
	return nil
}

func (s *SessionKey) ClientProcess(ctx context.Context, signKey ed25519.PrivateKey, verifyKeys []ed25519.PublicKey) (err error) {
	if err = s.sendSessionPublicKey(signKey); err != nil {
		return fmt.Errorf("client-side: %w", err)
	}
	LogInfo(ctx, "SessionKey: client-side write public key and signature success")

	if err = s.receiveSessionPublicKey(verifyKeys); err != nil {
		return fmt.Errorf("client-side: %w", err)
	}
	LogInfo(ctx, "SessionKey: client-side create session key %d bytes success", len(s.sessionKey))
	return nil
}

func (s *SessionKey) sendSessionPublicKey(signKey ed25519.PrivateKey) error {
	// Send the local public key and signature to remote.
	publicKey := s.privateKey.PublicKey().Bytes()
	signature, err := s.sign(signKey, publicKey)
	if err != nil {
		return fmt.Errorf("sign public key failed: %w", err)
	}
	if _, err = s.Write(publicKey); err != nil {
		return fmt.Errorf("write public key failed: %w", err)
	}
	if _, err = s.Write(signature); err != nil {
		return fmt.Errorf("write public key signature failed: %w", err)
	}
	return nil
}

func (s *SessionKey) receiveSessionPublicKey(verifyKeys []ed25519.PublicKey) error {
	// Receive the remote public key, signature and generate the session key if verified.
	n, e := io.ReadFull(s, s.buf)
	if e != nil {
		return fmt.Errorf("read public key and signature failed: %w", e)
	}
	if n != len(s.buf) {
		return fmt.Errorf("read public key and signature failed: expected %d bytes, got %d", len(s.buf), n)
	}
	publicKey, signature := s.buf[:ed25519.PublicKeySize], s.buf[ed25519.PublicKeySize:]
	if !s.verify(verifyKeys, publicKey, signature) {
		return fmt.Errorf("verify public key signature error")
	}
	remotePub, keyErr := ecdh.X25519().NewPublicKey(publicKey)
	if keyErr != nil {
		return fmt.Errorf("create public key failed: %w", keyErr)
	}

	var err error
	s.sessionKey, err = s.privateKey.ECDH(remotePub)
	if err != nil {
		return fmt.Errorf("create session key key failed: %w", err)
	}
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
