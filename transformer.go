package netunnel

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"io"
	"strings"
	"sync"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

// Transformer abstracts the bytes transform operations on the tunnel connection.
// A transformer must be bound to a connection and keep lifetime the same with it.
type Transformer interface {
	// Wrap encodes the essential information about the stream from the reader
	// and wrap them to the target writer, returns the wrapped size and error.
	// It is called for a sized payload when writing to the tunnel.
	Wrap(from io.Reader, to io.Writer) (int64, error)
	// Unwrap decodes the essential information about the stream from the reader
	// and write plain data to the writer, returns the unwrapped size and error.
	// It is called for sized payload when reading from the tunnel.
	Unwrap(from io.Reader, to io.Writer) (int64, error)
}

// NullTransformer performs null transformation.
type NullTransformer struct {
	buf []byte
}

func NewNullTransformer() Transformer {
	return &NullTransformer{buf: make([]byte, 16*1024)}
}

func (n *NullTransformer) Wrap(from io.Reader, to io.Writer) (int64, error) {
	return n.copyOnce(from, to)
}

func (n *NullTransformer) Unwrap(from io.Reader, to io.Writer) (int64, error) {
	return n.copyOnce(from, to)
}

func (n *NullTransformer) copyOnce(from io.Reader, to io.Writer) (int64, error) {
	nr, er := from.Read(n.buf)
	if nr > 0 {
		nw, ew := to.Write(n.buf[:nr])
		if nw < 0 || nr < nw {
			nw = 0
		}
		if ew != nil {
			return 0, ew
		}
		if nr != nw {
			return 0, io.ErrShortWrite
		}
	}
	return int64(nr), er
}

// AEADPayloadSizeMask is the maximum size of payload in bytes.
const AEADPayloadSizeMask = 0x3FFF

const (
	AEADNameAES128GCM = "AEAD_AES_128_GCM"
	AEADNameAES256GCM = "AEAD_AES_256_GCM"
	AEADNameCHACHA20  = "AEAD_CHACHA20_POLY1305"
)

// AEADTransformer performs the AEAD cipher transformation.
type AEADTransformer struct {
	aeadMaker func([]byte) (cipher.AEAD, error)
	name      string
	key       []byte
	saltBuf   []byte

	wrapAEAD     cipher.AEAD
	unwrapAEAD   cipher.AEAD
	wrapOnce     sync.Once
	unwrapOnce   sync.Once
	rnonce, rbuf []byte
	wnonce, wbuf []byte
}

// NewAEADTransformer creates an instance of AEADTransformer based on
// the given name and key, which key size should match the named cipher.
func NewAEADTransformer(name string, key []byte) (Transformer, error) {
	aesAEADMaker := func(k []byte) (cipher.AEAD, error) {
		blk, err := aes.NewCipher(k)
		if err != nil {
			return nil, err
		}
		return cipher.NewGCM(blk)
	}

	var aeadMaker func(key []byte) (cipher.AEAD, error)
	name = strings.ToUpper(name)
	switch name {
	case AEADNameAES128GCM:
		if len(key) != aes.BlockSize {
			return nil, ErrKeySizeError
		}
		aeadMaker = aesAEADMaker
	case AEADNameAES256GCM:
		if len(key) != aes.BlockSize*2 {
			return nil, ErrKeySizeError
		}
		aeadMaker = aesAEADMaker
	case AEADNameCHACHA20:
		if len(key) != chacha20poly1305.KeySize {
			return nil, ErrKeySizeError
		}
		aeadMaker = chacha20poly1305.New
	default:
		return nil, ErrInvalidTransformerName
	}

	t := &AEADTransformer{
		aeadMaker: aeadMaker,
		name:      name,
		key:       key,
		saltBuf:   make([]byte, len(key)),
	}
	return t, nil
}

// NewAEADTransformerPassword creates an instance of AEADTransformer based
// on the given name and password.
func NewAEADTransformerPassword(name, password string) (Transformer, error) {
	var keySize int
	switch name {
	case AEADNameAES128GCM:
		keySize = aes.BlockSize
	case AEADNameAES256GCM:
		keySize = aes.BlockSize * 2
	case AEADNameCHACHA20:
		keySize = chacha20poly1305.KeySize
	default:
		return nil, ErrInvalidTransformerName
	}

	var key, prev []byte
	h := md5.New()
	for len(key) < keySize {
		h.Write(prev)
		h.Write([]byte(password))
		key = h.Sum(key)
		prev = key[len(key)-h.Size():]
		h.Reset()
	}
	key = key[:keySize]
	return NewAEADTransformer(name, key)
}

func (a *AEADTransformer) callMaker() (cipher.AEAD, error) {
	subKey := make([]byte, len(a.key))
	r := hkdf.New(sha1.New, a.key, a.saltBuf, []byte("ss-subkey"))
	if _, err := io.ReadFull(r, subKey); err != nil {
		return nil, err
	}
	return a.aeadMaker(subKey)
}

func (a *AEADTransformer) incrNonce(b []byte) {
	for i := range b {
		b[i]++
		if b[i] != 0 {
			return
		}
	}
}

func (a *AEADTransformer) Wrap(from io.Reader, to io.Writer) (n int64, err error) {
	// 1. write the random salt to target firstly
	a.wrapOnce.Do(func() {
		if _, err = io.ReadFull(rand.Reader, a.saltBuf); err != nil { // generate the random salt
			return
		}
		if a.wrapAEAD, err = a.callMaker(); err != nil {
			return
		}
		a.wbuf = make([]byte, 2+a.wrapAEAD.Overhead()+AEADPayloadSizeMask+a.wrapAEAD.Overhead())
		a.wnonce = make([]byte, a.wrapAEAD.NonceSize())

		_, err = to.Write(a.saltBuf) // send salt to remote to create the same aead
		LogDebug(context.Background(), "wrap salt %d bytes: %x", len(a.saltBuf), a.saltBuf)
	})
	if err != nil {
		return
	}

	// 2. read the original payload
	buf := a.wbuf
	payloadBuf := buf[2+a.wrapAEAD.Overhead() : 2+a.wrapAEAD.Overhead()+AEADPayloadSizeMask]
	nr, er := from.Read(payloadBuf)

	// 3. wrap the payload size and content, then write to target
	if nr > 0 {
		buf = buf[:2+a.wrapAEAD.Overhead()+nr+a.wrapAEAD.Overhead()]
		payloadBuf = payloadBuf[:nr]
		buf[0], buf[1] = byte(nr>>8), byte(nr) // big-endian payload size
		a.wrapAEAD.Seal(buf[:0], a.wnonce, buf[:2], nil)
		a.incrNonce(a.wnonce)

		a.wrapAEAD.Seal(payloadBuf[:0], a.wnonce, payloadBuf, nil)
		a.incrNonce(a.wnonce)

		LogDebug(context.Background(), "wrap size+payload %d bytes: %x", len(buf), buf)
		if _, err = to.Write(buf); err != nil {
			return
		}
	}
	return int64(nr), er
}

func (a *AEADTransformer) Unwrap(from io.Reader, to io.Writer) (n int64, err error) {
	// 1. read the random salt firstly
	a.unwrapOnce.Do(func() {
		if _, err = io.ReadFull(from, a.saltBuf); err != nil { // read salt from remote
			return
		}
		LogDebug(context.Background(), "unwrap read salt %d bytes: %x", len(a.saltBuf), a.saltBuf)
		if a.unwrapAEAD, err = a.callMaker(); err != nil { // make aead based on remote salt
			return
		}

		a.rbuf = make([]byte, AEADPayloadSizeMask+a.unwrapAEAD.Overhead())
		a.rnonce = make([]byte, a.unwrapAEAD.NonceSize())
	})
	if err != nil {
		return
	}

	// 2. read and unwarp the payload size
	buf := a.rbuf[:2+a.unwrapAEAD.Overhead()]
	if _, err = io.ReadFull(from, buf); err != nil {
		return
	}
	LogDebug(context.Background(), "unwrap size %d bytes: %x", len(buf), buf)
	_, err = a.unwrapAEAD.Open(buf[:0], a.rnonce, buf, nil)
	a.incrNonce(a.rnonce)
	if err != nil {
		return
	}
	size := (int(buf[0])<<8 + int(buf[1])) & AEADPayloadSizeMask

	// 3. read and unwarp payload content, then write to target
	buf = a.rbuf[:size+a.unwrapAEAD.Overhead()]
	if _, err = io.ReadFull(from, buf); err != nil {
		return
	}
	LogDebug(context.Background(), "unwrap payload(size=%d) %d bytes: %x", size, len(buf), buf)
	_, err = a.unwrapAEAD.Open(buf[:0], a.rnonce, buf, nil)
	a.incrNonce(a.rnonce)
	if err != nil {
		return
	}
	if size > 0 {
		nw, ew := to.Write(a.rbuf[:size])
		n = int64(nw)
		if ew != nil {
			err = ew
		}
	}

	return n, err
}
