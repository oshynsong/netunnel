package netunnel

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"
)

var (
	ErrUnknown                = errors.New("netunnel: unknown error")
	ErrNotImplemented         = errors.New("netunnel: not implemented")
	ErrInvalidTransformerName = errors.New("netunnel: invalid transformer name")
	ErrKeySizeError           = errors.New("netunnel: key size error")
	ErrSaltCorrupt            = errors.New("netunnel: salt corrupt")
	ErrInvalidEndpointType    = errors.New("netunnel: invalid endpoint type")
	ErrInvalidNetwork         = errors.New("netunnel: invalid network")
	ErrEndpointClosed         = errors.New("netunnel: endpoint closed")
)

// ExitNotify registers the exit signal handler to the kernel to exit gracefully.
func ExitNotify() <-chan os.Signal {
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)
	return signalChan
}

// Relay copies the data stream between given two connections.
func Relay(ctx context.Context, left, right net.Conn, done <-chan struct{}) error {
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

	var err error
	select {
	case err = <-errCh:
	case <-done:
		err = os.ErrClosed
	}
	LogInfo(ctx, "relay finished: %s <=> {%s | %s} <=> %s", left.RemoteAddr(), left.LocalAddr(), right.LocalAddr(), right.RemoteAddr())
	if err != nil && !errors.Is(err, os.ErrDeadlineExceeded) && !errors.Is(err, os.ErrClosed) {
		return err
	}
	return nil
}

// BuildSSHClientConfig builds the client config to connect remote ssh server.
func BuildSSHClientConfig(user, password, keyFile string, connTimeout time.Duration, keyPass ...string) (*ssh.ClientConfig, error) {
	if len(user) == 0 {
		return nil, fmt.Errorf("no ssh user given")
	}
	conf := &ssh.ClientConfig{
		User:            user,
		Timeout:         connTimeout,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	conf.Ciphers = []string{
		"aes256-gcm@openssh.com", "aes128-gcm@openssh.com",
		"chacha20-poly1305@openssh.com",
		"aes128-ctr", "aes192-ctr", "aes256-ctr",
		"3des-cbc", // add this cipher to keep compatible connecting old version SSH servers
	}
	if len(password) != 0 {
		conf.Auth = append(conf.Auth, ssh.Password(password))
	} else if len(keyFile) != 0 {
		signer, err := ParseSSHPrivateKey(keyFile, keyPass...)
		if err != nil {
			return nil, err
		}
		conf.Auth = append(conf.Auth, ssh.PublicKeys(signer))
	} else {
		return nil, fmt.Errorf("no password or private key given")
	}
	return conf, nil
}

// ParseSSHPrivateKey parses the ssh private key from the given file path and
// the optional passphrase if parse failed without passphrase.
func ParseSSHPrivateKey(keyFile string, keyPassphrase ...string) (ssh.Signer, error) {
	privateKeyBytes, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, fmt.Errorf("read private key from file(%s) failed: %w", keyFile, err)
	}

	signer, parseErr := ssh.ParsePrivateKey(privateKeyBytes)
	if parseErr != nil {
		_, ok := parseErr.(*ssh.PassphraseMissingError)
		if !ok {
			return nil, fmt.Errorf("parse private key failed %w", parseErr)
		}

		// Try to parse private key with passphrase.
		if len(keyPassphrase) == 0 {
			return nil, fmt.Errorf("parse private encrypted key without passphrase")
		}
		keyPass := keyPassphrase[0]
		signer, parseErr = ssh.ParsePrivateKeyWithPassphrase(privateKeyBytes, []byte(keyPass))
		if parseErr != nil {
			return nil, fmt.Errorf("parse private key with passphrase failed %w", parseErr)
		}
	}
	return signer, nil
}

// Daemonize makes a new process with given params and create a pid and log file.
func Daemonize(appName string, argv []string, pidPath string) (err error) {
	var execPath string
	execPath, err = os.Executable()
	if err != nil {
		return fmt.Errorf("find current executable path failed: %w", err)
	}
	execPath, err = filepath.EvalSymlinks(execPath)
	if err != nil {
		return fmt.Errorf("eval synlinks %s failed: %w", execPath, err)
	}
	dir := filepath.Dir(execPath)
	name := filepath.Join(dir, appName)
	if info, statErr := os.Stat(name); statErr != nil || info.IsDir() {
		execPath, err = exec.LookPath(appName)
		if err != nil {
			return fmt.Errorf("can not found %s from system: %w", appName, err)
		}
		abs, _ := filepath.Abs(execPath)
		dir, name = filepath.Dir(abs), abs
		LogInfo(context.Background(), "found %s from system with full path=%v", appName, name)
	} else {
		LogInfo(context.Background(), "found %s from current executable path=%v", appName, name)
	}

	var pidFile, logFile *os.File
	pidFilePath := filepath.Join(pidPath, appName+".pid")
	pidFile, err = os.OpenFile(pidFilePath, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("open pid file %s failed: %w", pidFilePath, err)
	}
	logFilePath := filepath.Join(filepath.Dir(pidFilePath), appName+".log")
	logFile, err = os.OpenFile(logFilePath, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0644)
	if err != nil {
		_ = pidFile.Close()
		return fmt.Errorf("open log file %s failed: %w", logFilePath, err)
	}

	cmd := exec.Command(name, argv...)
	cmd.Dir = dir
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, logFile, logFile
	if err = cmd.Start(); err != nil {
		_ = pidFile.Close()
		_ = logFile.Close()
		return fmt.Errorf("create daemon process %v failed: %v", appName, err)
	}

	pid := cmd.Process.Pid
	if _, err = pidFile.WriteString(strconv.Itoa(pid)); err != nil {
		_ = pidFile.Close()
		_ = logFile.Close()
		return fmt.Errorf("save daemon pid %v failed: %w", pid, err)
	}
	_ = pidFile.Close()
	LogInfo(context.Background(), "daemonize %s success with pid=%v", appName, pid)
	return nil
}

// MemAddr is a custom network addr used to build the memory conn.
type MemAddr struct {
	network string
	addr    string
}

// NewMemAddr creates a memory address instance.
func NewMemAddr(val string) *MemAddr {
	return &MemAddr{
		network: "mem",
		addr:    val,
	}
}

func (m *MemAddr) Network() string { return m.network }
func (m *MemAddr) String() string  { return m.addr }

// unidirectionalMemConn builds a blocking memory connection with timeout support. It Only
// provides an one-way direction connection. Use both to support bidirectional connection
type unidirectionalMemConn struct {
	dataCh     chan []byte
	lastUnread []byte
	rtimeout   time.Duration
	wtimeout   time.Duration
	rtimer     *time.Timer
	wtimer     *time.Timer
	closed     chan struct{}
}

func (m *unidirectionalMemConn) Read(buf []byte) (n int, e error) {
	if len(m.lastUnread) > 0 {
		nr := copy(buf, m.lastUnread)
		m.lastUnread = m.lastUnread[nr:]
		if len(m.lastUnread) == 0 {
			m.lastUnread = nil
		}
		return nr, nil
	}

	var got []byte
	if m.rtimer == nil {
		select {
		case got = <-m.dataCh:
		case <-m.closed:
			e = os.ErrClosed
		}
	} else {
		select {
		case got = <-m.dataCh:
		case <-m.rtimer.C:
			e = os.ErrDeadlineExceeded
			m.rtimer = time.NewTimer(m.rtimeout)
		case <-m.closed:
			e = os.ErrClosed
		}
	}
	if e != nil {
		return
	}
	n = copy(buf, got)
	if n < len(got) {
		m.lastUnread = append(m.lastUnread, got[n:]...)
	}
	return n, nil
}

func (m *unidirectionalMemConn) Write(buf []byte) (n int, e error) {
	if m.wtimer == nil {
		select {
		case m.dataCh <- buf:
			n = len(buf)
		case <-m.closed:
			e = os.ErrClosed
		}
	} else {
		select {
		case m.dataCh <- buf:
			n = len(buf)
		case <-m.wtimer.C:
			e = os.ErrDeadlineExceeded
			m.wtimer = time.NewTimer(m.wtimeout)
		case <-m.closed:
			e = os.ErrClosed
		}
	}
	return
}

func (m *unidirectionalMemConn) Close() error {
	if m.closed != nil {
		close(m.closed)
		m.closed = nil
	}
	return nil
}

func (m *unidirectionalMemConn) SetDeadline(t time.Time) error {
	duration := time.Until(t)
	m.rtimeout, m.wtimeout = duration, duration
	m.rtimer = time.NewTimer(duration)
	m.wtimer = time.NewTimer(duration)
	return nil
}

func (m *unidirectionalMemConn) SetReadDeadline(t time.Time) error {
	m.rtimeout = time.Until(t)
	m.rtimer = time.NewTimer(m.rtimeout)
	return nil
}

func (m *unidirectionalMemConn) SetWriteDeadline(t time.Time) error {
	m.wtimeout = time.Until(t)
	m.wtimer = time.NewTimer(m.wtimeout)
	return nil
}

// MemConn provides a bidirectional memory connection functionalitiy.
type MemConn struct {
	addr   net.Addr
	reader *unidirectionalMemConn
	writer *unidirectionalMemConn
}

// NewMemConn creates an instance of MemConn with given address.
func NewMemConn(addr string) (client, server net.Conn) {
	reader := &unidirectionalMemConn{
		dataCh: make(chan []byte),
		closed: make(chan struct{}),
	}
	writer := &unidirectionalMemConn{
		dataCh: make(chan []byte),
		closed: make(chan struct{}),
	}
	ma := NewMemAddr(addr)
	client = &MemConn{addr: ma, reader: reader, writer: writer}
	server = &MemConn{addr: ma, reader: writer, writer: reader}
	return client, server
}

func (m *MemConn) LocalAddr() net.Addr           { return m.addr }
func (m *MemConn) RemoteAddr() net.Addr          { return m.addr }
func (m *MemConn) Read(buf []byte) (int, error)  { return m.reader.Read(buf) }
func (m *MemConn) Write(buf []byte) (int, error) { return m.writer.Write(buf) }

func (m *MemConn) Close() error {
	_ = m.reader.Close()
	_ = m.writer.Close()
	return nil
}

func (m *MemConn) SetDeadline(t time.Time) error {
	_ = m.reader.SetDeadline(t)
	_ = m.writer.SetDeadline(t)
	return nil
}

func (m *MemConn) SetReadDeadline(t time.Time) error {
	return m.reader.SetReadDeadline(t)
}

func (m *MemConn) SetWriteDeadline(t time.Time) error {
	return m.writer.SetWriteDeadline(t)
}
