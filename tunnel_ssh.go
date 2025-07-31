package netunnel

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"time"

	"golang.org/x/crypto/ssh"
)

const (
	sshTunnelChannelName = "ssh-tunnel"
)

// SSHTunnel implements a tunnel based on the ssh low-level protocol.
type SSHTunnel struct {
	serverListener net.Listener
	serverAcceptCh chan func() (net.Addr, ssh.Channel, []byte)
	authorizedKey  string
	sshClient      *ssh.Client
	sshUser        string
	password       string
	keyFilePath    string
	keyPassphrase  string
	connTimeout    time.Duration
	done           chan struct{}
}

type SSHTunnelOpt = func(*SSHTunnel)

func WithSSHTunnelUser(user string) SSHTunnelOpt {
	return func(t *SSHTunnel) {
		t.sshUser = user
	}
}

func WithSSHTunnelPassword(password string) SSHTunnelOpt {
	return func(t *SSHTunnel) {
		t.password = password
	}
}

func WithSSHTunnelKey(keyFilePath, keyPassphrase string) SSHTunnelOpt {
	return func(t *SSHTunnel) {
		t.keyFilePath = keyFilePath
		t.keyPassphrase = keyPassphrase
	}
}

func WithSSHTunnelAuthorizedKey(key string) SSHTunnelOpt {
	return func(t *SSHTunnel) {
		t.authorizedKey = key
	}
}

func WithSSHTunnelConnTimeout(timeout time.Duration) SSHTunnelOpt {
	return func(t *SSHTunnel) {
		t.connTimeout = timeout
	}
}

// NewSSHTunnel creates an instance of Tunnel which implemented by SSH at low-level.
func NewSSHTunnel(opts ...SSHTunnelOpt) Tunnel {
	st := &SSHTunnel{done: make(chan struct{})}
	for _, opt := range opts {
		opt(st)
	}
	return st
}

func (s *SSHTunnel) parseKeyFile() (ssh.Signer, error) {
	privateKeyBytes, err := os.ReadFile(s.keyFilePath)
	if err != nil {
		return nil, fmt.Errorf("read private key with %s failed %w", s.keyFilePath, err)
	}
	signer, parseErr := ssh.ParsePrivateKey(privateKeyBytes)
	if parseErr != nil {
		_, ok := parseErr.(*ssh.PassphraseMissingError)
		if !ok {
			return nil, fmt.Errorf("parse private key failed %w", parseErr)
		}
		// Try to parse private key with passphrase.
		signer, parseErr = ssh.ParsePrivateKeyWithPassphrase(privateKeyBytes, []byte(s.keyPassphrase))
		if parseErr != nil {
			return nil, fmt.Errorf("parse private key with passphrase failed %w", parseErr)
		}
	}
	return signer, nil
}

func (s *SSHTunnel) Open(ctx context.Context, network, remoteAddr string) error {
	// Initiate the ssh client config to prepare to create tunnel to remote.
	conf := &ssh.ClientConfig{
		User:            s.sshUser,
		Timeout:         s.connTimeout,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	conf.Ciphers = []string{
		"aes256-gcm@openssh.com", "aes128-gcm@openssh.com",
		"chacha20-poly1305@openssh.com",
		"aes128-ctr", "aes192-ctr", "aes256-ctr",
		"3des-cbc", // add this cipher to keep compatible connecting old version SSH servers
	}
	if len(s.password) != 0 {
		conf.Auth = append(conf.Auth, ssh.Password(s.password))
	} else if len(s.keyFilePath) != 0 {
		signer, err := s.parseKeyFile()
		if err != nil {
			return err
		}
		conf.Auth = append(conf.Auth, ssh.PublicKeys(signer))
	} else {
		return fmt.Errorf("no password or private key given")
	}
	LogInfo(ctx, "SSHTunnel.Open: create client config success")

	// Create the ssh tunnel to the remote server.
	client, err := ssh.Dial(network, remoteAddr, conf)
	if err != nil {
		return fmt.Errorf("dial remote %s failed %w", remoteAddr, err)
	}
	s.sshClient = client
	LogInfo(ctx, "SSHTunnel.Open: create ssh client success")
	return nil
}

func (s *SSHTunnel) Close() error {
	close(s.done)
	if s.sshClient != nil {
		s.sshClient.Close()
	} else if s.serverListener != nil {
		s.serverListener.Close()
	}
	return nil
}

func (s *SSHTunnel) KeepAlive(ctx context.Context, interval time.Duration) {
	if interval < time.Minute {
		interval = time.Minute
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case t := <-ticker.C:
			LogDebug(ctx, "SSHTunnel.KeepAlive: start at %s", t.Format(time.DateTime))
			if s.sshClient == nil {
				return
			}
			_, _, err := s.sshClient.SendRequest("keepalive@openssh.com", true, nil)
			if err != nil {
				LogError(ctx, "SSHTunnel.KeepAlive: error %v", err)
			} else {
				LogInfo(ctx, "SSHTunnel.KeepAlive: success at %s", t.Format(time.DateTime))
			}
		case <-ctx.Done():
			LogInfo(ctx, "SSHTunnel.KeepAlive: cancel exit")
			return
		case <-s.done:
			LogInfo(ctx, "SSHTunnel.KeepAlive: closed exit")
			return
		}
	}
}

func (s *SSHTunnel) Dial(ctx context.Context, network, targetAddr string) (*TunnelConn, error) {
	sa, err := NewSocksAddrString(targetAddr)
	if err != nil {
		return nil, err
	}
	channel, reqs, err := s.sshClient.OpenChannel(sshTunnelChannelName, []byte(sa))
	if err != nil {
		return nil, err
	}
	go ssh.DiscardRequests(reqs)
	channelConn := &sshChannelConn{
		Channel:    channel,
		localAddr:  s.sshClient.LocalAddr(),
		remoteAddr: s.sshClient.RemoteAddr(),
	}
	tc := NewTunnelConn(ctx, channelConn, nil)
	LogInfo(ctx, "SSHTunnel.Dail: dial to %s with id %s", targetAddr, tc.ID())
	return tc, nil
}

func (s *SSHTunnel) Listen(ctx context.Context, network, serverAddr string) error {
	config := &ssh.ServerConfig{
		NoClientAuth:  true,
		ServerVersion: "SSH-2.0-OWN-SERVER",
	}
	signer, err := s.parseKeyFile()
	if err != nil {
		return err
	}
	config.AddHostKey(signer)
	if len(s.password) != 0 {
		config.PasswordCallback = func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			if c.User() == s.sshUser && string(pass) == s.password {
				return &ssh.Permissions{}, nil
			}
			return nil, fmt.Errorf("password rejected for %q", c.User())
		}
	}
	if len(s.authorizedKey) != 0 {
		pubKeyBytes, err := os.ReadFile(s.authorizedKey)
		if err != nil {
			return fmt.Errorf("read authorized key from %s failed: %v", s.authorizedKey, err)
		}
		pubKey, _, _, _, err := ssh.ParseAuthorizedKey(pubKeyBytes)
		if err != nil {
			return fmt.Errorf("parse authorized key from %s failed: %v", s.authorizedKey, err)
		}
		config.PublicKeyCallback = func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if bytes.Equal(key.Marshal(), pubKey.Marshal()) {
				return &ssh.Permissions{}, nil
			}
			return nil, fmt.Errorf("key not match")
		}
	}
	if config.PasswordCallback == nil && config.PublicKeyCallback == nil {
		return fmt.Errorf("no ssh server auth method: password and public key empty")
	}
	LogInfo(ctx, "SSHTunnel.Listen: create ssh server config success")

	listener, err := net.Listen(network, serverAddr)
	if err != nil {
		return err
	}
	s.serverListener = listener
	s.serverAcceptCh = make(chan func() (net.Addr, ssh.Channel, []byte))
	go func() {
		defer func() {
			if r := recover(); r != nil {
				LogError(ctx, "ssh connection accepter panic: %v", r)
				return
			}
			LogInfo(ctx, "ssh connection accepter exit")
		}()
		for {
			conn, err := s.serverListener.Accept()
			if err != nil {
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					time.Sleep(time.Second)
					continue
				}
				LogError(ctx, "ssh accept connection error: %v", err)
				return
			}
			select {
			case <-s.done:
				return
			default:
			}
			sshConn, chans, reqs, err := ssh.NewServerConn(conn, config)
			if err != nil {
				LogError(ctx, "ssh handshake from %s error %v", conn.RemoteAddr(), err)
				continue
			}
			fromAddr := sshConn.RemoteAddr()
			LogInfo(ctx, "ssh conn from %s: accepted with user %s", fromAddr, sshConn.User())
			go ssh.DiscardRequests(reqs)
			go func() {
				defer LogInfo(ctx, "ssh conn from %s: channel receiver exit", fromAddr)
				for ch := range chans {
					if ch.ChannelType() != sshTunnelChannelName {
						ch.Reject(ssh.Prohibited, "channel type not supported")
						continue
					}
					channel, chanReqs, chErr := ch.Accept()
					if chErr != nil {
						LogError(ctx, "ssh conn from %s: accept channel error %v", fromAddr, chErr)
						continue
					}
					go ssh.DiscardRequests(chanReqs)
					extra := ch.ExtraData()
					s.serverAcceptCh <- func() (net.Addr, ssh.Channel, []byte) { return fromAddr, channel, extra }
				}
			}()
		}
	}()
	return nil
}

func (s *SSHTunnel) Accept(ctx context.Context) (*TunnelConn, string, error) {
	accepted := <-s.serverAcceptCh
	fromAddr, channel, extra := accepted()
	channelConn := &sshChannelConn{
		Channel:    channel,
		localAddr:  s.serverListener.Addr(),
		remoteAddr: fromAddr,
	}
	sa, err := NewSocksAddrStream(bytes.NewReader(extra))
	if err != nil {
		return nil, "", err
	}
	tc := NewTunnelConn(ctx, channelConn, nil)
	return tc, sa.String(), nil
}

// sshChannelConn is an adapter to make a ssh.Channel as a net.Conn.
type sshChannelConn struct {
	ssh.Channel
	localAddr  net.Addr
	remoteAddr net.Addr
}

func (s *sshChannelConn) LocalAddr() net.Addr                { return s.localAddr }
func (s *sshChannelConn) RemoteAddr() net.Addr               { return s.remoteAddr }
func (s *sshChannelConn) SetDeadline(t time.Time) error      { return nil }
func (s *sshChannelConn) SetReadDeadline(t time.Time) error  { return nil }
func (s *sshChannelConn) SetWriteDeadline(t time.Time) error { return nil }
