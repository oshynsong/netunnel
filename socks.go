package netunnel

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
)

// SocksVersionType defines the version type of the socks protocol.
type SocksVersionType = byte

// Socks avaliable version number enum.
const (
	SocksV4 SocksVersionType = 0x04
	SocksV5 SocksVersionType = 0x05
)

// SocksError represents a socks error.
type SocksError byte

func (err SocksError) Error() string {
	return "socks error: " + strconv.Itoa(int(err))
}

const (
	SocksErrGeneralFailure       = SocksError(1)
	SocksErrConnectionNotAllowed = SocksError(2)
	SocksErrNetworkUnreachable   = SocksError(3)
	SocksErrHostUnreachable      = SocksError(4)
	SocksErrConnectionRefused    = SocksError(5)
	SocksErrTTLExpired           = SocksError(6)
	SocksErrCommandNotSupported  = SocksError(7)
	SocksErrAddressNotSupported  = SocksError(8)
	SocksInfoUDPAssociate        = SocksError(9)
)

// Socks address types as defined by the protocol.
const (
	SocksAtypIPv4       byte = 1
	SocksAtypDomainName byte = 3
	SocksAtypIPv6       byte = 4
)

// SocksAddr represents a SOCKS address with following structure:
// +-------------------------------------+
// |  ATYP   |    DST.ADDR    | DST.PORT |
// +--- 1 ---|--- 4/16/1+N ---|---- 2 ---+
type SocksAddr []byte

// NewSocksAddr creates a SocksAddr from the given fields, which
// performs a reverse procedure of the Parts method.
func NewSocksAddr(atyp byte, addr, port []byte) (SocksAddr, error) {
	var sa []byte
	sa = append(sa, atyp)

	switch atyp {
	case SocksAtypIPv4:
		if len(addr) != net.IPv4len {
			return nil, SocksErrAddressNotSupported
		}
		sa = append(sa, addr...)
	case SocksAtypIPv6:
		if len(addr) != net.IPv6len {
			return nil, SocksErrAddressNotSupported
		}
		sa = append(sa, addr...)
	case SocksAtypDomainName:
		if len(addr) > 0xff {
			return nil, SocksErrAddressNotSupported
		}
		sa = append(sa, byte(len(addr)))
		sa = append(sa, addr...)
	default:
		return nil, SocksErrAddressNotSupported
	}

	sa = append(sa, port...)
	return sa, nil
}

// NewSocksAddrString creates a SocksAddr from the given string, which
// performs a reverse procedure of the String method.
func NewSocksAddrString(s string) (SocksAddr, error) {
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		return nil, err
	}

	var addr SocksAddr
	if ip := net.ParseIP(host); ip != nil {
		if ipv4 := ip.To4(); ipv4 != nil {
			addr = make([]byte, 1+net.IPv4len+2)
			addr[0] = SocksAtypIPv4
			copy(addr[1:], ipv4)
		} else {
			addr = make([]byte, 1+net.IPv6len+2)
			addr[0] = SocksAtypIPv6
			copy(addr[1:], ip)
		}
	} else { // domain name addr
		if len(host) > 255 {
			return nil, SocksErrAddressNotSupported
		}
		addr = make([]byte, 1+1+len(host)+2)
		addr[0], addr[1] = SocksAtypDomainName, byte(len(host))
		copy(addr[2:], host)
	}

	portNum, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return nil, err
	}
	addr[len(addr)-2] = byte((portNum >> 8) & 0xff)
	addr[len(addr)-1] = byte(portNum & 0xff)

	return addr, nil
}

// NewSocksAddrStream creates a SocksAddr from the given stream reader.
func NewSocksAddrStream(r io.Reader) (SocksAddr, error) {
	var addr SocksAddr
	_, max := addr.LengthRange()
	buf := make([]byte, max)

	// 1. read the first ATYP byte
	if _, err := io.ReadFull(r, buf[:1]); err != nil {
		return nil, err
	}

	// 2. read addr and port based on different type
	switch buf[0] {
	case SocksAtypIPv4:
		if _, err := io.ReadFull(r, buf[1:1+net.IPv4len+2]); err != nil {
			return nil, err
		}
		return SocksAddr(buf[:1+net.IPv4len+2]), nil
	case SocksAtypDomainName:
		if _, err := io.ReadFull(r, buf[1:2]); err != nil {
			return nil, err
		}
		domainLen := int(buf[1])
		if _, err := io.ReadFull(r, buf[2:2+domainLen+2]); err != nil {
			return nil, err
		}
		return SocksAddr(buf[:1+1+domainLen+2]), nil
	case SocksAtypIPv6:
		if _, err := io.ReadFull(r, buf[1:1+net.IPv6len+2]); err != nil {
			return nil, err
		}
		return SocksAddr(buf[:1+net.IPv6len+2]), nil
	}

	return nil, SocksErrAddressNotSupported
}

// LengthRange returns the min and max length of a SocksAddr.
func (s SocksAddr) LengthRange() (int, int) {
	min := 1 + net.IPv4len + 2 // for ipv4 with 4 byte addr
	max := 1 + 1 + 255 + 2     // for domain name with 1 byte size + 255 domain
	return min, max
}

// String serializes SOCKS address a to string form.
func (s SocksAddr) String() string {
	atyp, addr, port, err := s.Parts()
	if err != nil {
		return SocksErrAddressNotSupported.Error()
	}

	portNum := strconv.Itoa((int(port[0]) << 8) | int(port[1]))
	if atyp == SocksAtypDomainName {
		return net.JoinHostPort(string(addr), portNum)
	}
	return net.JoinHostPort(net.IP(addr).String(), portNum)
}

// PortNumber returns the integer of the socks addr port number.
func (s SocksAddr) PortNumber() int {
	if len(s) < 2 {
		return -1
	}
	s = s[len(s)-2:]
	return (int(s[0]) << 8) | int(s[1])
}

// Parts returns different part of the socks addr without any modification.
func (s SocksAddr) Parts() (atyp byte, addr, port []byte, err error) {
	min, _ := s.LengthRange()
	if len(s) < min {
		return 0, nil, nil, SocksErrAddressNotSupported
	}

	atyp = s[0]
	s = s[1:]

	switch atyp {
	case SocksAtypIPv4:
		addr = s[:net.IPv4len]
		s = s[net.IPv4len:]
	case SocksAtypDomainName:
		domainLen := int(s[0])
		if len(s) < 1+domainLen {
			return 0, nil, nil, SocksErrAddressNotSupported
		}
		addr = s[1 : 1+domainLen]
		s = s[1+domainLen:]
	case SocksAtypIPv6:
		addr = s[:net.IPv6len]
		s = s[net.IPv6len:]
		if len(s) < net.IPv6len {
			return 0, nil, nil, SocksErrAddressNotSupported
		}
	default:
		return 0, nil, nil, SocksErrAddressNotSupported
	}

	if len(s) < 2 {
		return 0, nil, nil, SocksErrAddressNotSupported
	}
	port = s[:2]
	return
}

// Socks supported request commands as defined by the protocol.
const (
	SocksCmdConnect      = 1
	SocksCmdBind         = 2
	SocksCmdUDPAssociate = 3
)

// Socks supported auth method code as defined by the protocol.
const (
	SocksAuthMethodNone     = 0x00
	SocksAuthMethodGSSAPI   = 0x01
	SocksAuthMethodUserPass = 0x02
	SocksAuthMethodEmpty    = 0xff
)

const (
	socksReqAuthNegotiate byte = iota
	socksReqAuthNegotiateReply
	socksReqAuthPassword
	socksReqAuthPasswordReply
	socksReqCmdConnect
	socksReqCmdConnectReply
	socksReqCmdBind
	socksReqCmdBindReply
	socksReqCmdUDPAssociate
	socksReqCmdUDPAssociateReply
)

const (
	socksReserveByte     = 0x00
	socks4ConnectSuccess = 0x5a
)

// SocksProcessor implements all of the socks protocol details, which
// contains the server-side as well as the client-side process.
type SocksProcessor struct {
	io.ReadWriter
	version        SocksVersionType
	isClient       bool
	allAuthMethods []byte
	selAuthMethod  byte
	authUser       string
	authPass       string
	authStatus     byte

	RequestAddr  SocksAddr // target addr sent from client-side, received by server-side
	ResponseCode byte      // server-side response code sent to client-side
	ResponseAddr SocksAddr // server-side response addr sent to client-side
}

// NewSocksProcessor creates an instance of SocksProcessor based on the given
// read/write stream as well as optional params which should be set properly
// from the view of the processor usage: server-side(default) or client-side.
func NewSocksProcessor(rw io.ReadWriter, opts ...SocksOpt) *SocksProcessor {
	sp := &SocksProcessor{
		ReadWriter:     rw,
		version:        SocksV5,                     // default use socksv5
		isClient:       false,                       // default process socks server-side
		allAuthMethods: []byte{SocksAuthMethodNone}, // default none auth
		selAuthMethod:  SocksAuthMethodNone,         // default none auth
	}
	for _, opt := range opts {
		opt(sp)
	}
	return sp
}

// SocksOpt provides multiple parameters configuration facility.
type SocksOpt = func(*SocksProcessor)

func WithSocksClientSide() SocksOpt {
	return func(sp *SocksProcessor) {
		sp.isClient = true
	}
}

func WithSocksVersion(v SocksVersionType) SocksOpt {
	return func(sp *SocksProcessor) {
		sp.version = v
	}
}

func WithSocksAuthMethod(avaliable []byte, selectAuthMethod byte) SocksOpt {
	return func(sp *SocksProcessor) {
		sp.allAuthMethods = avaliable       // for client-side
		sp.selAuthMethod = selectAuthMethod // for server-side
	}
}

func WithSocksAuthUserPass(user, pass string) SocksOpt {
	return func(sp *SocksProcessor) {
		sp.authUser = user
		sp.authPass = pass
	}
}

func (s *SocksProcessor) buildRequest(reqType byte) []byte {
	var b bytes.Buffer
	b.WriteByte(s.version)

	switch reqType {
	case socksReqAuthNegotiate:
		b.WriteByte(byte(len(s.allAuthMethods)))
		b.Write(s.allAuthMethods)
	case socksReqAuthNegotiateReply:
		b.WriteByte(s.selAuthMethod)
	case socksReqAuthPassword:
		b.WriteByte(byte(len(s.authUser)))
		b.WriteString(s.authUser)
		b.WriteByte(byte(len(s.authPass)))
		b.WriteString(s.authPass)
	case socksReqAuthPasswordReply:
		b.WriteByte(s.authStatus)

	case socksReqCmdConnect:
		b.WriteByte(SocksCmdConnect)
		if s.version == SocksV4 {
			atyp, addr, port, err := s.RequestAddr.Parts()
			if atyp != SocksAtypIPv4 || err != nil {
				return nil
			}
			b.Write(port)
			b.Write(addr)
			b.WriteByte(socksReserveByte)
		} else {
			b.WriteByte(socksReserveByte)
			b.Write(s.RequestAddr)
		}
	case socksReqCmdConnectReply:
		b.WriteByte(s.ResponseCode)
		if s.version == SocksV4 {
			atyp, addr, port, err := s.ResponseAddr.Parts()
			if atyp != SocksAtypIPv4 || err != nil {
				return nil
			}
			b.Write(port)
			b.Write(addr)
		} else {
			b.WriteByte(socksReserveByte)
			b.Write(s.ResponseAddr)
		}
	case socksReqCmdUDPAssociate:
		if s.version != SocksV5 {
			return nil
		}
		b.WriteByte(SocksCmdUDPAssociate)
		b.WriteByte(socksReserveByte)
		b.Write(s.RequestAddr)
	case socksReqCmdUDPAssociateReply:
		if s.version != SocksV5 {
			return nil
		}
		b.WriteByte(s.ResponseCode)
		b.WriteByte(socksReserveByte)
		b.Write(s.ResponseAddr)
	default:
		return nil
	}
	return b.Bytes()
}

// Authenticate performs the whole authentication procedure of both sides.
func (s *SocksProcessor) Authenticate(ctx context.Context) error {
	if s.version != SocksV5 {
		return nil // no need to authenticate
	}
	if s.isClient {
		return s.clientAuthenticate(ctx)
	}

	// 1. recv auth method negotiation request from client.
	var authBuf [1 + 1 + 255 + 1 + 255]byte
	n, err := s.Read(authBuf[:])
	if err != nil {
		return fmt.Errorf("server-side: recv auth request error: %w", err)
	}
	LogDebug(ctx, "SocksProcessor.Authenticate: server-side recv auth request %x", authBuf[:n])
	if authBuf[0] != SocksV5 {
		return fmt.Errorf("server-side: invalid socks version %d", authBuf[0])
	}
	nmethods, found := int(authBuf[1]), false
	for i := 0; i < nmethods; i++ {
		method := authBuf[i+2]
		if method == s.selAuthMethod {
			found = true
			break
		}
	}
	if nmethods > 0 && !found { // auth method not found from client provided methods
		return fmt.Errorf("server-side: need auth method %x but not found from %x", s.selAuthMethod, authBuf[2:2+nmethods])
	}
	LogInfo(ctx, "SocksProcessor.Authenticate: server-side check auth method %v supported", s.selAuthMethod)

	// 2. send the selected auth method to client.
	authReply := s.buildRequest(socksReqAuthNegotiateReply)
	if _, err := s.Write(authReply); err != nil {
		return fmt.Errorf("send auth method reply error: %w", err)
	}
	LogDebug(ctx, "SocksProcessor.Authenticate: server-side send auth method reply %x", authReply)
	switch s.selAuthMethod {
	case SocksAuthMethodNone:
		return nil
	case SocksAuthMethodUserPass:
		n, err := s.Read(authBuf[:])
		if err != nil {
			return fmt.Errorf("server-side: recv user+password error: %w", err)
		}
		LogDebug(ctx, "SocksProcessor.Authenticate: server-side recv user+password %x", authBuf[:n])
		if authBuf[0] != SocksV5 {
			return fmt.Errorf("server-side: invalid socks version %d", authBuf[0])
		}

		up := authBuf[1:n]
		userLen := int(up[0])
		username := string(up[1 : 1+userLen])
		up = up[1+userLen:]
		passLen := int(up[0])
		password := string(up[1 : 1+passLen])
		if username != s.authUser || password != s.authPass {
			s.authStatus = byte(SocksErrGeneralFailure)
		}
		LogInfo(ctx, "SocksProcessor.Authenticate: server-side auth user+password %v", s.authStatus)
		upReply := s.buildRequest(socksReqAuthPasswordReply)
		if _, err = s.Write(upReply); err != nil {
			return fmt.Errorf("server-side: send user+password auth reply error: %w", err)
		}
		LogDebug(ctx, "SocksProcessor.Authenticate: server-side send auth reply %x", upReply)
		return nil
	}
	return SocksErrGeneralFailure
}

func (s *SocksProcessor) clientAuthenticate(ctx context.Context) error {
	// 1. send auth method for negotiation.
	if s.version != SocksV5 {
		return fmt.Errorf("invalid socks version %d", s.version)
	}
	req := s.buildRequest(socksReqAuthNegotiate)
	if _, err := s.Write(req); err != nil {
		return fmt.Errorf("client-side: send auth method error: %w", err)
	}
	LogDebug(ctx, "SocksProcessor.Authenticate: client-side send auth method %x", req)

	// 2. recv server-side selected auth method and perform auth.
	var authReply [2]byte
	if _, err := io.ReadFull(s.ReadWriter, authReply[:]); err != nil {
		return fmt.Errorf("client-side: recv selected auth method error: %w", err)
	}
	LogDebug(ctx, "SocksProcessor.Authenticate: client-side recv auth method reply %x", authReply)
	if authReply[0] != SocksV5 {
		return fmt.Errorf("invalid socks version %d", authReply[0])
	}
	LogInfo(ctx, "SocksProcessor.Authenticate: client-side recv auth method %d", authReply[1])
	switch authReply[1] {
	case SocksAuthMethodNone:
		return nil
	case SocksAuthMethodUserPass:
		up := s.buildRequest(socksReqAuthPassword)
		if _, err := s.Write(up); err != nil {
			return fmt.Errorf("client-side: send user+password error: %w", err)
		}
		LogDebug(ctx, "SocksProcessor.Authenticate: client-side send user+password %x", up)

		if _, err := io.ReadFull(s.ReadWriter, authReply[:]); err != nil {
			return fmt.Errorf("client-side: recv auth status error: %w", err)
		}
		if authReply[1] != socksReserveByte {
			return fmt.Errorf("client-side: user+password authenticate failed")
		}
		LogInfo(ctx, "SocksProcessor.Authenticate: client-side user+password authenticate success")
		return nil
	}
	return SocksErrGeneralFailure
}

// Command performs the cmd socks request procedure of both sides.
func (s *SocksProcessor) Command(ctx context.Context, cmd byte) error {
	if s.isClient {
		return s.clientCommend(ctx, cmd)
	}

	// 1. recv cmd request from client, check fields and parse addr.
	var buf [3]byte
	rb := buf[:]
	if s.version == SocksV4 {
		rb = rb[:2]
	}
	_, err := io.ReadFull(s.ReadWriter, rb)
	if err != nil {
		return fmt.Errorf("server-side: recv cmd request error: %w", err)
	}
	ver, cmd := rb[0], rb[1]
	LogDebug(ctx, "SocksProcessor.Command: server-side recv cmd header ver=%d, cmd=%d", ver, cmd)

	var sa SocksAddr
	switch ver {
	case SocksV4:
		var dstBuf [2 + 4]byte
		if _, err := io.ReadFull(s.ReadWriter, dstBuf[:]); err != nil {
			return fmt.Errorf("server-side: parse socks4 addr error: %w", err)
		}
		LogDebug(ctx, "SocksProcessor.Command: server-side recv socks4 addr %x", dstBuf)
		port, addr := dstBuf[:2], dstBuf[2:]
		sa, err = NewSocksAddr(SocksAtypIPv4, addr, port)
	case SocksV5:
		sa, err = NewSocksAddrStream(s.ReadWriter)
	default:
		return fmt.Errorf("server-side: invalid cmd request version %d", ver)
	}
	if err != nil {
		return fmt.Errorf("server-side: parse addr in cmd request error: %w", err)
	}
	LogInfo(ctx, "SocksProcessor.Command: server-side parse request addr %s", sa)
	s.RequestAddr = sa

	// 2. send cmd response to client based on different command.
	switch cmd {
	case SocksCmdConnect:
		s.ResponseCode = socksReserveByte
		if s.version == SocksV4 {
			s.ResponseCode = socks4ConnectSuccess
		}
		if s.ResponseAddr == nil {
			s.ResponseAddr = s.RequestAddr
		}
		connReply := s.buildRequest(socksReqCmdConnectReply)
		if connReply == nil {
			return fmt.Errorf("server-side: build connect reply request nil")
		}
		LogDebug(ctx, "SocksProcessor.Command: server-side send connect reply %x", connReply)
		if _, err := s.Write(connReply); err != nil {
			return fmt.Errorf("server-side: send connect reply error: %w", err)
		}
		LogInfo(ctx, "SocksProcessor.Command: server-side send connect reply success")
	case SocksCmdUDPAssociate:
		if s.version != SocksV5 {
			return SocksErrConnectionNotAllowed
		}
		listenAddr, err := NewSocksAddrString(s.ReadWriter.(net.Conn).LocalAddr().String())
		if err != nil {
			return err
		}
		s.ResponseCode = socksReserveByte
		s.ResponseAddr = listenAddr
		reply := s.buildRequest(socksReqCmdUDPAssociateReply)
		if reply == nil {
			return fmt.Errorf("server-side: build udp associate reply request nil")
		}
		LogDebug(ctx, "SocksProcessor.Command: server-side send udp associate reply %x", reply)
		if _, err = s.Write(reply); err != nil {
			return fmt.Errorf("server-side: send connect reply error: %w", err)
		}
		LogInfo(ctx, "SocksProcessor.Command: server-side send udp associate reply success")
	default:
		return SocksErrCommandNotSupported
	}
	return nil
}

func (s *SocksProcessor) clientCommend(ctx context.Context, cmd byte) error {
	// 1. send cmd request.
	var reqType byte
	switch cmd {
	case SocksCmdConnect:
		reqType = socksReqCmdConnect
	case SocksCmdBind:
		reqType = socksReqCmdBind
	case SocksCmdUDPAssociate:
		reqType = socksReqCmdUDPAssociate
	default:
		return fmt.Errorf("client-side: command %d not supported", cmd)
	}
	req := s.buildRequest(reqType)
	if req == nil {
		return fmt.Errorf("client-side: build cmd request nil")
	}
	if _, err := s.Write(req); err != nil {
		return fmt.Errorf("client-side: send cmd request error: %w", err)
	}
	LogDebug(ctx, "SocksProcessor.Command: client-side send cmd request %x", req)

	// 2. recv cmd reply and check result.
	_, max := s.ResponseAddr.LengthRange()
	buf := make([]byte, 3+max)
	n, err := s.Read(buf)
	if err != nil {
		return fmt.Errorf("client-side: recv cmd reply error: %w", err)
	}
	LogDebug(ctx, "SocksProcessor.Connect: client-side recv connect reply %x", buf[:n])
	if (buf[0] == SocksV4 && buf[1] == socks4ConnectSuccess) ||
		(buf[0] == SocksV5 && buf[1] == socksReserveByte) {
		return nil
	}
	return SocksErrConnectionRefused
}

// Process implements the overall process for socksv4 and socksv5. The optional cmd
// specifies the client-side command, while will be ignored for server-side.
func (s *SocksProcessor) Process(ctx context.Context, cmd ...byte) (err error) {
	if s.version == SocksV5 { // only v5 need to authenticate
		err = s.Authenticate(ctx)
	}
	if err != nil {
		return err
	}
	var c byte
	if len(cmd) > 0 {
		c = cmd[0]
	}
	if s.version == SocksV4 {
		c = SocksCmdConnect
	}
	return s.Command(ctx, c)
}
