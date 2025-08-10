package netunnel

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

const (
	HttpProxyDefaultVersion   = "HTTP/1.1"
	HttpProxyConnectedMessage = "Connection Established"
	HttpProxyAuthHeaderKey    = "Proxy-Authorization"
	HttpProxyAuthBasicPrefix  = "Basic "
)

// Supported two http proxy authentication method.
const (
	HttpProxyAuthNone = iota
	HttpProxyAuthBasic
)

// HttpProcessor implements all of the http proxy protocol details, which
// contains the server-side as well as the client-side process.
type HttpProcessor struct {
	io.ReadWriter
	isClient   bool
	authMethod byte
	version    string
	basicUser  string
	basicPass  string
	buf        []byte

	RequestAddr  string // target addr sent from client-side, received by server-side
	ResponseCode byte   // server-side response code to client-side
}

// NewHttpProcessor creates an instance of HttpProcessor.
func NewHttpProcessor(rw io.ReadWriter, opts ...HttpOpt) *HttpProcessor {
	obj := &HttpProcessor{
		ReadWriter: rw,
		authMethod: HttpProxyAuthNone,
		version:    HttpProxyDefaultVersion,
		buf:        make([]byte, 4096),
	}
	for _, opt := range opts {
		opt(obj)
	}
	return obj
}

// HttpOpt provides multiple parameters configuration facility.
type HttpOpt = func(*HttpProcessor)

func WithHttpClientSide() HttpOpt {
	return func(hp *HttpProcessor) {
		hp.isClient = true
	}
}

func WithHttpVersion(v string) HttpOpt {
	return func(hp *HttpProcessor) {
		hp.version = v
	}
}

func WithHttpAuthUserPass(user, pass string) HttpOpt {
	return func(hp *HttpProcessor) {
		hp.authMethod = HttpProxyAuthBasic
		hp.basicUser = user
		hp.basicPass = pass
	}
}

func (h *HttpProcessor) Process(ctx context.Context) (err error) {
	if h.isClient {
		return h.clientProcess(ctx)
	}

	defer func() {
		statusCode, statusText := http.StatusOK, HttpProxyConnectedMessage
		if err != nil {
			LogError(ctx, "HttpProcessor: process failed: %v", err)
			statusCode = http.StatusProxyAuthRequired
			statusText = http.StatusText(http.StatusProxyAuthRequired)
		}

		ret := fmt.Sprintf("%s %d %s\r\n\r\n", h.version, statusCode, statusText)
		LogInfo(ctx, "HttpProcessor: server-side send response\n%s", ret)
		if _, we := io.WriteString(h.ReadWriter, ret); we != nil {
			err = fmt.Errorf("server-side process got err: %v, and send response failed: %w", err, we)
		}
	}()

	var n int
	n, err = h.Read(h.buf)
	if err != nil {
		return fmt.Errorf("server-side read raw request error %w", err)
	}
	LogDebug(ctx, "server-side got request:\n%s", string(h.buf[:n]))
	reader := bufio.NewReader(bytes.NewReader(h.buf[:n]))
	req, err := http.ReadRequest(reader)
	if err != nil {
		return fmt.Errorf("server-side parse request error %w", err)
	}
	if req.Method != http.MethodConnect {
		return fmt.Errorf("server-side got invalid proxy request method: %s", req.Method)
	}
	if h.authMethod == HttpProxyAuthBasic {
		proxyAuth := req.Header.Get(HttpProxyAuthHeaderKey)
		user, pass, ok := h.decodeProxyBasicAuth(proxyAuth)
		if !ok {
			return fmt.Errorf("server-side no basic auth given")
		}
		if h.basicUser != user || h.basicPass != pass {
			return fmt.Errorf("server-side basic auth failed")
		}
	}
	h.RequestAddr = req.RequestURI
	LogInfo(ctx, "HttpProcessor: server-side parse request addr %s", h.RequestAddr)
	return nil
}

func (h *HttpProcessor) clientProcess(ctx context.Context) (err error) {
	req := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Host: h.RequestAddr},
		Host:   h.RequestAddr,
		Proto:  h.version,
		Header: make(http.Header),
	}
	req.Header.Add("Proxy-Connection", "Keep-Alive")
	req.Header.Add("Content-Length", "0")
	if h.authMethod == HttpProxyAuthBasic {
		req.Header.Add(HttpProxyAuthHeaderKey, h.encodeProxyBasicAuth())
	}

	buf := bytes.NewBuffer(h.buf[:0])
	if err := req.WriteProxy(buf); err != nil {
		return fmt.Errorf("client-side build request error %w", err)
	}
	LogInfo(ctx, "HttpProcessor: client-side send request with length=%d\n%s", buf.Len(), buf.String())
	if _, err = h.Write(buf.Bytes()); err != nil {
		return fmt.Errorf("client-side send request error %w", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(h.ReadWriter), req)
	if err != nil {
		return fmt.Errorf("client-side read response error %w", err)
	}
	h.ResponseCode = byte(resp.StatusCode)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("client-side process failed with %v", resp.StatusCode)
	}
	LogInfo(ctx, "HttpProcessor: client-side process success(%v/%v) with addr=%s",
		resp.StatusCode, http.StatusText(resp.StatusCode), h.RequestAddr)
	return nil
}

func (h *HttpProcessor) encodeProxyBasicAuth() string {
	auth := h.basicUser + ":" + h.basicPass
	val := base64.StdEncoding.EncodeToString([]byte(auth))
	return HttpProxyAuthBasicPrefix + val
}

func (h *HttpProcessor) decodeProxyBasicAuth(auth string) (username, password string, ok bool) {
	prefix := HttpProxyAuthBasicPrefix
	if len(auth) < len(prefix) || !strings.EqualFold(auth[:len(prefix)], prefix) {
		return "", "", false
	}
	c, err := base64.StdEncoding.DecodeString(auth[len(prefix):])
	if err != nil {
		return "", "", false
	}
	cs := string(c)
	username, password, ok = strings.Cut(cs, ":")
	if !ok {
		return "", "", false
	}
	return username, password, true
}
