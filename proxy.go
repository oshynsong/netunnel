package netunnel

const (
	ProxyTypeHttp   = "HTTP"
	ProxyTypeHttps  = "HTTPS"
	ProxyTypeSocks5 = "SOCKS5"
	ProxyTypeSocks4 = "SOCKS4"
)

type ProxySetting struct {
	enabled     uint32
	address     string
	serviceName string
	proxyType   string
}
