package authproxy

import (
	"crypto/tls"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/pkg/errors"
)

// tcpReverseProxy is a layer 4 reverse proxy.
type tcpReverseProxy struct {
	backend *url.URL

	dial func(network, addr string) (net.Conn, error)

	logger *log.Logger
}

// tcpProxyConfig holds configuration options for the tcp reverse proxy.
type tcpProxyConfig struct {
	// Backend is the backend URL of the service. It must use a ws or wss scheme.
	Backend string
	// TLSConfig controls the TLS client configuration for connecting to the backend.
	TLSConfig *tls.Config
	// Logger is used by the proxy to log errors connecting to the backend.
	//
	// If not provided, logs will be printed through the log package's default logger.
	Logger *log.Logger
}

// newTCPReverseProxy creates a reverse proxy from the given configuration.
func newTCPReverseProxy(c *tcpProxyConfig) (*tcpReverseProxy, error) {
	u, err := url.Parse(c.Backend)
	if err != nil {
		return nil, errors.Wrap(err, "parsing backend URL")
	}

	host, port, splitErr := net.SplitHostPort(u.Host)

	p := &tcpReverseProxy{
		backend: u,
		logger:  c.Logger,
	}

	dialer := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
		DualStack: true,
	}

	switch u.Scheme {
	case "http":
		if splitErr != nil {
			port = "80"
			host = u.Host
		}
		p.dial = dialer.Dial
	case "https":
		if splitErr != nil {
			port = "443"
			host = u.Host
		}
		tlsConfig := c.TLSConfig
		if tlsConfig == nil {
			tlsConfig = &tls.Config{}
		}
		if tlsConfig.ServerName == "" {
			tlsConfig.ServerName = host
		}
		p.dial = func(network, addr string) (net.Conn, error) {
			return tls.DialWithDialer(dialer, network, addr, tlsConfig)
		}
	default:
		return nil, errors.Errorf("backend URL requires scheme http:// or https://, got %s", u.Scheme)
	}
	p.backend.Host = net.JoinHostPort(host, port)

	return p, nil
}

func (p *tcpReverseProxy) logf(format string, v ...interface{}) {
	if p.logger != nil {
		p.logger.Printf(format, v...)
		return
	}
	log.Printf(format, v...)
}

func (p *tcpReverseProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !isUpgradeRequest(r) {
		p.logf("wsutil: attempted to proxy a non-upgrade request")
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	r.URL.Host = p.backend.Host
	r.URL.Scheme = p.backend.Scheme
	r.URL.Path = path.Join(p.backend.Path, r.URL.Path)

	connBackend, err := p.dial("tcp", p.backend.Host)
	if err != nil {
		p.logf("dial backend: %v", err)
		http.Error(w, "Bad gateway", http.StatusBadGateway)
		return
	}
	defer connBackend.Close()

	h, ok := w.(http.Hijacker)
	if !ok {
		p.logf("response writer isn't a hijacker for upgrade connections")
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	connFrontend, brw, err := h.Hijack()
	if err != nil {
		p.logf("response writer can't be hijacked for upgrade connections: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	defer connFrontend.Close()

	if brw.Reader.Buffered() > 0 {
		p.logf("client sent data before handshake is complete")
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	if err := r.WriteProxy(connBackend); err != nil {
		p.logf("write request to backend: %v", err)
		http.Error(w, "Bad gateway", http.StatusBadGateway)
		return
	}

	done := make(chan error, 2)
	cp := func(dest, src net.Conn) {
		_, err := io.Copy(dest, src)
		done <- err
	}

	go cp(connFrontend, connBackend)
	go cp(connBackend, connFrontend)
	<-done
	// Close both connections
	connBackend.Close()
	connFrontend.Close()
	<-done
}

// isUpgradeRequest determines if an HTTP request is attempting to upgrade to
// a WebSocket connection.
func isUpgradeRequest(r *http.Request) bool {
	contains := func(key, val string) bool {
		vv := strings.Split(r.Header.Get(key), ",")
		for _, v := range vv {
			if val == strings.ToLower(strings.TrimSpace(v)) {
				return true
			}
		}
		return false
	}
	if !contains("Connection", "upgrade") {
		return false
	}
	if r.Header.Get("Upgrade") == "" {
		return false
	}
	return true
}
