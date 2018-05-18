package authproxy

import (
	"crypto/tls"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"path"
	"strings"

	"github.com/gorilla/websocket"
	"github.com/pkg/errors"
)

// wsReverseProxy is a layer 7 websocket reverse proxy.
//
// The proxy doesn't support other protocols and will reject HTTP requests not
// explicitly requesting a websocket upgrade. Use the isWSRequest to determine
// if a request can be served by this handler.
type wsReverseProxy struct {
	backend *url.URL

	upgrader *websocket.Upgrader
	dialer   *websocket.Dialer

	logger *log.Logger
}

// wsProxyConfig holds configuration options for the websocket reverse proxy.
type wsProxyConfig struct {
	// Backend is the backend URL of the service. It must use a ws or wss scheme.
	Backend string
	// TLSConfig controls the TLS client configuration for connecting to the backend.
	TLSConfig *tls.Config
	// Logger is used by the proxy to log errors connecting to the backend.
	//
	// If not provided, logs will be printed through the log package's default logger.
	Logger *log.Logger
}

// newWSReverseProxy creates a reverse proxy from the given configuration.
func newWSReverseProxy(c *wsProxyConfig) (*wsReverseProxy, error) {
	u, err := url.Parse(c.Backend)
	if err != nil {
		return nil, errors.Wrap(err, "parsing backend URL")
	}
	if u.Scheme != "ws" && u.Scheme != "wss" {
		return nil, errors.Errorf("backend URL requires scheme ws:// or wss://, got %s", u.Scheme)
	}
	return &wsReverseProxy{
		upgrader: &websocket.Upgrader{
			ReadBufferSize:  1024,
			WriteBufferSize: 1024,
		},
		backend: u,
		dialer: &websocket.Dialer{
			TLSClientConfig: c.TLSConfig,
		},
		logger: c.Logger,
	}, nil
}

func (p *wsReverseProxy) logf(format string, v ...interface{}) {
	if p.logger != nil {
		p.logger.Printf(format, v...)
		return
	}
	log.Printf(format, v...)
}

// Headers which the websocket dialer adds itself and will complain about
// existing beforehand.
//
// https://github.com/gorilla/websocket/blob/v1.2.0/client.go#L233
var headerBlacklist = map[string]bool{
	"Upgrade":                  true,
	"Connection":               true,
	"Sec-Websocket-Key":        true,
	"Sec-Websocket-Version":    true,
	"Sec-Websocket-Extensions": true,
}

func (p *wsReverseProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !isWSRequest(r) {
		p.logf("wsutil: attempted to proxy a non-websocket request")
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	headerCp := http.Header{}
	for k, vv := range r.Header {
		if !headerBlacklist[k] {
			headerCp[k] = vv
		}
	}

	var backend url.URL
	backend = *p.backend
	backend.Path = path.Join(backend.Path, r.URL.Path)
	backend.RawQuery = r.URL.RawQuery

	conn1, resp, err := p.dialer.Dial(backend.String(), headerCp)
	if err != nil {
		if err == websocket.ErrBadHandshake {
			// ErrBadHandshake indicates that the response holds an error
			// from the backend service.
			//
			// TODO: Include headers?
			body, _ := ioutil.ReadAll(resp.Body)
			if len(body) > 0 {
				err = errors.Errorf("%v %s %s", err, resp.Status, body)
			} else {
				err = errors.Errorf("%v %s", err, resp.Status)
			}
			w.WriteHeader(resp.StatusCode)
			io.Copy(w, resp.Body)
		}
		p.logf("wsutil: dial backend: %v", err)
		http.Error(w, "Bad gateway", http.StatusBadGateway)
		return
	}

	conn2, err := p.upgrader.Upgrade(w, r, nil)
	if err != nil {
		conn1.Close()
		p.logf("wsutil: failed to upgrade request: %v", err)
		return
	}

	done := make(chan struct{}, 2)
	cp := func(dest, src *websocket.Conn) {
		defer func() { done <- struct{}{} }()
		for {
			typ, p, err := src.ReadMessage()
			if err != nil {
				return
			}
			if err := dest.WriteMessage(typ, p); err != nil {
				return
			}
		}
	}

	go cp(conn1, conn2)
	go cp(conn2, conn1)
	<-done
	// Close both connections
	conn1.Close()
	conn2.Close()
	<-done
}

// toWSURL replaces the scheme of a HTTP or HTTPS to its equivalent
// WS or WSS protocol.
//
//		print(wsutil.toWSURL("https://example.com")) // "wss://example.com"
//
func toWSURL(httpURL string) string {
	if !strings.HasPrefix(httpURL, "http") {
		return httpURL
	}
	return "ws" + httpURL[len("http"):]
}

// isWSRequest determines if an HTTP request is attempting to upgrade to
// a WebSocket connection.
func isWSRequest(r *http.Request) bool {
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
	if !contains("Upgrade", "websocket") {
		return false
	}
	return true
}
