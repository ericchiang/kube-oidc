package authproxy

import (
	"bytes"
	"crypto/x509"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/websocket"
)

type testConfig struct {
	modifyRequest func(url string, h http.Header) (string, http.Header)
	checkRequest  func(r *http.Request)

	// If connections should use TLS
	useTLS bool
}

func TestWSReverseProxy(t *testing.T) {
	testWSReverseProxy(t, &testConfig{})
}

func TestWSReverseProxyTLSConfig(t *testing.T) {
	testWSReverseProxy(t, &testConfig{
		useTLS: true,
	})
}

func TestWSReverseProxyHeaders(t *testing.T) {
	testWSReverseProxy(t, &testConfig{
		modifyRequest: func(url string, h http.Header) (string, http.Header) {
			h.Set("foo", "bar")
			return url, h
		},
		checkRequest: func(r *http.Request) {
			if r.Header.Get("foo") != "bar" {
				t.Errorf("proxy didn't maintain headers")
			}
		},
	})
}

func TestWSReverseProxyURLPath(t *testing.T) {
	testWSReverseProxy(t, &testConfig{
		modifyRequest: func(url string, h http.Header) (string, http.Header) {
			url += "/foo?hello=world"
			return url, h
		},
		checkRequest: func(r *http.Request) {
			if r.URL.Path != "/foo" {
				t.Errorf("expected path /foo, got %s", r.URL.Path)
			}
			if r.URL.Query().Get("hello") != "world" {
				t.Errorf("expected query hello=world, got %s", r.URL.Query())
			}
		},
	})
}

func TestWSReverseProxySubprotocols(t *testing.T) {
	const (
		// NOTE: For some reason "Sec-WebSocket-Protocol" fails here. Unsure which is
		// the correct value to send.
		//
		// TODO: See what browsers send.
		subProtocol = "Sec-Websocket-Protocol"
		bearerAuth  = "base64url.bearer.authorization.k8s.io.bXl0b2tlb"
		binary      = "base64.binary.k8s.io"
	)

	contains := func(haystack []string, needle string) bool {
		for _, ele := range haystack {
			if ele == needle {
				return true
			}
		}
		return false
	}

	testWSReverseProxy(t, &testConfig{
		modifyRequest: func(url string, h http.Header) (string, http.Header) {
			h.Add(subProtocol, bearerAuth)
			h.Add(subProtocol, binary)
			return url, h
		},
		checkRequest: func(r *http.Request) {
			got := r.Header[subProtocol]
			if len(got) != 2 {
				t.Errorf("expected 2 subprotocol header values got %d", len(got))
			}
			if !contains(got, bearerAuth) {
				t.Errorf("subprotocols did not contain bearer token header: %v", got)
			}
			if !contains(got, binary) {
				t.Errorf("subprotocols did not contain binary header: %v", got)
			}
		},
	})
}

func testWSReverseProxy(t *testing.T, config *testConfig) {
	newServer := httptest.NewServer
	if config.useTLS {
		newServer = func(h http.Handler) *httptest.Server {
			s := httptest.NewTLSServer(h)
			s.TLS.RootCAs = x509.NewCertPool()
			s.TLS.RootCAs.AddCert(s.Certificate())
			return s
		}
	}

	var upgrader websocket.Upgrader
	f := func(w http.ResponseWriter, r *http.Request) {
		if config.checkRequest != nil {
			config.checkRequest(r)
		}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Errorf("handling websocket: %v", err)
			return
		}
		defer conn.Close()

		_, b, err := conn.ReadMessage()
		if err != nil {
			t.Errorf("reading from websocket: %v", err)
			return
		}
		if !bytes.Equal(b, []byte("hello")) {
			t.Errorf("unexpected data from websocket: %s", b)
			return
		}
		if err := conn.WriteMessage(websocket.TextMessage, []byte("goodbye")); err != nil {
			t.Errorf("writing to websocket: %v", err)
		}
		return
	}

	backend := newServer(http.HandlerFunc(f))
	p, err := newWSReverseProxy(&wsProxyConfig{
		TLSConfig: backend.TLS,
		Backend:   toWSURL(backend.URL),
		Logger:    log.New(ioutil.Discard, "", 0),
	})
	if err != nil {
		t.Fatalf("new proxy: %v", err)
	}

	proxy := newServer(p)

	dialer := &websocket.Dialer{TLSClientConfig: proxy.TLS}
	targetURL := toWSURL(proxy.URL)
	h := http.Header{}
	if config.modifyRequest != nil {
		targetURL, h = config.modifyRequest(targetURL, h)
	}

	conn, resp, err := dialer.Dial(targetURL, h)
	if err != nil {
		t.Fatalf("dialing: %v %v", err, resp)
	}
	if err := conn.WriteMessage(websocket.TextMessage, []byte("hello")); err != nil {
		t.Fatalf("writing to websocket: %v", err)
	}

	_, b, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("reading from websocket: %v", err)
	}
	if !bytes.Equal(b, []byte("goodbye")) {
		t.Errorf("unexpected data from websocket: %s", b)
	}
}

func TestToWSURL(t *testing.T) {
	tests := []struct {
		url  string
		want string
	}{
		{"https://foo.com", "wss://foo.com"},
		{"http://foo.com", "ws://foo.com"},
		{"wss://foo.com", "wss://foo.com"},
	}

	for _, test := range tests {
		got := toWSURL(test.url)
		if got != test.want {
			t.Errorf("toWSURL(%q), wanted=%s, got=%s", test.url, test.want, got)
		}
	}
}

func TestIsWSRequest(t *testing.T) {
	tests := []struct {
		name string
		req  *http.Request
		isWS bool
	}{
		{
			name: "websocket_request",
			req: func() *http.Request {
				r := httptest.NewRequest("GET", "https://example.com/", nil)
				r.Header.Set("Connection", "Upgrade")
				r.Header.Set("Upgrade", "websocket")
				return r
			}(),
			isWS: true,
		},
		{
			name: "different_proto",
			req: func() *http.Request {
				r := httptest.NewRequest("GET", "https://example.com/", nil)
				r.Header.Set("Connection", "Upgrade")
				r.Header.Set("Upgrade", "h2c")
				return r
			}(),
			isWS: false,
		},
		{
			name: "with_comma",
			req: func() *http.Request {
				r := httptest.NewRequest("GET", "https://example.com/", nil)
				r.Header.Set("Connection", "Upgrade, Setting")
				r.Header.Set("Upgrade", "websocket")
				return r
			}(),
			isWS: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := isWSRequest(test.req)
			if got != test.isWS {
				t.Errorf("expected %v got %v", test.isWS, got)
			}
		})
	}
}
