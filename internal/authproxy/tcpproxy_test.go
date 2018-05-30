package authproxy

import (
	"bytes"
	"crypto/x509"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/websocket"
)

type testConfig struct {
	modifyRequest func(url string, h http.Header) (string, http.Header)
	checkRequest  func(r *http.Request)

	// If connections should use TLS
	useTLS bool
}

func TestTCPReverseProxy(t *testing.T) {
	testTCPReverseProxy(t, &testConfig{})
}

func TestTCPReverseProxyTLSConfig(t *testing.T) {
	testTCPReverseProxy(t, &testConfig{
		useTLS: true,
	})
}

func TestTCPReverseProxyHeaders(t *testing.T) {
	testTCPReverseProxy(t, &testConfig{
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

func TestTCPReverseProxyURLPath(t *testing.T) {
	testTCPReverseProxy(t, &testConfig{
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

func TestTCPReverseProxySubprotocols(t *testing.T) {
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

	testTCPReverseProxy(t, &testConfig{
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

func testTCPReverseProxy(t *testing.T, config *testConfig) {
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
	p, err := newTCPReverseProxy(&tcpProxyConfig{
		TLSConfig: backend.TLS,
		Backend:   backend.URL,
		Logger:    log.New(ioutil.Discard, "", 0),
	})
	if err != nil {
		t.Fatalf("new proxy: %v", err)
	}

	proxy := newServer(p)

	dialer := &websocket.Dialer{TLSClientConfig: proxy.TLS}
	targetURL := "ws" + strings.TrimPrefix(proxy.URL, "http")
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

func TestIsUpgradeRequest(t *testing.T) {
	tests := []struct {
		name      string
		req       *http.Request
		isUpgrade bool
	}{
		{
			name: "websocket_request",
			req: func() *http.Request {
				r := httptest.NewRequest("GET", "https://example.com/", nil)
				r.Header.Set("Connection", "Upgrade")
				r.Header.Set("Upgrade", "websocket")
				return r
			}(),
			isUpgrade: true,
		},
		{
			name: "spdy",
			req: func() *http.Request {
				r := httptest.NewRequest("GET", "https://example.com/", nil)
				r.Header.Set("Connection", "Upgrade")
				r.Header.Set("Upgrade", "spdy")
				return r
			}(),
			isUpgrade: true,
		},
		{
			name: "with_comma",
			req: func() *http.Request {
				r := httptest.NewRequest("GET", "https://example.com/", nil)
				r.Header.Set("Connection", "Upgrade, Setting")
				r.Header.Set("Upgrade", "websocket")
				return r
			}(),
			isUpgrade: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := isUpgradeRequest(test.req)
			if got != test.isUpgrade {
				t.Errorf("expected %v got %v", test.isUpgrade, got)
			}
		})
	}
}
