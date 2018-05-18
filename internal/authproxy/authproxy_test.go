package authproxy

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"testing"

	"github.com/pkg/errors"
)

type authFunc func(string) (string, []string, error)

func (af authFunc) AuthenticateToken(token string) (string, []string, error) {
	return af(token)
}

type authProxyTest struct {
	authFunc    func(token string) (string, []string, error)
	backendAuth func(r *http.Request)

	request             *http.Request
	checkBackendRequest func(*http.Request)

	wantErrorStatus int
}

func TestAuthProxy(t *testing.T) {
	testAuthProxy(t, &authProxyTest{
		authFunc: func(token string) (string, []string, error) {
			if token != "foo" {
				t.Errorf("expected token foo, got %s", token)
			}
			return "joe@example.com", []string{"group1", "group2"}, nil
		},
		backendAuth: func(r *http.Request) {
			r.Header.Set("Authorization", "Bearer bar")
		},
		request: func() *http.Request {
			r := httptest.NewRequest("GET", "https://example.com", nil)
			r.Header.Set("Authorization", "Bearer foo")
			return r
		}(),
		checkBackendRequest: func(r *http.Request) {
			wantAuthHeader := "Bearer bar"
			if gotAuthHeader := r.Header.Get("Authorization"); gotAuthHeader != wantAuthHeader {
				t.Errorf("expected authorization header=%v, got=%v", wantAuthHeader, gotAuthHeader)
			}

			wantUser := "joe@example.com"
			if user := r.Header.Get("Impersonate-User"); user != wantUser {
				t.Errorf("expected impersonation user header=%s, got=%s", wantUser, user)
			}

			wantGroups := []string{"group1", "group2"}
			gotGroups := r.Header["Impersonate-Group"]

			sort.Strings(wantGroups)
			sort.Strings(gotGroups)

			if !reflect.DeepEqual(wantGroups, gotGroups) {
				t.Errorf("expected impersionation group headers=%v, got=%v", wantGroups, gotGroups)
			}
		},
	})
}

func TestAuthProxyImpersionationRequest(t *testing.T) {
	testAuthProxy(t, &authProxyTest{
		authFunc: func(token string) (string, []string, error) {
			return "joe", nil, nil
		},
		request: func() *http.Request {
			r := httptest.NewRequest("GET", "https://example.com", nil)
			r.Header.Set("Authorization", "Bearer foo")

			// Proxy doesn't allow clients to set impersonation headers
			r.Header.Set("Impersonate-User", "jane")
			return r
		}(),
		wantErrorStatus: http.StatusBadRequest,
	})
}

func TestAuthProxyInvalidBearerToken(t *testing.T) {
	testAuthProxy(t, &authProxyTest{
		authFunc: func(token string) (string, []string, error) {
			return "", nil, errors.New("invalid credentials")
		},
		request: func() *http.Request {
			r := httptest.NewRequest("GET", "https://example.com", nil)
			r.Header.Set("Authorization", "Bearer foo")
			return r
		}(),
		wantErrorStatus: http.StatusUnauthorized,
	})
}

func TestAuthProxyInvalidAuthorizationHeader(t *testing.T) {
	testAuthProxy(t, &authProxyTest{
		authFunc: func(token string) (string, []string, error) {
			return "joe", nil, nil
		},
		request: func() *http.Request {
			r := httptest.NewRequest("GET", "https://example.com", nil)
			r.SetBasicAuth("foo", "bar")
			return r
		}(),
		wantErrorStatus: http.StatusUnauthorized,
	})
}

func TestAuthProxyImpersionationRequestLowercase(t *testing.T) {
	testAuthProxy(t, &authProxyTest{
		authFunc: func(token string) (string, []string, error) {
			return "joe", nil, nil
		},
		request: func() *http.Request {
			r := httptest.NewRequest("GET", "https://example.com", nil)
			r.Header.Set("Authorization", "Bearer foo")

			// Proxy doesn't allow clients to set impersonation headers
			r.Header.Set("impersonate-User", "jane")
			return r
		}(),
		wantErrorStatus: http.StatusBadRequest,
	})
}

func testAuthProxy(t *testing.T, test *authProxyTest) {
	backendAuth := test.backendAuth
	if backendAuth == nil {
		backendAuth = func(r *http.Request) {}
	}

	gotRequest := false
	hf := func(w http.ResponseWriter, r *http.Request) {
		gotRequest = true
		if test.checkBackendRequest != nil {
			test.checkBackendRequest(r)
		}
		fmt.Fprint(w, "ok")
	}

	backend := httptest.NewTLSServer(http.HandlerFunc(hf))
	defer backend.Close()

	tlsConfig := &tls.Config{RootCAs: x509.NewCertPool()}
	tlsConfig.RootCAs.AddCert(backend.Certificate())

	h, err := New(&Config{
		Backend:          backend.URL,
		BackendAuth:      backendAuth,
		BackendTLSConfig: tlsConfig,
		Authenticator:    authFunc(test.authFunc),
		Logger:           log.New(ioutil.Discard, "", 0),
	})
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, test.request)

	if test.wantErrorStatus != 0 {
		if rr.Code != test.wantErrorStatus {
			t.Errorf("expected HTTP status %d got %d", test.wantErrorStatus, rr.Code)
		}
	} else if !gotRequest {
		t.Errorf("backend didn't get a request")
	}
}
