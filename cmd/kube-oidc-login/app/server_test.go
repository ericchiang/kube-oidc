package app

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"text/template"

	"github.com/pkg/errors"
)

type oauth2Client struct {
	id          string
	secret      string
	redirectURI string
}

func newTestServer(clients ...oauth2Client) *httptest.Server {
	server := &testServer{}
	for _, client := range clients {
		server.registerClient(client)
	}
	s := httptest.NewServer(server)
	server.issuer = s.URL
	return s
}

func TestNewServer(t *testing.T) {
	var h http.Handler
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(w, r)
	}))
	defer s.Close()

	client := oauth2Client{
		id:          "client-id",
		secret:      "client-secret",
		redirectURI: s.URL + "/callback",
	}

	p := newTestServer(client)
	defer p.Close()

	config := &serverConfig{
		clientID:     client.id,
		clientSecret: client.secret,
		redirectURI:  client.redirectURI,
		issuer:       p.URL,

		kubernetesEndpoint: "https://k8s.example.com",
		kubernetesCA:       []byte("hello"),

		// logger: log.New(ioutil.Discard, "", 0),
	}

	loginServer, err := newServer(config)
	if err != nil {
		t.Fatalf("initializing server: %v", err)
	}
	h = loginServer

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("new cookie jar: %v", err)
	}
	httpClient := &http.Client{Jar: jar}

	resp, err := httpClient.Get(s.URL)
	if err != nil {
		t.Fatalf("getting server")
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status code 200, got %s %s", resp.Status, body)
	}
}

// testServer is a mock implementation of an OpenID Connect provider.
type testServer struct {
	issuer string

	clients map[string]oauth2Client
}

func (t *testServer) registerClient(client oauth2Client) {
	if t.clients == nil {
		t.clients = make(map[string]oauth2Client)
	}
	t.clients[client.id] = client
}

func (t *testServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	m := r.Method
	p := r.URL.Path

	switch {
	case m == "GET" && p == "/.well-known/openid-configuration":
		t.handleWellKnown(w, r)
	case m == "GET" && p == "/auth":
		t.handleAuth(w, r)
	case m == "POST" && p == "/token":
		t.handleToken(w, r)
	default:
		http.NotFound(w, r)
	}
}

// handleWellKnown implement the discovery endpoint
//
// https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfig
func (t *testServer) handleWellKnown(w http.ResponseWriter, r *http.Request) {
	wellKnownTmpl.Execute(w, struct {
		Issuer string
	}{t.issuer})
}

var wellKnownTmpl = template.Must(template.New("").Parse(`{
	"issuer": "{{ .Issuer }}",
	"authorization_endpoint": "{{ .Issuer }}/auth",
	"token_endpoint": "{{ .Issuer }}/token",
	"jwks_uri": "{{ .Issuer }}/keys"
}`))

// handleAuth implements the authorization endpoint
//
// http://openid.net/specs/openid-connect-core-1_0.html#AuthorizationEndpoint
func (t *testServer) handleAuth(w http.ResponseWriter, r *http.Request) {
	redirect, err := t.parseAuthRequest(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, redirect, http.StatusSeeOther)
}

func (t *testServer) parseAuthRequest(r *http.Request) (string, error) {
	q := r.URL.Query()
	if rt := q.Get("response_type"); rt != "code" {
		return "", errors.Errorf("invalid response_type: %v", rt)
	}

	hasOpenIDScope := false
	for _, scope := range strings.Split(q.Get("scope"), " ") {
		if scope == "openid" {
			hasOpenIDScope = true
			break
		}
	}
	if !hasOpenIDScope {
		return "", errors.Errorf("scopes didn't contain 'openid' scope: %s", q.Get("scope"))
	}

	clientID := q.Get("client_id")
	client, ok := t.clients[clientID]
	if !ok {
		return "", errors.Errorf("unknown client ID: %s", clientID)
	}

	redirectURI := q.Get("redirect_uri")
	if client.redirectURI != redirectURI {
		return "", errors.Errorf("invalid redirect URI: %s", redirectURI)
	}

	code, err := (&oauth2Code{
		RedirectURI: redirectURI,
		ClientID:    clientID,
	}).encode()
	if err != nil {
		return "", errors.Wrap(err, "encoding code")
	}

	v := url.Values{}
	v.Set("code", code)
	if state := q.Get("state"); state != "" {
		v.Set("state", state)
	}
	if strings.Contains(redirectURI, "?") {
		return redirectURI + "&" + v.Encode(), nil
	}
	return redirectURI + "?" + v.Encode(), nil
}

// handleToken implements the token endpoint
//
// http://openid.net/specs/openid-connect-core-1_0.html#TokenEndpoint
func (t *testServer) handleToken(w http.ResponseWriter, r *http.Request) {
	if err := t.parseTokenRequest(r); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Write an arbitrary token respones back
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{
	"access_token": "SlAV32hkKG",
	"token_type": "Bearer",
	"expires_in": 3600,
	"id_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.TCYt5XsITJX1CxPCT8yAV-TVkIEq_PbChOMqsLfRoPsnsgw5WEuts01mq-pQy7UJiN5mgRxD-WUcX16dUEMGlv50aqzpqh4Qktb3rk-BuQy72IFLOqV0G_zS245-kronKb78cPN25DGlcTwLtjPAYuNzVBAh4vGHSrQyHUdBBPM"
}`)
}

func (t *testServer) parseTokenRequest(r *http.Request) error {
	if gt := r.PostFormValue("grant_type"); gt != "authorization_code" {
		return errors.Errorf("invalid grant_type: %s", gt)
	}

	code := r.PostFormValue("code")
	if code == "" {
		return errors.New("no code forum value")
	}

	o := &oauth2Code{}
	if err := o.decode(code); err != nil {
		return errors.Wrap(err, "parsing code")
	}

	clientID, clientSecret, ok := r.BasicAuth()
	if !ok {
		return errors.New("no client credentials provided")
	}

	if clientID != o.ClientID {
		return errors.New("invalid client ID")
	}

	client, ok := t.clients[clientID]
	if !ok {
		return errors.Errorf("unknown client ID: %s", clientID)
	}
	if client.secret != clientSecret {
		return errors.New("invalid credentials provided")
	}

	if redirectURI := r.PostFormValue("redirect_uri"); redirectURI != o.RedirectURI {
		return errors.Errorf("invalid redirect_uri: %s", redirectURI)
	}

	return nil
}

type oauth2Code struct {
	ClientID    string
	RedirectURI string
}

func (o *oauth2Code) encode() (string, error) {
	data, err := json.Marshal(o)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(data), nil
}

func (o *oauth2Code) decode(s string) error {
	data, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return errors.Wrap(err, "base64 decoding")
	}

	if err := json.Unmarshal(data, o); err != nil {
		return errors.Wrap(err, "unmarshaling json")
	}
	return nil
}
