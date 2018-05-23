package app

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"text/template"
	"time"

	"github.com/pkg/errors"
	"golang.org/x/oauth2"
)

type serverConfig struct {
	clientID     string
	clientSecret string

	redirectURI string

	issuer          string
	issuerTLSConfig *tls.Config

	kubernetesEndpoint string
	kubernetesCA       []byte

	scopes []string

	logger *log.Logger
}

type server struct {
	config *oauth2.Config

	redirectURI *url.URL

	kubernetesEndpoint string
	kubernetesCA       []byte

	logger *log.Logger
}

func newServer(c *serverConfig) (*server, error) {
	redirectURI, err := url.Parse(c.redirectURI)
	if err != nil {
		return nil, errors.Wrap(err, "parse redirect URI")
	}

	client := &http.Client{
		Timeout: time.Second * 30,
	}
	if c.issuerTLSConfig != nil {
		client.Transport = &http.Transport{
			TLSClientConfig: c.issuerTLSConfig,

			// All of the http.DefaultTransport fields.
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
				DualStack: true,
			}).DialContext,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		}
	}

	endpoint, err := fetchProvider(client, c.issuer)
	if err != nil {
		return nil, errors.Wrap(err, "fetching oidc well-known data")
	}

	scopes := c.scopes
	if len(scopes) == 0 {
		scopes = []string{"openid", "email", "profile"}
	}

	return &server{
		config: &oauth2.Config{
			ClientID:     c.clientID,
			ClientSecret: c.clientSecret,
			Endpoint:     *endpoint,
			RedirectURL:  c.redirectURI,
			Scopes:       scopes,
		},
		redirectURI:        redirectURI,
		kubernetesEndpoint: c.kubernetesEndpoint,
		kubernetesCA:       c.kubernetesCA,
		logger:             c.logger,
	}, nil
}

// fetchProvider fetches the token and auth endpoints for an OpenID Connect provider
// using the HTTP discovery method.
//
// See: https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfig
func fetchProvider(client *http.Client, issuerURL string) (*oauth2.Endpoint, error) {
	// Per the spec:
	// "any terminating / MUST be removed before appending /.well-known/openid-configuration"
	endpoint := strings.TrimRight(issuerURL, "/") + "/.well-known/openid-configuration"

	req, err := http.NewRequest("GET", endpoint, nil)
	if err != nil {
		return nil, errors.Wrap(err, "creating request to well-known endpoint")
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "getting well-known endpoint")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, errors.Errorf("invalid status from %s %s", endpoint, resp.Status)
	}

	var respJSON struct {
		AuthEndpoint  string `json:"authorization_endpoint"`
		TokenEndpoint string `json:"token_endpoint"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&respJSON); err != nil {
		return nil, errors.Wrapf(err, "decode response from %s", endpoint)
	}
	return &oauth2.Endpoint{
		AuthURL:  respJSON.AuthEndpoint,
		TokenURL: respJSON.TokenEndpoint,
	}, nil
}

func (s *server) logf(format string, v ...interface{}) {
	if s.logger != nil {
		s.logger.Printf(format, v...)
		return
	}
	log.Printf(format, v...)
}

func (s *server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.redirectURI.Path == r.URL.Path {
		s.handleCallback(w, r)
		return
	}
	s.handleIndex(w, r)
}

func (s *server) handleIndex(w http.ResponseWriter, r *http.Request) {
	var b [32]byte
	if _, err := io.ReadFull(rand.Reader, b[:]); err != nil {
		s.logf("failed to create state token: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	state := base64.RawURLEncoding.EncodeToString(b[:])

	http.SetCookie(w, &http.Cookie{
		Name:     "state",
		Value:    state,
		HttpOnly: true,
		Secure:   s.redirectURI.Scheme == "https",
		Path:     s.redirectURI.Path,
	})

	http.Redirect(w, r, s.config.AuthCodeURL(state), http.StatusSeeOther)
}

func (s *server) handleCallback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	errMsg := q.Get("error")
	if errMsg != "" {
		err := errors.New(errMsg)
		if d := q.Get("error_description"); d != "" {
			err = errors.Errorf("%s: %s", errMsg, d)
		}
		s.logf("bad response from oauth2 server: %v", err)
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	code := q.Get("code")
	state := q.Get("state")

	if code == "" || state == "" {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	cookie, err := r.Cookie("state")
	if err != nil {
		s.logf("failed to get state cookie: %v", err)
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	if cookie.Value != state {
		s.logf("invalid state token")
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	token, err := s.config.Exchange(r.Context(), code)
	if err != nil {
		s.logf("token exchange failed: %v", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	idToken, ok := token.Extra("id_token").(string)
	if !ok {
		s.logf("token response didn't contain an id_token")
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	out := &bytes.Buffer{}
	err = kubeconfigTmpl.Execute(out, struct {
		Server  string
		CAData  string
		IDToken string
	}{
		s.kubernetesEndpoint,
		base64.StdEncoding.EncodeToString(s.kubernetesCA),
		idToken,
	})
	if err != nil {
		s.logf("failed to render kubeconfig: %v", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/yaml")
	w.Write(out.Bytes())
}

var kubeconfigTmpl = template.Must(template.New("").Parse(`apiVersion: v1
kind: Config
clusters:
- name: cluster
  cluster:
    server: {{ .Server }}
    certificate-authority-data: {{ .CAData }}
users:
- name: user
  user:
    token: {{ .IDToken }}
contexts:
- name: context
  context:
    cluster: cluster
    name: user
`))
