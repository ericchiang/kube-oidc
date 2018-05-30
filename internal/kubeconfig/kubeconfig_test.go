package kubeconfig

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"text/template"
)

func newKubeconfig(t *testing.T, kubeconfigTmpl, endpoint string) (string, func()) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getting working directory: %v", err)
	}
	out := &bytes.Buffer{}

	funcs := template.FuncMap{
		"loadBase64": func(s string) string {
			data, err := ioutil.ReadFile(filepath.Join(wd, "testdata", s))
			if err != nil {
				t.Fatalf("load file: %v", err)
			}
			return base64.StdEncoding.EncodeToString(data)
		},
	}

	data := struct {
		Endpoint string
		Testdata string
	}{endpoint, filepath.Join(wd, "testdata")}

	tmpl, err := template.New("").Funcs(funcs).Parse(kubeconfigTmpl)
	if err != nil {
		t.Fatalf("parsing kubeconfig template: %v", err)
	}
	if err := tmpl.Execute(out, data); err != nil {
		t.Fatalf("executing kubeconfig template: %v", err)
	}

	f, err := ioutil.TempFile("", "kube_oidc_test_")
	if err != nil {
		t.Fatalf("creating temp file: %v", err)
	}
	path := f.Name()

	_, err = io.Copy(f, out)
	f.Close()
	if err != nil {
		t.Fatalf("writing kubeconfig to file: %v", err)
	}

	return path, func() {
		if err := os.Remove(path); err != nil {
			t.Errorf("remove temp file: %v", err)
		}
	}
}

func TestLoad(t *testing.T) {
	tests := []struct {
		name string
		data string

		wantToken      string
		wantClientCert bool

		wantParseErr bool
	}{
		{
			name: "kubeconfig",
			data: `
apiVersion: v1
kind: Config
clusters:
- name: dev
  cluster:
    certificate-authority: {{ .Testdata }}/ca.pem
    server: {{ .Endpoint }}
users:
- name: developer
  user:
contexts:
- name: dev
  context:
    user: developer
    cluster: dev
current-context: dev
`,
		},
		{
			name: "no_context",
			data: `
apiVersion: v1
kind: Config
clusters:
- name: dev
  cluster:
    certificate-authority: {{ .Testdata }}/ca.pem
    server: {{ .Endpoint }}
users:
- name: developer
  user:
`,
		},
		{
			name: "bearer_token",
			data: `
apiVersion: v1
kind: Config
clusters:
- name: dev
  cluster:
    certificate-authority: {{ .Testdata }}/ca.pem
    server: {{ .Endpoint }}
users:
- name: developer
  user:
    token: a-token
`,
			wantToken: "a-token",
		},
		{
			name: "client_auth",
			data: `
apiVersion: v1
kind: Config
clusters:
- name: dev
  cluster:
    certificate-authority: {{ .Testdata }}/ca.pem
    server: {{ .Endpoint }}
users:
- name: developer
  user:
    client-certificate: {{ .Testdata }}/client.pem
    client-key: {{ .Testdata }}/client-key.pem
`,
			wantClientCert: true,
		},
		{
			name: "client_auth_inlined",
			data: `
apiVersion: v1
kind: Config
clusters:
- name: dev
  cluster:
    certificate-authority-data: {{ loadBase64 "ca.pem" }}
    server: {{ .Endpoint }}
users:
- name: developer
  user:
    client-certificate-data: {{ loadBase64 "client.pem" }}
    client-key-data: {{ loadBase64 "client-key.pem" }}
`,
			wantClientCert: true,
		},
		{
			name: "insecure_skip_verify",
			data: `
apiVersion: v1
kind: Config
clusters:
- name: dev
  cluster:
    insecure-skip-tls-verify: true
    server: {{ .Endpoint }}
users:
- name: developer
  user:
    client-certificate: {{ .Testdata }}/client.pem
    client-key: {{ .Testdata }}/client-key.pem
`,
		},
		{
			name: "AuthProvider",
			data: `
apiVersion: v1
kind: Config
clusters:
- name: dev
  cluster:
    certificate-authority: {{ .Testdata }}/ca.pem
    server: {{ .Endpoint }}
users:
- name: developer
  user:
    auth-provider:
      name: oidc
      config:
        client-id: foo
        client-secret: bar
contexts:
- name: dev
  context:
    user: developer
    cluster: dev
current-context: dev
`,
			wantParseErr: true,
		},
		{
			name: "ExecPlugin",
			data: `
apiVersion: v1
kind: Config
clusters:
- name: dev
  cluster:
    certificate-authority: {{ .Testdata }}/ca.pem
    server: {{ .Endpoint }}
users:
- name: developer
  user:
    exec:
      command: "example-client-go-exec-plugin"
      apiVersion: "client.authentication.k8s.io/v1alpha1"
contexts:
- name: dev
  context:
    user: developer
    cluster: dev
current-context: dev
`,
			wantParseErr: true,
		},
	}

	caData, err := ioutil.ReadFile("testdata/ca.pem")
	if err != nil {
		t.Fatalf("load ca file: %v", err)
	}
	rootCAs := x509.NewCertPool()
	rootCAs.AppendCertsFromPEM(caData)

	cert, err := tls.LoadX509KeyPair("testdata/server.pem", "testdata/server-key.pem")
	if err != nil {
		t.Fatalf("load serving cert: %v", err)
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			hf := func(w http.ResponseWriter, r *http.Request) {
				if test.wantToken != "" {
					got := r.Header.Get("Authorization")
					want := "Bearer " + test.wantToken
					if got != want {
						t.Errorf("expected Authorization header %q got %q", want, got)
					}
				}
				fmt.Fprint(w, "ok")
			}
			s := httptest.NewUnstartedServer(http.HandlerFunc(hf))
			s.TLS = &tls.Config{
				Certificates: []tls.Certificate{cert},
				ClientCAs:    rootCAs,
			}
			if test.wantClientCert {
				s.TLS.ClientAuth = tls.RequireAndVerifyClientCert
			}

			s.StartTLS()
			defer s.Close()

			u, err := url.Parse(s.URL)
			if err != nil {
				t.Fatalf("parse test server URL: %v", err)
			}
			// Serving cert is signed for "localhost" not an IP address
			if _, port, err := net.SplitHostPort(u.Host); err == nil {
				u.Host = "localhost:" + port
			} else {
				u.Host = "localhost"
			}
			endpoint := u.String()

			path, close := newKubeconfig(t, test.data, endpoint)
			defer close()

			config, err := Load(path)
			if err != nil {
				if !test.wantParseErr {
					t.Errorf("parsing kubeconfig: %v", err)
				}
				return
			}

			if test.wantParseErr {
				t.Errorf("expected error parsing kubeconfig")
				return
			}

			client := &http.Client{
				Transport: &http.Transport{
					TLSClientConfig: config.TLSConfig,
				},
			}

			req, err := http.NewRequest("GET", endpoint, nil)
			if err != nil {
				t.Errorf("create request: %v", err)
				return
			}
			config.Auth(req)

			resp, err := client.Do(req)
			if err != nil {
				t.Errorf("failed to get response: %v", err)
				return
			}
			resp.Body.Close()
		})
	}
}

func TestParse(t *testing.T) {
	tests := []struct {
		name string
		data string
		want *kubeconfig
	}{
		{
			name: "kubeconfig",
			data: `apiVersion: v1
clusters:
- cluster:
    certificate-authority: fake-ca-file
    server: https://1.2.3.4
  name: development
contexts:
- context:
    cluster: development
    namespace: frontend
    user: developer
  name: dev-frontend
current-context: dev-frontend
kind: Config
preferences: {}
users:
- name: developer
  user:
    client-certificate: fake-cert-file
    client-key: fake-key-file
`,
			want: &kubeconfig{
				Clusters: []namedCluster{
					{
						Name: "development",
						Cluster: cluster{
							CA:     "fake-ca-file",
							Server: "https://1.2.3.4",
						},
					},
				},
				Contexts: []namedContext{
					{
						Name: "dev-frontend",
						Context: context{
							Cluster: "development",
							User:    "developer",
						},
					},
				},
				Users: []namedUser{
					{
						Name: "developer",
						User: user{
							ClientCert: "fake-cert-file",
							ClientKey:  "fake-key-file",
						},
					},
				},
				CurrentContext: "dev-frontend",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := parse([]byte(test.data))
			if err != nil {
				t.Fatalf("failed to parse kubeconfig: %v", err)
			}
			if !reflect.DeepEqual(got, test.want) {
				t.Errorf("expected\n%#v\ngot\n%#v", test.want, got)
			}
		})
	}
}
