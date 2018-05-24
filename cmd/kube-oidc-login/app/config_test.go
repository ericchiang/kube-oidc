package app

import (
	"reflect"
	"testing"
)

func TestParseConfig(t *testing.T) {
	tests := []struct {
		name    string
		data    string
		want    *config
		wantErr bool
	}{
		{
			name: "config",
			data: `
version: "v1"

web:
  http: "0.0.0.0:80"
  https: "0.0.0.0:443"
  httpsCert: "certs/serving.crt"
  httpsKey: "certs/serving.key"

oidc:
  issuer: "https://accounts.google.com"
  issuerCA: "/etc/certs/certs.pem"

  clientID: "my-client-id"
  clientSecretFile: "/etc/client-secret"

  scopes:
  - "openid"
  - "email"
  - "profile"

  redirectURI: "http://localhost:8080/callback"

kubernetes:
  apiServer: "https://k8s.example.com"
  apiServerCA: "/etc/certs/cert.pem"
`,
			want: &config{
				httpAddress:          "0.0.0.0:80",
				httpsAddress:         "0.0.0.0:443",
				httpsCertificate:     "certs/serving.crt",
				httpsKey:             "certs/serving.key",
				oidcIssuer:           "https://accounts.google.com",
				oidcIssuerCA:         "/etc/certs/certs.pem",
				oidcClientID:         "my-client-id",
				oidcClientSecretFile: "/etc/client-secret",
				oidcRedirectURI:      "http://localhost:8080/callback",
				oidcScopes:           []string{"openid", "email", "profile"},
				kubernetesEndpoint:   "https://k8s.example.com",
				kubernetesCA:         "/etc/certs/cert.pem",
			},
		},
		{
			name: "unknown_field",
			data: `
version: "v1"

web:
  http: "0.0.0.0:80"
  https: "0.0.0.0:443"
  httpsCert: "certs/serving.crt"
  httpsKey: "certs/serving.key"

oidc:
  issuer: "https://accounts.google.com"
  issuerCA: "/etc/certs/certs.pem"

  clientID: "my-client-id"
  clientSecretFile: "/etc/client-secret"
  redirectURI: "http://localhost:8080/callback"

# Woops, this was unindented!
scopes:
- "openid"
- "email"
- "profile"

kubernetes:
  apiServer: "https://k8s.example.com"
  apiServerCA: "/etc/certs/cert.pem"
`,
			wantErr: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := parseConfig([]byte(test.data))
			if err != nil {
				if !test.wantErr {
					t.Fatalf("parse config: %v", err)
				}
				return
			}

			if test.wantErr {
				t.Fatalf("expected error parsing config")
			}

			if !reflect.DeepEqual(got, test.want) {
				t.Errorf("wanted:\n%#v\ngot:\n%#v", test.want, got)
			}
		})
	}
}
