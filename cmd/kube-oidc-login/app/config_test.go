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

httpAddress: "0.0.0.0:80"

httpsAddress: "0.0.0.0:443"
httpsCertificate: "certs/serving.crt"
httpsKey: "certs/serving.key"

oidcIssuer: "https://accounts.google.com"
oidcIssuerCA: "/etc/certs/certs.pem"

oidcClientID: "my-client-id"
oidcClientSecretFile: "/etc/client-secret"

oidcRedirectURI: "http://localhost:8080/callback"

kubernetesEndpoint: "https://k8s.example.com"
kubernetesCA: "/etc/certs/cert.pem"
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
				kubernetesEndpoint:   "https://k8s.example.com",
				kubernetesCA:         "/etc/certs/cert.pem",
			},
		},
		{
			name: "unknown_field",
			data: `
version: "v1"

httpAddress: "0.0.0.0:80"

httpsAddress: "0.0.0.0:443"
httpsCertificate: "certs/serving.crt"
httpsKey: "certs/serving.key"

oidcIssuer: "https://accounts.google.com"
oidcIssuerCA: "/etc/certs/certs.pem"

oidcClientID: "my-client-id"
oidcClientSecretFile: "/etc/client-secret"

oidcRedirectURI: "http://localhost:8080/callback"

kubernetesEndpoint: "https://k8s.example.com"
kubernetesCA: "/etc/certs/cert.pem"

unknown: "hi"
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
