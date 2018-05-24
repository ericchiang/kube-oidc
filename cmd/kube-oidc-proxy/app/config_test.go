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

  usernameClaim: "email"
  groupsClaim: "groups"

  allowedClientID: "my-client-id"

kubernetes:
  kubeconfig: "/etc/kubeconfig"
`,
			want: &config{
				httpAddress:         "0.0.0.0:80",
				httpsAddress:        "0.0.0.0:443",
				httpsCertificate:    "certs/serving.crt",
				httpsKey:            "certs/serving.key",
				oidcIssuer:          "https://accounts.google.com",
				oidcCA:              "/etc/certs/certs.pem",
				oidcUsernameClaim:   "email",
				oidcGroupsClaim:     "groups",
				oidcAllowedClientID: "my-client-id",
				kubeconfig:          "/etc/kubeconfig",
			},
		},
		{
			name: "no_version",
			data: `
web:
  http: "0.0.0.0:80"
  https: "0.0.0.0:443"
  httpsCert: "certs/serving.crt"
  httpsKey: "certs/serving.key"

oidc:
  issuer: "https://accounts.google.com"
  issuerCA: "/etc/certs/certs.pem"

  usernameClaim: "email"
  groupsClaim: "groups"

  allowedClientID: "my-client-id"

kubernetes:
  kubeconfig: "/etc/kubeconfig"
`,
			wantErr: true,
		},
		{
			name: "unrecognized_version",
			data: `
version: "v10"

web:
  http: "0.0.0.0:80"
  https: "0.0.0.0:443"
  httpsCert: "certs/serving.crt"
  httpsKey: "certs/serving.key"

oidc:
  issuer: "https://accounts.google.com"
  issuerCA: "/etc/certs/certs.pem"

  usernameClaim: "email"
  groupsClaim: "groups"

  allowedClientID: "my-client-id"

kubernetes:
  kubeconfig: "/etc/kubeconfig"
`,
			wantErr: true,
		},
		{
			name: "unknown_field",
			data: `
version: "v1"

unknown: "hi"

web:
  http: "0.0.0.0:80"
  https: "0.0.0.0:443"
  httpsCert: "certs/serving.crt"
  httpsKey: "certs/serving.key"

oidc:
  issuer: "https://accounts.google.com"
  issuerCA: "/etc/certs/certs.pem"

  usernameClaim: "email"
  groupsClaim: "groups"

  allowedClientID: "my-client-id"

kubernetes:
  kubeconfig: "/etc/kubeconfig"
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
