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
oidcCA: "/etc/certs/certs.pem"

oidcUsernameClaim: "email"
oidcGroupsClaim: "groups"

oidcAllowedClientID: "my-client-id"

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
httpAddress: "0.0.0.0:80"

httpsAddress: "0.0.0.0:443"
httpsCertificate: "certs/serving.crt"
httpsKey: "certs/serving.key"

oidcIssuer: "https://accounts.google.com"
oidcCA: "/etc/certs/certs.pem"

oidcUsernameClaim: "email"
oidcGroupsClaim: "groups"

oidcAllowedClientID: "my-client-id"

kubeconfig: "/etc/kubeconfig"
`,
			wantErr: true,
		},
		{
			name: "unrecognized_version",
			data: `
veresion: "v10"
httpAddress: "0.0.0.0:80"

httpsAddress: "0.0.0.0:443"
httpsCertificate: "certs/serving.crt"
httpsKey: "certs/serving.key"

oidcIssuer: "https://accounts.google.com"
oidcCA: "/etc/certs/certs.pem"

oidcUsernameClaim: "email"
oidcGroupsClaim: "groups"

oidcAllowedClientID: "my-client-id"

kubeconfig: "/etc/kubeconfig"
`,
			wantErr: true,
		},
		{
			name: "unknown_field",
			data: `
version: "v1"

unknown: "hi"

httpAddress: "0.0.0.0:80"

httpsAddress: "0.0.0.0:443"
httpsCertificate: "certs/serving.crt"
httpsKey: "certs/serving.key"

oidcIssuer: "https://accounts.google.com"
oidcCA: "/etc/certs/certs.pem"

oidcUsernameClaim: "email"
oidcGroupsClaim: "groups"

oidcAllowedClientID: "my-client-id"

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
