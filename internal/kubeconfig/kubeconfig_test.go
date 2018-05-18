package kubeconfig

import (
	"reflect"
	"testing"
)

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
