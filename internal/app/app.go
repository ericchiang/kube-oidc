package app

import (
	"fmt"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

// NewKubeOIDCProxy returns a command line tool for an authenticating
// proxy against the Kubernetes API server.
func NewKubeOIDCProxy() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "kube-oidc-proxy",
		Short: "An OpenID Connect authenticating proxy for Kubernetes",
		Long: `An authentication proxy for Kubernetes.
		
kube-oidc-proxy proxy authenticates OpenID Connect ID tokens and uses
impersionation headers to act on behalf of the user to the Kubernetes
API server. This allows the proxy to authenticate users for any
Kubernetes cluster, without API server reconfiguration.
		`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return nil
		},
	}

	versionCmd := &cobra.Command{
		Use:   "version",
		Short: "Print the version of the tool and exit",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) > 0 {
				return errors.New("surplus arguments provided")
			}
			fmt.Println(versionString())
			return nil
		},
	}

	cmd.AddCommand(versionCmd)

	return cmd
}
