package app

import (
	"context"
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/oklog/run"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"

	"github.com/ericchiang/kube-oidc/internal/authproxy"
	"github.com/ericchiang/kube-oidc/internal/forked/oidc"
	"github.com/ericchiang/kube-oidc/internal/kubeconfig"
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

	serveCmd := &cobra.Command{
		Use:   "serve [config file]",
		Short: "Begin serving the authenticating proxy",
		RunE: func(cmd *cobra.Command, args []string) error {
			switch len(args) {
			case 0:
				return errors.New("no config file provided")
			case 1:
			default:
				return errors.New("surplus arguments provided")
			}
			return serveKubeOIDCProxy(args[0])
		},
	}

	cmd.AddCommand(serveCmd)

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

type authFunc func(token string) (username string, groups []string, err error)

func (af authFunc) AuthenticateToken(token string) (username string, groups []string, err error) {
	return af(token)
}

func serveKubeOIDCProxy(configPath string) error {
	data, err := ioutil.ReadFile(configPath)
	if err != nil {
		return errors.Wrap(err, "reading config file")
	}
	c, err := parseConfig(data)
	if err != nil {
		return errors.Wrap(err, "parsing config file")
	}

	logger := log.New(os.Stderr, "", log.LstdFlags)

	oidcConfig := oidc.Options{
		IssuerURL:     c.oidcIssuer,
		CAFile:        c.oidcCA,
		ClientID:      c.oidcAllowedClientID,
		UsernameClaim: c.oidcUsernameClaim,
		GroupsClaim:   c.oidcGroupsClaim,
		Logger:        logger,
	}

	authenticator, err := oidc.New(oidcConfig)
	if err != nil {
		return errors.Wrap(err, "initializing oidc authenticator")
	}

	kubeConfig, err := kubeconfig.Load(c.kubeconfig)
	if err != nil {
		return errors.Wrap(err, "loading kubeconfig")
	}

	authProxyConfig := &authproxy.Config{
		Backend:          kubeConfig.Endpoint,
		BackendAuth:      kubeConfig.Auth,
		BackendTLSConfig: kubeConfig.TLSConfig,
		Logger:           logger,
		Authenticator: authFunc(func(token string) (string, []string, error) {
			username, groups, ok, err := authenticator.AuthenticateToken(token)
			if err == nil && !ok {
				err = errors.New("invalid token")
			}
			return username, groups, err
		}),
	}

	h, err := authproxy.New(authProxyConfig)
	if err != nil {
		return errors.Wrap(err, "initializing auth proxy")
	}

	// Go's server defaults are pretty bad. These configurations are taken from
	// https://blog.cloudflare.com/exposing-go-on-the-internet/

	var g run.Group
	if c.httpAddress != "" {
		s := &http.Server{
			Addr:         c.httpAddress,
			Handler:      h,
			ReadTimeout:  5 * time.Second,
			WriteTimeout: 10 * time.Second,
			IdleTimeout:  120 * time.Second,
		}

		g.Add(func() error {
			return s.ListenAndServe()
		}, func(err error) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
			defer cancel()

			s.Shutdown(ctx)
		})
	}

	if c.httpsAddress != "" {
		cert, err := tls.LoadX509KeyPair(c.httpsCertificate, c.httpsKey)
		if err != nil {
			return errors.Wrap(err, "loading serving certificate")
		}

		s := &http.Server{
			Addr:         c.httpsAddress,
			Handler:      h,
			ReadTimeout:  5 * time.Second,
			WriteTimeout: 10 * time.Second,
			IdleTimeout:  120 * time.Second,
			TLSConfig: &tls.Config{
				Certificates:             []tls.Certificate{cert},
				PreferServerCipherSuites: true,
				MinVersion:               tls.VersionTLS12,
			},
		}

		g.Add(func() error {
			return s.ListenAndServeTLS("", "")
		}, func(err error) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
			defer cancel()

			s.Shutdown(ctx)
		})
	}
	return g.Run()
}
