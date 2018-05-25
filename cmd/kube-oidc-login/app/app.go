package app

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/oklog/run"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"

	"github.com/ericchiang/kube-oidc/internal/version"
)

// New returns a command line tool for an authenticating proxy against the
// Kubernetes API server.
func New() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "kube-oidc-login",
		Short: "An OpenID Connect client for logging in users",
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
			return serve(args[0])
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
			fmt.Println(version.String())
			return nil
		},
	}

	cmd.AddCommand(versionCmd)
	return cmd
}

func serve(configPath string) error {
	data, err := ioutil.ReadFile(configPath)
	if err != nil {
		return errors.Wrap(err, "loading config file")
	}

	c, err := parseConfig(data)
	if err != nil {
		return errors.Wrap(err, "parsing config file")
	}

	secretData, err := ioutil.ReadFile(c.oidcClientSecretFile)
	if err != nil {
		return errors.Wrap(err, "reading client secret file")
	}
	clientSecret := strings.TrimSpace(string(secretData))

	var issuerTLSConfig *tls.Config
	if c.oidcIssuerCA != "" {
		data, err := ioutil.ReadFile(c.oidcIssuerCA)
		if err != nil {
			return errors.Wrap(err, "loading issuer CA")
		}
		rootCAs := x509.NewCertPool()
		if !rootCAs.AppendCertsFromPEM(data) {
			return errors.New("issuer CA file didn't contain any PEM encodec certificates")
		}
		issuerTLSConfig = &tls.Config{RootCAs: rootCAs}
	}

	var kubernetesCA []byte
	if c.kubernetesCA != "" {
		kubernetesCA, err = ioutil.ReadFile(c.kubernetesCA)
		if err != nil {
			return errors.Wrap(err, "reading kubernetes CA file")
		}
	}

	logger := log.New(os.Stderr, "", log.LstdFlags)
	h, err := newServer(&serverConfig{
		clientID:           c.oidcClientID,
		clientSecret:       clientSecret,
		issuer:             c.oidcIssuer,
		issuerTLSConfig:    issuerTLSConfig,
		scopes:             c.oidcScopes,
		redirectURI:        c.oidcRedirectURI,
		kubernetesEndpoint: c.kubernetesEndpoint,
		kubernetesCA:       kubernetesCA,
		logger:             logger,
	})
	if err != nil {
		return errors.New("initializing server")
	}

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
			logger.Printf("serving HTTP at: http://%s", c.httpAddress)
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
			logger.Printf("serving HTTPS at: https://%s", c.httpsAddress)
			return s.ListenAndServeTLS("", "")
		}, func(err error) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
			defer cancel()

			s.Shutdown(ctx)
		})
	}
	return g.Run()
}
