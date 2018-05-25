package app

import (
	"bytes"
	"encoding/json"

	"github.com/ghodss/yaml"
	"github.com/pkg/errors"
)

type config struct {
	httpAddress string

	httpsAddress     string
	httpsCertificate string
	httpsKey         string

	oidcIssuer   string
	oidcIssuerCA string

	oidcClientID         string
	oidcClientSecretFile string

	oidcRedirectURI string

	oidcScopes []string

	kubernetesEndpoint string
	kubernetesCA       string
}

func parseConfig(b []byte) (*config, error) {
	jsonData, err := yaml.YAMLToJSON(b)
	if err != nil {
		return nil, errors.Wrap(err, "parsing config yaml")
	}

	var v struct {
		Version string `json:"version"`
	}
	if err := json.Unmarshal(jsonData, &v); err != nil {
		return nil, errors.Wrap(err, "parsing config version")
	}

	switch v.Version {
	case "":
		return nil, errors.New("no config version provided")
	default:
		return nil, errors.Errorf("unrecognized config version provided: %s", v.Version)
	case "v1":
		decoder := json.NewDecoder(bytes.NewReader(jsonData))
		decoder.DisallowUnknownFields()

		var v1 configV1
		if err := decoder.Decode(&v1); err != nil {
			return nil, errors.Wrap(err, "parsing v1 config")
		}
		if err := v1.verify(); err != nil {
			return nil, errors.Wrap(err, "invalid v1 config")
		}
		return &config{
			httpAddress:          v1.Web.HTTP,
			httpsAddress:         v1.Web.HTTPS,
			httpsCertificate:     v1.Web.HTTPSCert,
			httpsKey:             v1.Web.HTTPSKey,
			oidcIssuer:           v1.OIDC.Issuer,
			oidcIssuerCA:         v1.OIDC.IssuerCA,
			oidcClientID:         v1.OIDC.ClientID,
			oidcClientSecretFile: v1.OIDC.ClientSecretFile,
			oidcRedirectURI:      v1.OIDC.RedirectURI,
			oidcScopes:           v1.OIDC.Scopes,
			kubernetesEndpoint:   v1.Kubernetes.APIServer,
			kubernetesCA:         v1.Kubernetes.APIServerCA,
		}, nil
	}
}

type configV1 struct {
	Version string `json:"version"`

	Web struct {
		HTTP      string `json:"http"`
		HTTPS     string `json:"https"`
		HTTPSCert string `json:"httpsCert"`
		HTTPSKey  string `json:"httpsKey"`
	} `json:"web"`

	OIDC struct {
		Issuer   string `json:"issuer"`
		IssuerCA string `json:"issuerCA"`

		ClientID         string `json:"clientID"`
		ClientSecretFile string `json:"clientSecretFile"`

		RedirectURI string `json:"redirectURI"`

		Scopes []string `json:"scopes"`
	} `json:"oidc"`

	Kubernetes struct {
		APIServer   string `json:"apiServer"`
		APIServerCA string `json:"apiServerCA"`
	} `json:"kubernetes"`
}

func (c *configV1) verify() error {
	required := []struct {
		val, name string
	}{
		{c.OIDC.Issuer, "oidc.issuer"},
		{c.OIDC.ClientID, "oidc.clientID"},
		{c.OIDC.ClientSecretFile, "oidc.clientSecretFile"},
		{c.OIDC.RedirectURI, "oidc.redirectURI"},
		{c.Kubernetes.APIServer, "kubernetes.apiServer"},
	}

	for _, req := range required {
		if req.val == "" {
			return errors.Errorf("missing required config field %s", req.name)
		}
	}

	if c.Web.HTTP == "" && c.Web.HTTPS == "" {
		return errors.New("must specify either web.http or web.https")
	}
	if c.Web.HTTPS != "" && (c.Web.HTTPSCert == "" || c.Web.HTTPSKey == "") {
		return errors.New("web.https requires both web.httpsCert and web.httpsKey")
	}
	if c.Web.HTTPS == "" && (c.Web.HTTPSCert != "" || c.Web.HTTPSKey != "") {
		return errors.New("cannot specify web.httpsCert or web.httpsKey without web.https")
	}
	return nil
}
