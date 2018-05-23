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
			httpAddress:          v1.HTTPAddress,
			httpsAddress:         v1.HTTPSAddress,
			httpsCertificate:     v1.HTTPSCertificate,
			httpsKey:             v1.HTTPSKey,
			oidcIssuer:           v1.OIDCIssuer,
			oidcIssuerCA:         v1.OIDCIssuerCA,
			oidcClientID:         v1.OIDCClientID,
			oidcClientSecretFile: v1.OIDCClientSecretFile,
			oidcRedirectURI:      v1.OIDCRedirectURI,
			oidcScopes:           v1.OIDCScopes,
			kubernetesEndpoint:   v1.KubernetesEndpoint,
			kubernetesCA:         v1.KubernetesCA,
		}, nil
	}
}

type configV1 struct {
	Version string `json:"version"`

	HTTPAddress string `json:"httpAddress"`

	HTTPSAddress     string `json:"httpsAddress"`
	HTTPSCertificate string `json:"httpsCertificate"`
	HTTPSKey         string `json:"httpsKey"`

	OIDCIssuer   string `json:"oidcIssuer"`
	OIDCIssuerCA string `json:"oidcIssuerCA"`

	OIDCClientID         string `json:"oidcClientID"`
	OIDCClientSecretFile string `json:"oidcClientSecretFile"`

	OIDCRedirectURI string `json:"oidcRedirectURI"`

	OIDCScopes []string `json:"oidcScopes"`

	KubernetesEndpoint string `json:"kubernetesEndpoint"`
	KubernetesCA       string `json:"kubernetesCA"`
}

func (c *configV1) verify() error {
	required := []struct {
		val, name string
	}{
		{c.OIDCIssuer, "oidcIssuer"},
		{c.OIDCClientID, "oidcClientID"},
		{c.OIDCClientSecretFile, "oidcClientSecretFile"},
		{c.OIDCRedirectURI, "oidcRedirectURI"},
	}

	for _, req := range required {
		if req.val == "" {
			return errors.Errorf("missing required config field %s", req.name)
		}
	}

	if c.HTTPAddress == "" && c.HTTPSAddress == "" {
		return errors.New("must specify either httpAddress or httpsAddress")
	}
	if c.HTTPSAddress != "" && (c.HTTPSCertificate == "" || c.HTTPSKey == "") {
		return errors.New("httpsAddress required both httpsCertificate and httpsKey")
	}
	if c.HTTPSAddress == "" && (c.HTTPSCertificate != "" || c.HTTPSKey != "") {
		return errors.New("cannot specify httpsCertificate or httpsKey without httpsAddress")
	}
	return nil
}
