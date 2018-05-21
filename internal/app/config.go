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

	oidcIssuer string
	oidcCA     string

	oidcUsernameClaim string
	oidcGroupsClaim   string

	oidcAllowedClientID string

	kubeconfig string
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
			httpAddress:         v1.HTTPAddress,
			httpsAddress:        v1.HTTPSAddress,
			httpsCertificate:    v1.HTTPSCertificate,
			httpsKey:            v1.HTTPSKey,
			oidcIssuer:          v1.OIDCIssuer,
			oidcCA:              v1.OIDCCA,
			oidcUsernameClaim:   v1.OIDCUsernameClaim,
			oidcGroupsClaim:     v1.OIDCGroupsClaim,
			oidcAllowedClientID: v1.OIDCAllowedClientID,
			kubeconfig:          v1.Kubeconfig,
		}, nil
	}
}

type configV1 struct {
	// version defined here to ensure
	Version string `json:"version"`

	HTTPAddress string `json:"httpAddress"`

	HTTPSAddress     string `json:"httpsAddress"`
	HTTPSCertificate string `json:"httpsCertificate"`
	HTTPSKey         string `json:"httpsKey"`

	OIDCIssuer string `json:"oidcIssuer"`
	OIDCCA     string `json:"oidcCA"`

	OIDCUsernameClaim string `json:"oidcUsernameClaim"`
	OIDCGroupsClaim   string `json:"oidcGroupsClaim"`

	OIDCAllowedClientID string `json:"oidcAllowedClientID"`

	Kubeconfig string `json:"kubeconfig"`
}

func (c *configV1) verify() error {
	required := []struct {
		val, name string
	}{
		{c.OIDCIssuer, "oidcIssuer"},
		{c.OIDCUsernameClaim, "oidcUsernameClaim"},
		{c.OIDCAllowedClientID, "oidcAllowedClientID"},
		{c.Kubeconfig, "kubeconfig"},
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
