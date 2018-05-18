package kubeconfig

import (
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
	"net/http"
	"os"
	"strings"

	"github.com/ghodss/yaml"
	"github.com/pkg/errors"
)

// Config represents a Kubernetes client configuration
type Config struct {
	// Endpoint is the URL of the API server
	Endpoint string
	// Auth configures client credential headers on a HTTP request
	Auth func(r *http.Request)
	// TLS client config to connect to the API server
	TLSConfig *tls.Config
}

// Load reads a kubeconfig file from disk, loads any referenced credentials or
// certificates, and determines the config's active context.
func Load(path string) (*Config, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, errors.Wrap(err, "reading kubeconfig")
	}
	k, err := parse(data)
	if err != nil {
		return nil, errors.Wrap(err, "parsing kubeconfig")
	}
	u, c, err := getCurrentContext(k)
	if err != nil {
		return nil, errors.Wrap(err, "evaluting current context")
	}
	return load(u, c)
}

// LoadInCluster loads the service account credentials of a Kubernetes Pod.
func LoadInCluster() (*Config, error) {
	host := os.Getenv("KUBERNETES_SERVICE_HOST")
	port := os.Getenv("KUBERNETES_SERVICE_PORT")

	if len(host) == 0 || len(port) == 0 {
		return nil, errors.New("unable to load in-cluster configuration, KUBERNETES_SERVICE_HOST and KUBERNETES_SERVICE_PORT must be defined")
	}
	return load(
		&user{
			TokenFile: "/var/run/secrets/kubernetes.io/serviceaccount/token",
		},
		&cluster{
			Server: "https://" + host + ":" + port,
			CA:     "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt",
		},
	)
}

type credentials struct {
	bearerToken string
	username    string
	password    string
}

func (c *credentials) set(r *http.Request) {
	if c.bearerToken != "" {
		r.Header.Set("Authorization", "Bearer "+c.bearerToken)
	}
	if c.username != "" {
		r.SetBasicAuth(c.username, c.password)
	}
}

func load(u *user, c *cluster) (*Config, error) {
	// Quick checks first
	if c.Server == "" {
		return nil, errors.New("cluster has no server address")
	}
	if (u.Username == "") != (u.Password == "") {
		return nil, errors.New("must specify both username and password")
	}

	// Load certs
	ca, err := inlineOrLoad(c.CAData, c.CA)
	if err != nil {
		return nil, errors.Wrap(err, "loading certificate authority")
	}
	clientCert, err := inlineOrLoad(u.ClientCertData, u.ClientCert)
	if err != nil {
		return nil, errors.Wrap(err, "loading client cert")
	}
	clientKey, err := inlineOrLoad(u.ClientKeyData, u.ClientKey)
	if err != nil {
		return nil, errors.Wrap(err, "loading client key")
	}

	token := u.Token
	if u.TokenFile != "" {
		if token != "" {
			return nil, errors.New("cannot specify both token and token file")
		}
		data, err := ioutil.ReadFile(u.TokenFile)
		if err != nil {
			return nil, errors.Wrap(err, "read token file")
		}
		token = strings.TrimSpace(string(data))
	}

	if (len(clientKey) == 0) != (len(clientCert) == 0) {
		return nil, errors.New("must specify both client cert and key")
	}

	tlsConfig := &tls.Config{
		InsecureSkipVerify: c.InsecureSkipVerify,
	}
	if len(ca) > 0 {
		certPool := x509.NewCertPool()
		if !certPool.AppendCertsFromPEM(ca) {
			return nil, errors.New("certificate authority didn't contain any PEM encoded certificates")
		}
		tlsConfig.RootCAs = certPool
	}

	if len(clientKey) > 0 {
		cert, err := tls.X509KeyPair(clientCert, clientKey)
		if err != nil {
			return nil, errors.Wrap(err, "invalid client cert and key combinatoin")
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}

	creds := credentials{token, u.Username, u.Password}

	return &Config{
		Endpoint:  c.Server,
		TLSConfig: tlsConfig,
		Auth:      creds.set,
	}, nil
}

func parse(b []byte) (*kubeconfig, error) {
	var k kubeconfig
	err := yaml.Unmarshal(b, &k)
	return &k, err
}

func inlineOrLoad(b []byte, file string) ([]byte, error) {
	if len(b) > 0 && file != "" {
		return nil, errors.New("cannot provide both inline data and a file")
	}
	if len(b) > 0 {
		return b, nil
	}
	if file != "" {
		return ioutil.ReadFile(file)
	}
	return nil, nil
}

type namedCluster struct {
	Name    string  `json:"name"`
	Cluster cluster `json:"cluster"`
}

type namedUser struct {
	Name string `json:"name"`
	User user   `json:"user"`
}

type namedContext struct {
	Name    string  `json:"name"`
	Context context `json:"context"`
}

type kubeconfig struct {
	Clusters       []namedCluster `json:"clusters"`
	Users          []namedUser    `json:"users"`
	Contexts       []namedContext `json:"contexts"`
	CurrentContext string         `json:"current-context"`
}

type user struct {
	ClientCert     string `json:"client-certificate"`
	ClientKey      string `json:"client-key"`
	ClientCertData []byte `json:"client-certificate-data"`
	ClientKeyData  []byte `json:"client-key-data"`
	Username       string `json:"username"`
	Password       string `json:"password"`
	Token          string `json:"token"`
	TokenFile      string `json:"tokenFile"`
}

type cluster struct {
	InsecureSkipVerify bool   `json:"insecure-skip-tls-verify"`
	Server             string `json:"server"`
	CA                 string `json:"certificate-authority"`
	CAData             []byte `json:"certificate-authority-data"`
}

type context struct {
	Cluster string `json:"cluster"`
	User    string `json:"user"`
}

func getCurrentContext(k *kubeconfig) (*user, *cluster, error) {
	if k.CurrentContext == "" {
		if len(k.Contexts) == 1 {
			u, c, err := getContext(k, k.Contexts[0].Context)
			if err != nil {
				return nil, nil, errors.Wrapf(err, "get context %s", k.Contexts[0].Name)
			}
			return u, c, nil
		}

		if len(k.Users) == 1 && len(k.Clusters) == 1 {
			return &k.Users[0].User, &k.Clusters[0].Cluster, nil
		}
		return nil, nil, errors.Errorf("no current context")
	}

	for _, ctx := range k.Contexts {
		if ctx.Name != k.CurrentContext {
			continue
		}

		u, c, err := getContext(k, ctx.Context)
		if err != nil {
			return nil, nil, errors.Wrapf(err, "get context %s", k.CurrentContext)
		}
		return u, c, nil
	}
	return nil, nil, errors.Errorf("no context with name: %s", k.CurrentContext)
}

func getContext(k *kubeconfig, ctx context) (*user, *cluster, error) {
	if ctx.Cluster == "" {
		return nil, nil, errors.Errorf("context doesn't specify a cluster")
	}
	if ctx.User == "" {
		return nil, nil, errors.Errorf("context doesn't specify a user")
	}

	var (
		u *user
		c *cluster
	)

	for _, user := range k.Users {
		if user.Name == ctx.User {
			u = &user.User
		}
		break
	}
	if u == nil {
		return nil, nil, errors.Errorf("user %s doesn't exist", ctx.User)
	}

	for _, cluster := range k.Clusters {
		if cluster.Name == ctx.Cluster {
			c = &cluster.Cluster
		}
		break
	}
	if c == nil {
		return nil, nil, errors.Errorf("cluster %s doesn't exist", ctx.Cluster)
	}
	return u, c, nil
}
