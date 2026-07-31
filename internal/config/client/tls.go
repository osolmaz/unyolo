package clientconfig

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"os"

	"github.com/osolmaz/unyolo/transport/endpoint"
)

// HTTPClient returns a client carrying the pinned transport trust for this configuration.
func (client Client) HTTPClient() (*http.Client, error) {
	configuration, err := client.TLSConfig()
	if err != nil {
		return nil, err
	}
	if configuration == nil {
		return nil, nil
	}
	base := http.DefaultTransport.(*http.Transport).Clone()
	base.TLSClientConfig = configuration
	return &http.Client{Transport: base}, nil
}

// TLSConfig returns pinned TLS 1.3 settings for a TLS client endpoint.
func (client Client) TLSConfig() (*tls.Config, error) {
	parsed, err := endpoint.Parse(client.AgentEndpoint, endpoint.ParseOptions{AllowNetworkTLS: true})
	if err != nil {
		return nil, errors.New("broker client endpoint is invalid")
	}
	if parsed.Scheme() != endpoint.SchemeTLS {
		return nil, nil
	}
	if !cleanAbsoluteFile(client.CAFile) || client.ServerName == "" {
		return nil, errors.New("broker TLS client configuration is incomplete")
	}
	info, err := os.Lstat(client.CAFile)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o022 != 0 {
		return nil, errors.New("broker client CA file is unsafe")
	}
	data, err := os.ReadFile(client.CAFile) // #nosec G304 -- absolute protected path from validated client config.
	if err != nil || len(data) == 0 || len(data) > maxClientConfigBytes {
		return nil, errors.New("broker client CA file could not be read")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(data) {
		return nil, errors.New("broker client CA file is invalid")
	}
	return &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, ServerName: client.ServerName}, nil
}
