// Package auth authenticates named broker clients from shared secrets.
package auth

import (
	"encoding/base64"
	"errors"
	"net/http"
	"strings"

	"github.com/osolmaz/brokerkit/internal/secretset"
)

// MinimumSecretBytes is the broker-wide minimum for client and operator
// shared secrets.
const MinimumSecretBytes = 32

var (
	// ErrMissing means no usable credential was presented.
	ErrMissing = errors.New("authentication required")
	// ErrInvalid means a credential was presented but matched no client.
	ErrInvalid = errors.New("invalid credentials")
)

// Options configures an Authenticator.
type Options struct {
	// MinSecretBytes is the minimum accepted client secret length.
	MinSecretBytes int
}

// Authenticator resolves Authorization headers to named clients.
type Authenticator struct {
	clients *secretset.Set
}

// New builds an Authenticator from client id to shared secret.
func New(secrets map[string]string, opts Options) (*Authenticator, error) {
	if opts.MinSecretBytes <= 0 {
		opts.MinSecretBytes = MinimumSecretBytes
	}
	clients, err := secretset.New("client", secrets, opts.MinSecretBytes, nil)
	if err != nil {
		return nil, err
	}
	return &Authenticator{clients: clients}, nil
}

// AuthenticateHeader authenticates one raw Authorization header value.
func (a *Authenticator) AuthenticateHeader(header string) (string, error) {
	secret, ok := SecretFromAuthorization(header)
	if !ok {
		return "", ErrMissing
	}
	return a.authenticateSecret(secret)
}

// AuthenticateRequest authenticates the Authorization header from r.
func (a *Authenticator) AuthenticateRequest(r *http.Request) (string, error) {
	return a.AuthenticateHeader(r.Header.Get("Authorization"))
}

func (a *Authenticator) authenticateSecret(secret string) (string, error) {
	id, ok := a.clients.Match(secret)
	if !ok {
		return "", ErrInvalid
	}
	return id, nil
}

// SecretFromAuthorization extracts a broker secret from Bearer or Basic auth.
func SecretFromAuthorization(header string) (string, bool) {
	scheme, value, ok := strings.Cut(strings.TrimSpace(header), " ")
	if !ok || strings.TrimSpace(value) == "" {
		return "", false
	}
	credential := strings.TrimSpace(value)
	switch {
	case strings.EqualFold(scheme, "Bearer"):
		return credential, true
	case strings.EqualFold(scheme, "Basic"):
		return secretFromBasic(credential)
	default:
		return "", false
	}
}

func secretFromBasic(value string) (string, bool) {
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return "", false
	}
	_, password, ok := strings.Cut(string(decoded), ":")
	return password, ok && password != ""
}
