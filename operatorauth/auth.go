// Package operatorauth authenticates operator identities independently of broker clients.
package operatorauth

import (
	"errors"
	"net/http"

	"github.com/osolmaz/brokerkit/auth"
	"github.com/osolmaz/brokerkit/internal/secretset"
)

const defaultMinSecretBytes = 24

var (
	ErrMissing = errors.New("operator authentication required")
	ErrInvalid = errors.New("invalid operator credentials")
)

// Options configures operator-secret authentication.
type Options struct {
	MinSecretBytes int
	ClientSecrets  map[string]string
}

// Authenticator resolves dedicated operator credentials to stable identities.
type Authenticator struct {
	identities *secretset.Set
}

// New validates operator credentials and rejects reuse of any client secret.
func New(secrets map[string]string, options Options) (*Authenticator, error) {
	if options.MinSecretBytes <= 0 {
		options.MinSecretBytes = defaultMinSecretBytes
	}
	identities, err := secretset.New("operator", secrets, options.MinSecretBytes, secretset.Hashes(options.ClientSecrets))
	if err != nil {
		return nil, err
	}
	return &Authenticator{identities: identities}, nil
}

// AuthenticateRequest authenticates Bearer or Basic operator credentials.
func (a *Authenticator) AuthenticateRequest(request *http.Request) (string, error) {
	secret, ok := auth.SecretFromAuthorization(request.Header.Get("Authorization"))
	if !ok {
		return "", ErrMissing
	}
	id, ok := a.identities.Match(secret)
	if !ok {
		return "", ErrInvalid
	}
	return id, nil
}
