// Package auth adapts brokerkit shared-secret authentication to hf-broker.
package auth

import bkauth "github.com/osolmaz/brokerkit/auth"

const minSecretBytes = 32

var (
	ErrMissing = bkauth.ErrMissing
	ErrInvalid = bkauth.ErrInvalid
)

// Authenticator resolves presented secrets to client names.
type Authenticator struct {
	inner *bkauth.Authenticator
}

// New builds an Authenticator from already validated client secrets.
func New(clients map[string]string) *Authenticator {
	inner, err := bkauth.New(clients, bkauth.Options{MinSecretBytes: minSecretBytes})
	if err != nil {
		panic(err)
	}
	return &Authenticator{inner: inner}
}

// Authenticate checks the raw Authorization header value and returns the
// matched client name.
func (a *Authenticator) Authenticate(authorizationHeader string) (string, error) {
	return a.inner.AuthenticateHeader(authorizationHeader)
}
