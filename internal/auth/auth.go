// Package auth checks the broker shared secret on incoming requests.
//
// The secret is accepted as a Bearer token or as the password of HTTP
// Basic auth (the username is ignored), which is how stock git and S3
// tooling present credentials. Comparison is constant-time over SHA-256
// digests so neither timing nor error branches leak which secrets exist.
package auth

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"strings"
)

// Authentication failures. ErrMissing means no credential was presented
// (HTTP 401); ErrInvalid means a credential was presented but matched no
// client (HTTP 403).
var (
	ErrMissing = errors.New("authentication required")
	ErrInvalid = errors.New("invalid credentials")
)

type client struct {
	name       string
	secretHash [sha256.Size]byte
}

// Authenticator resolves presented secrets to client names.
type Authenticator struct {
	clients []client
}

// New builds an Authenticator from (name, secret) pairs.
func New(clients map[string]string) *Authenticator {
	authenticator := &Authenticator{}
	for name, secret := range clients {
		authenticator.clients = append(authenticator.clients, client{
			name:       name,
			secretHash: sha256.Sum256([]byte(secret)),
		})
	}
	return authenticator
}

// Authenticate checks the raw Authorization header value and returns the
// matched client name.
func (a *Authenticator) Authenticate(authorizationHeader string) (string, error) {
	presented, ok := extractSecret(authorizationHeader)
	if !ok {
		return "", ErrMissing
	}
	presentedHash := sha256.Sum256([]byte(presented))
	matchedIndex := -1
	for i := range a.clients {
		if subtle.ConstantTimeCompare(presentedHash[:], a.clients[i].secretHash[:]) == 1 {
			matchedIndex = i
		}
	}
	if matchedIndex < 0 {
		return "", ErrInvalid
	}
	return a.clients[matchedIndex].name, nil
}

// extractSecret pulls the candidate secret out of an Authorization
// header: the Bearer token, or the Basic-auth password.
func extractSecret(header string) (string, bool) {
	scheme, value, found := strings.Cut(header, " ")
	if !found || value == "" {
		return "", false
	}
	switch {
	case strings.EqualFold(scheme, "Bearer"):
		return value, true
	case strings.EqualFold(scheme, "Basic"):
		decoded, err := base64.StdEncoding.DecodeString(value)
		if err != nil {
			return "", false
		}
		_, password, hasPassword := strings.Cut(string(decoded), ":")
		if !hasPassword || password == "" {
			return "", false
		}
		return password, true
	default:
		return "", false
	}
}
