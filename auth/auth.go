// Package auth authenticates named broker clients from shared secrets.
package auth

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

const defaultMinSecretBytes = 16

var (
	// ErrMissing means no usable credential was presented.
	ErrMissing = errors.New("authentication required")
	// ErrInvalid means a credential was presented but matched no client.
	ErrInvalid = errors.New("invalid credentials")
)

// Options configures an Authenticator.
type Options struct {
	// MinSecretBytes is the minimum accepted client secret length. The default
	// is intentionally modest so existing broker deployments can cut over
	// without weakening production guidance.
	MinSecretBytes int
}

type client struct {
	id         string
	secretHash [sha256.Size]byte
}

// Authenticator resolves Authorization headers to named clients.
type Authenticator struct {
	clients []client
}

// New builds an Authenticator from client id to shared secret.
func New(secrets map[string]string, opts Options) (*Authenticator, error) {
	if opts.MinSecretBytes <= 0 {
		opts.MinSecretBytes = defaultMinSecretBytes
	}
	if len(secrets) == 0 {
		return nil, errors.New("at least one client secret is required")
	}
	clients := make([]client, 0, len(secrets))
	seen := make(map[string]struct{}, len(secrets))
	seenSecrets := make(map[[sha256.Size]byte]string, len(secrets))
	for id, secret := range secrets {
		normalizedID := strings.TrimSpace(id)
		if normalizedID == "" {
			return nil, errors.New("client id is required")
		}
		if _, ok := seen[normalizedID]; ok {
			return nil, fmt.Errorf("duplicate client id %q", normalizedID)
		}
		seen[normalizedID] = struct{}{}
		if len(secret) < opts.MinSecretBytes {
			return nil, fmt.Errorf("client %q secret must be at least %d bytes", normalizedID, opts.MinSecretBytes)
		}
		secretHash := sha256.Sum256([]byte(secret))
		if existingID, ok := seenSecrets[secretHash]; ok {
			return nil, fmt.Errorf("client %q secret duplicates client %q", normalizedID, existingID)
		}
		seenSecrets[secretHash] = normalizedID
		clients = append(clients, client{id: normalizedID, secretHash: secretHash})
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
	presented := sha256.Sum256([]byte(secret))
	matched := -1
	for i := range a.clients {
		if subtle.ConstantTimeCompare(presented[:], a.clients[i].secretHash[:]) == 1 {
			matched = i
		}
	}
	if matched < 0 {
		return "", ErrInvalid
	}
	return a.clients[matched].id, nil
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
