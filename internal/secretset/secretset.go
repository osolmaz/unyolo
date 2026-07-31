// Package secretset validates and matches named shared-secret identities.
package secretset

import (
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

type identity struct {
	id         string
	secretHash [sha256.Size]byte
}

// Set is one immutable named-secret registry.
type Set struct {
	identities []identity
}

// New validates unique names and secrets, rejecting hashes in forbidden.
func New(kind string, secrets map[string]string, minBytes int, forbidden map[[sha256.Size]byte]struct{}) (*Set, error) {
	return newSet(kind, secrets, minBytes, forbidden, false)
}

// NewAllowEmpty validates a store that intentionally starts without identities.
func NewAllowEmpty(kind string, secrets map[string]string, minBytes int, forbidden map[[sha256.Size]byte]struct{}) (*Set, error) {
	return newSet(kind, secrets, minBytes, forbidden, true)
}

func newSet(kind string, secrets map[string]string, minBytes int, forbidden map[[sha256.Size]byte]struct{}, allowEmpty bool) (*Set, error) {
	if len(secrets) == 0 && !allowEmpty {
		return nil, fmt.Errorf("at least one %s secret is required", kind)
	}
	seenIDs := make(map[string]struct{}, len(secrets))
	seenSecrets := make(map[[sha256.Size]byte]string, len(secrets))
	identities := make([]identity, 0, len(secrets))
	for id, secret := range secrets {
		normalizedID := strings.TrimSpace(id)
		if !validID(normalizedID) {
			return nil, fmt.Errorf("%s id is required", kind)
		}
		if _, exists := seenIDs[normalizedID]; exists {
			return nil, fmt.Errorf("duplicate %s id %q", kind, normalizedID)
		}
		seenIDs[normalizedID] = struct{}{}
		if len(secret) < minBytes {
			return nil, fmt.Errorf("%s %q secret must be at least %d bytes", kind, normalizedID, minBytes)
		}
		hash := sha256.Sum256([]byte(secret))
		if _, reused := forbidden[hash]; reused {
			return nil, fmt.Errorf("%s %q secret reuses a forbidden secret", kind, normalizedID)
		}
		if existing, duplicate := seenSecrets[hash]; duplicate {
			return nil, fmt.Errorf("%s %q secret duplicates %s %q", kind, normalizedID, kind, existing)
		}
		seenSecrets[hash] = normalizedID
		identities = append(identities, identity{id: normalizedID, secretHash: hash})
	}
	return &Set{identities: identities}, nil
}

func validID(id string) bool {
	if id == "" || len(id) > 200 || !utf8.ValidString(id) {
		return false
	}
	for _, char := range id {
		if unicode.IsControl(char) {
			return false
		}
	}
	return true
}

// Match resolves a secret using constant-time hash comparisons.
func (s *Set) Match(secret string) (string, bool) {
	presented := sha256.Sum256([]byte(secret))
	matched := -1
	for index := range s.identities {
		if subtle.ConstantTimeCompare(presented[:], s.identities[index].secretHash[:]) == 1 {
			matched = index
		}
	}
	if matched < 0 {
		return "", false
	}
	return s.identities[matched].id, true
}

// Hashes returns the unique hashes of a secret map for domain separation.
func Hashes(secrets map[string]string) map[[sha256.Size]byte]struct{} {
	out := make(map[[sha256.Size]byte]struct{}, len(secrets))
	for _, secret := range secrets {
		out[sha256.Sum256([]byte(secret))] = struct{}{}
	}
	return out
}
