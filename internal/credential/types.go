package credential

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	"github.com/dutifuldev/gitcba/internal/shared/normalize"
)

type Kind string

const (
	KindGitHubToken Kind = "github_token"
)

type SecretMaterial struct {
	value []byte
}

func NewSecretMaterial(raw string) (SecretMaterial, error) {
	if raw == "" {
		return SecretMaterial{}, errors.New("secret is required")
	}
	return SecretMaterial{value: []byte(raw)}, nil
}

func (s SecretMaterial) CloneBytes() []byte {
	clone := make([]byte, len(s.value))
	copy(clone, s.value)
	return clone
}

func (s SecretMaterial) Fingerprint() string {
	sum := sha256.Sum256(s.value)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func (s SecretMaterial) Empty() bool {
	return len(s.value) == 0
}

func (s SecretMaterial) Zero() {
	for index := range s.value {
		s.value[index] = 0
	}
}

type OpaqueHandle string

type RegisterInput struct {
	TenantID string
	Name     string
	Kind     Kind
	Secret   SecretMaterial
	Scopes   []string
}

type Metadata struct {
	ID           string
	TenantID     string
	Name         string
	Kind         Kind
	Scopes       []string
	Fingerprint  string
	SecretHandle OpaqueHandle
	CreatedAt    time.Time
}

type PublicMetadata struct {
	ID          string    `json:"id"`
	TenantID    string    `json:"tenant_id"`
	Name        string    `json:"name"`
	Kind        Kind      `json:"kind"`
	Scopes      []string  `json:"scopes"`
	Fingerprint string    `json:"fingerprint"`
	CreatedAt   time.Time `json:"created_at"`
}

func (m Metadata) Public() PublicMetadata {
	scopes := make([]string, len(m.Scopes))
	copy(scopes, m.Scopes)
	return PublicMetadata{
		ID:          m.ID,
		TenantID:    m.TenantID,
		Name:        m.Name,
		Kind:        m.Kind,
		Scopes:      scopes,
		Fingerprint: m.Fingerprint,
		CreatedAt:   m.CreatedAt,
	}
}

func NormalizeScopes(scopes []string) []string {
	return normalize.Strings(scopes)
}

func ValidateKind(kind Kind) error {
	switch kind {
	case KindGitHubToken:
		return nil
	default:
		return errors.New("unsupported credential kind")
	}
}
