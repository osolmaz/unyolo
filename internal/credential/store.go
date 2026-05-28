package credential

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sync"
)

var ErrNotFound = errors.New("credential not found")

type SecretSink interface {
	Store(ctx context.Context, secret SecretMaterial) (OpaqueHandle, error)
}

type MetadataStore interface {
	Create(ctx context.Context, metadata Metadata) (Metadata, error)
	Get(ctx context.Context, tenantID string, id string) (Metadata, error)
	List(ctx context.Context, tenantID string) ([]Metadata, error)
}

type DiscardingSecretSink struct{}

func NewDiscardingSecretSink() DiscardingSecretSink {
	return DiscardingSecretSink{}
}

func (DiscardingSecretSink) Store(_ context.Context, secret SecretMaterial) (OpaqueHandle, error) {
	if secret.Empty() {
		return "", errors.New("secret is required")
	}
	handle, err := randomID("opaque")
	if err != nil {
		return "", err
	}
	return OpaqueHandle(handle), nil
}

type MemoryMetadataStore struct {
	mu    sync.RWMutex
	items map[string]Metadata
}

func NewMemoryMetadataStore() *MemoryMetadataStore {
	return &MemoryMetadataStore{
		items: make(map[string]Metadata),
	}
}

func (s *MemoryMetadataStore) Create(_ context.Context, metadata Metadata) (Metadata, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.items[metadata.ID]; exists {
		return Metadata{}, errors.New("credential id already exists")
	}
	metadata.Scopes = copyStrings(metadata.Scopes)
	s.items[metadata.ID] = metadata
	return metadata, nil
}

func (s *MemoryMetadataStore) Get(_ context.Context, tenantID string, id string) (Metadata, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	metadata, exists := s.items[id]
	if !exists || metadata.TenantID != tenantID {
		return Metadata{}, ErrNotFound
	}
	metadata.Scopes = copyStrings(metadata.Scopes)
	return metadata, nil
}

func (s *MemoryMetadataStore) List(_ context.Context, tenantID string) ([]Metadata, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	items := make([]Metadata, 0, len(s.items))
	for _, metadata := range s.items {
		if metadata.TenantID != tenantID {
			continue
		}
		metadata.Scopes = copyStrings(metadata.Scopes)
		items = append(items, metadata)
	}
	return items, nil
}

func randomID(prefix string) (string, error) {
	var bytes [16]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		return "", err
	}
	return prefix + "_" + hex.EncodeToString(bytes[:]), nil
}

func copyStrings(values []string) []string {
	copied := make([]string, len(values))
	copy(copied, values)
	return copied
}
