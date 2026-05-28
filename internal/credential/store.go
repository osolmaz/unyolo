package credential

import (
	"context"
	"errors"
	"sync"

	"github.com/dutifuldev/gitcba/internal/shared/id"
)

var ErrNotFound = errors.New("credential not found")

type SecretSink interface {
	Store(ctx context.Context, secret SecretMaterial) (OpaqueHandle, error)
}

type MetadataStore interface {
	Create(ctx context.Context, metadata Metadata) (Metadata, error)
	Get(ctx context.Context, id string) (Metadata, error)
	List(ctx context.Context) ([]Metadata, error)
}

type DiscardingSecretSink struct{}

func NewDiscardingSecretSink() DiscardingSecretSink {
	return DiscardingSecretSink{}
}

func (DiscardingSecretSink) Store(_ context.Context, secret SecretMaterial) (OpaqueHandle, error) {
	if secret.Empty() {
		return "", errors.New("secret is required")
	}
	handle, err := id.New("opaque")
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

func (s *MemoryMetadataStore) Get(_ context.Context, id string) (Metadata, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	metadata, exists := s.items[id]
	if !exists {
		return Metadata{}, ErrNotFound
	}
	metadata.Scopes = copyStrings(metadata.Scopes)
	return metadata, nil
}

func (s *MemoryMetadataStore) List(_ context.Context) ([]Metadata, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	items := make([]Metadata, 0, len(s.items))
	for _, metadata := range s.items {
		metadata.Scopes = copyStrings(metadata.Scopes)
		items = append(items, metadata)
	}
	return items, nil
}

func copyStrings(values []string) []string {
	copied := make([]string, len(values))
	copy(copied, values)
	return copied
}
