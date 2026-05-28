package policy

import (
	"context"
	"errors"
	"sync"
)

var ErrNotFound = errors.New("repository not found")

type RepositoryStore interface {
	Create(ctx context.Context, repository Repository) (Repository, error)
	Get(ctx context.Context, tenantID string, id string) (Repository, error)
	List(ctx context.Context, tenantID string) ([]Repository, error)
}

type MemoryRepositoryStore struct {
	mu    sync.RWMutex
	items map[string]Repository
}

func NewMemoryRepositoryStore() *MemoryRepositoryStore {
	return &MemoryRepositoryStore{
		items: make(map[string]Repository),
	}
}

func (s *MemoryRepositoryStore) Create(_ context.Context, repository Repository) (Repository, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.items[repository.ID]; exists {
		return Repository{}, errors.New("repository id already exists")
	}
	repository.Policy = repository.Policy.Clone()
	s.items[repository.ID] = repository
	return repository, nil
}

func (s *MemoryRepositoryStore) Get(_ context.Context, tenantID string, id string) (Repository, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	repository, exists := s.items[id]
	if !exists || repository.TenantID != tenantID {
		return Repository{}, ErrNotFound
	}
	repository.Policy = repository.Policy.Clone()
	return repository, nil
}

func (s *MemoryRepositoryStore) List(_ context.Context, tenantID string) ([]Repository, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	repositories := make([]Repository, 0, len(s.items))
	for _, repository := range s.items {
		if repository.TenantID != tenantID {
			continue
		}
		repository.Policy = repository.Policy.Clone()
		repositories = append(repositories, repository)
	}
	return repositories, nil
}
