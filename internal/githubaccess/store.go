package githubaccess

import (
	"context"
	"errors"
	"sync"

	"github.com/dutifuldev/gitcba/internal/shared/normalize"
)

var ErrNotFound = errors.New("github access selection not found")

type Store interface {
	Create(ctx context.Context, selection Selection) (Selection, error)
	Get(ctx context.Context, id string) (Selection, error)
	List(ctx context.Context) ([]Selection, error)
}

type MemoryStore struct {
	mu    sync.RWMutex
	items map[string]Selection
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		items: make(map[string]Selection),
	}
}

func (s *MemoryStore) Create(_ context.Context, selection Selection) (Selection, error) {
	selection = normalizeSelection(selection)
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.items[selection.ID]; exists {
		return Selection{}, errors.New("github access selection id already exists")
	}
	s.items[selection.ID] = selection
	return selection, nil
}

func (s *MemoryStore) Get(_ context.Context, id string) (Selection, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	selection, exists := s.items[id]
	if !exists {
		return Selection{}, ErrNotFound
	}
	return normalizeSelection(selection), nil
}

func (s *MemoryStore) List(_ context.Context) ([]Selection, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	selections := make([]Selection, 0, len(s.items))
	for _, selection := range s.items {
		selections = append(selections, normalizeSelection(selection))
	}
	return selections, nil
}

func normalizeSelection(selection Selection) Selection {
	selection.Owners = normalize.Strings(selection.Owners)
	selection.Repositories = normalizeRepositories(selection.Repositories)
	return selection
}
