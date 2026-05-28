package policy

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/dutifuldev/gitcba/internal/shared/id"
)

type Service struct {
	store RepositoryStore
	now   func() time.Time
	newID func() (string, error)
}

func NewService(store RepositoryStore) *Service {
	return &Service{
		store: store,
		now:   time.Now,
		newID: func() (string, error) {
			return id.New("repo")
		},
	}
}

func (s *Service) Configure(ctx context.Context, input RepositoryInput) (PublicRepository, error) {
	if err := validateRepositoryInput(input); err != nil {
		return PublicRepository{}, err
	}
	id, err := s.newID()
	if err != nil {
		return PublicRepository{}, err
	}
	repository := Repository{
		ID:           id,
		TenantID:     strings.TrimSpace(input.TenantID),
		Owner:        strings.TrimSpace(input.Owner),
		Name:         strings.TrimSpace(input.Name),
		Private:      input.Private,
		CredentialID: strings.TrimSpace(input.CredentialID),
		Policy:       input.Policy.Clone(),
		CreatedAt:    s.now().UTC(),
	}
	created, err := s.store.Create(ctx, repository)
	if err != nil {
		return PublicRepository{}, err
	}
	return created.Public(), nil
}

func (s *Service) Get(ctx context.Context, tenantID string, id string) (PublicRepository, error) {
	cleanTenant := strings.TrimSpace(tenantID)
	cleanID := strings.TrimSpace(id)
	repository, err := s.store.Get(ctx, cleanTenant, cleanID)
	if err != nil {
		return PublicRepository{}, err
	}
	publicRepository := repository.Public()
	return publicRepository, nil
}

func (s *Service) List(ctx context.Context, tenantID string) ([]PublicRepository, error) {
	repositories, err := s.store.List(ctx, strings.TrimSpace(tenantID))
	if err != nil {
		return nil, err
	}
	publicRepositories := make([]PublicRepository, len(repositories))
	for index, repository := range repositories {
		publicRepositories[index] = repository.Public()
	}
	return publicRepositories, nil
}

func validateRepositoryInput(input RepositoryInput) error {
	if strings.TrimSpace(input.TenantID) == "" {
		return errors.New("tenant_id is required")
	}
	if !validRepoPart(input.Owner) {
		return errors.New("owner is required and must not contain /")
	}
	if !validRepoPart(input.Name) {
		return errors.New("name is required and must not contain /")
	}
	if strings.TrimSpace(input.CredentialID) == "" {
		return errors.New("credential_id is required")
	}
	return input.Policy.Validate()
}

func validRepoPart(value string) bool {
	value = strings.TrimSpace(value)
	return value != "" && !strings.Contains(value, "/")
}
