package githubaccess

import (
	"context"
	"strings"
	"time"

	"github.com/dutifuldev/gitcba/internal/shared/id"
	"github.com/dutifuldev/gitcba/internal/shared/normalize"
)

type Service struct {
	store Store
	now   func() time.Time
	newID func() (string, error)
}

func NewService(store Store) *Service {
	return &Service{
		store: store,
		now:   time.Now,
		newID: func() (string, error) {
			return id.New("gha")
		},
	}
}

func (s *Service) Configure(ctx context.Context, input ConfigureInput) (PublicSelection, error) {
	if err := validateInput(input); err != nil {
		return PublicSelection{}, err
	}
	id, err := s.newID()
	if err != nil {
		return PublicSelection{}, err
	}
	selection := Selection{
		ID:           id,
		CredentialID: strings.TrimSpace(input.CredentialID),
		Owners:       normalize.Strings(input.Owners),
		Repositories: normalizeRepositories(input.Repositories),
		CreatedAt:    s.now().UTC(),
	}
	created, err := s.store.Create(ctx, selection)
	if err != nil {
		return PublicSelection{}, err
	}
	return created.Public(), nil
}

func (s *Service) Get(ctx context.Context, id string) (PublicSelection, error) {
	cleanID := strings.TrimSpace(id)
	selection, err := s.store.Get(ctx, cleanID)
	if err != nil {
		return PublicSelection{}, err
	}
	publicSelection := selection.Public()
	return publicSelection, nil
}

func (s *Service) List(ctx context.Context) ([]PublicSelection, error) {
	selections, err := s.store.List(ctx)
	if err != nil {
		return nil, err
	}
	publicSelections := make([]PublicSelection, len(selections))
	for index, selection := range selections {
		publicSelections[index] = selection.Public()
	}
	return publicSelections, nil
}
