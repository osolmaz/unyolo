package credential

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/dutifuldev/gitcba/internal/shared/id"
)

type Service struct {
	secrets SecretSink
	store   MetadataStore
	now     func() time.Time
	newID   func() (string, error)
}

func NewService(secrets SecretSink, store MetadataStore) *Service {
	return &Service{
		secrets: secrets,
		store:   store,
		now:     time.Now,
		newID: func() (string, error) {
			return id.New("cred")
		},
	}
}

func (s *Service) Register(ctx context.Context, input RegisterInput) (PublicMetadata, error) {
	defer input.Secret.Zero()
	if err := validateRegisterInput(input); err != nil {
		return PublicMetadata{}, err
	}
	handle, err := s.secrets.Store(ctx, input.Secret)
	if err != nil {
		return PublicMetadata{}, err
	}
	id, err := s.newID()
	if err != nil {
		return PublicMetadata{}, err
	}
	metadata := Metadata{
		ID:           id,
		TenantID:     strings.TrimSpace(input.TenantID),
		Name:         strings.TrimSpace(input.Name),
		Kind:         input.Kind,
		Scopes:       NormalizeScopes(input.Scopes),
		Fingerprint:  input.Secret.Fingerprint(),
		SecretHandle: handle,
		CreatedAt:    s.now().UTC(),
	}
	created, err := s.store.Create(ctx, metadata)
	if err != nil {
		return PublicMetadata{}, err
	}
	return created.Public(), nil
}

func (s *Service) Get(ctx context.Context, tenantID string, id string) (PublicMetadata, error) {
	metadata, err := s.store.Get(ctx, strings.TrimSpace(tenantID), strings.TrimSpace(id))
	if err != nil {
		return PublicMetadata{}, err
	}
	return metadata.Public(), nil
}

func (s *Service) List(ctx context.Context, tenantID string) ([]PublicMetadata, error) {
	records, err := s.store.List(ctx, strings.TrimSpace(tenantID))
	if err != nil {
		return nil, err
	}
	publicRecords := make([]PublicMetadata, 0, len(records))
	for _, record := range records {
		publicRecords = append(publicRecords, record.Public())
	}
	return publicRecords, nil
}

func validateRegisterInput(input RegisterInput) error {
	if strings.TrimSpace(input.TenantID) == "" {
		return errors.New("tenant_id is required")
	}
	if strings.TrimSpace(input.Name) == "" {
		return errors.New("name is required")
	}
	if err := ValidateKind(input.Kind); err != nil {
		return err
	}
	if input.Secret.Empty() {
		return errors.New("secret is required")
	}
	return nil
}
