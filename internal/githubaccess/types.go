package githubaccess

import (
	"errors"
	"strings"
	"time"

	"github.com/dutifuldev/gitcba/internal/shared/normalize"
)

type RepositoryRef struct {
	Owner string `json:"owner"`
	Name  string `json:"name"`
}

type ConfigureInput struct {
	CredentialID string
	Owners       []string
	Repositories []RepositoryRef
}

type Selection struct {
	ID           string
	CredentialID string
	Owners       []string
	Repositories []RepositoryRef
	CreatedAt    time.Time
}

type PublicSelection struct {
	ID           string          `json:"id"`
	CredentialID string          `json:"credential_id"`
	Owners       []string        `json:"owners"`
	Repositories []RepositoryRef `json:"repositories"`
	CreatedAt    time.Time       `json:"created_at"`
}

func (s Selection) Public() PublicSelection {
	return PublicSelection{
		ID:           s.ID,
		CredentialID: s.CredentialID,
		Owners:       normalize.Strings(s.Owners),
		Repositories: normalizeRepositories(s.Repositories),
		CreatedAt:    s.CreatedAt,
	}
}

func validateInput(input ConfigureInput) error {
	if strings.TrimSpace(input.CredentialID) == "" {
		return errors.New("credential_id is required")
	}
	owners := normalize.Strings(input.Owners)
	repositories := normalizeRepositories(input.Repositories)
	if len(owners) == 0 && len(repositories) == 0 {
		return errors.New("owners or repositories is required")
	}
	if err := validateOwners(owners); err != nil {
		return err
	}
	return validateRepositories(repositories)
}

func validateOwners(owners []string) error {
	for _, owner := range owners {
		if !validPart(owner) {
			return errors.New("owners must not contain /")
		}
	}
	return nil
}

func validateRepositories(repositories []RepositoryRef) error {
	for _, repository := range repositories {
		if !validPart(repository.Owner) || !validPart(repository.Name) {
			return errors.New("repository owner and name are required and must not contain /")
		}
	}
	return nil
}

func normalizeRepositories(repositories []RepositoryRef) []RepositoryRef {
	seen := make(map[RepositoryRef]struct{}, len(repositories))
	normalized := make([]RepositoryRef, 0, len(repositories))
	for _, repository := range repositories {
		repository = RepositoryRef{
			Owner: strings.TrimSpace(repository.Owner),
			Name:  strings.TrimSpace(repository.Name),
		}
		if repository.Owner == "" || repository.Name == "" {
			continue
		}
		if _, exists := seen[repository]; exists {
			continue
		}
		seen[repository] = struct{}{}
		normalized = append(normalized, repository)
	}
	return normalized
}

func validPart(value string) bool {
	value = strings.TrimSpace(value)
	return value != "" && !strings.Contains(value, "/")
}
