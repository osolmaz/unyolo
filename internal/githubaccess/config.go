package githubaccess

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/dutifuldev/gitcba/internal/shared/normalize"
)

type RepositoryRef struct {
	Owner string `json:"owner"`
	Name  string `json:"name"`
}

type Config struct {
	Owners                []string        `json:"owners"`
	Repositories          []RepositoryRef `json:"repositories"`
	WritableBranchOwners  []string        `json:"writable_branch_owners"`
	ForcePushBranchOwners []string        `json:"force_push_branch_owners"`
}

func LoadFile(path string) (Config, error) {
	// #nosec G304 -- this is the explicit operator-managed config file path, not request input.
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read github access file: %w", err)
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return Config{}, fmt.Errorf("parse github access file: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg.Normalized(), nil
}

func (c Config) Validate() error {
	normalized := c.Normalized()
	if len(normalized.Owners) == 0 && len(normalized.Repositories) == 0 {
		return errors.New("github access file must include owners or repositories")
	}
	if err := validateOwners(normalized.Owners, "github access owners must not contain /"); err != nil {
		return err
	}
	if err := validateRepositories(normalized.Repositories); err != nil {
		return err
	}
	if err := validateOwners(normalized.WritableBranchOwners, "github access writable branch owners must not contain /"); err != nil {
		return err
	}
	if err := validateOwners(normalized.ForcePushBranchOwners, "github access force-push branch owners must not contain /"); err != nil {
		return err
	}
	return nil
}

func validateRepositories(repositories []RepositoryRef) error {
	for _, repository := range repositories {
		if !validPart(repository.Owner) || !validPart(repository.Name) {
			return errors.New("github access repository owner and name are required and must not contain /")
		}
	}
	return nil
}

func (c Config) Normalized() Config {
	return Config{
		Owners:                normalize.Strings(c.Owners),
		Repositories:          normalizeRepositories(c.Repositories),
		WritableBranchOwners:  normalize.Strings(c.WritableBranchOwners),
		ForcePushBranchOwners: normalize.Strings(c.ForcePushBranchOwners),
	}
}

func (c Config) Allows(owner string, name string) bool {
	owner = strings.TrimSpace(owner)
	name = strings.TrimSpace(name)
	if owner == "" || name == "" {
		return false
	}
	for _, allowedOwner := range normalize.Strings(c.Owners) {
		if owner == allowedOwner {
			return true
		}
	}
	for _, repository := range normalizeRepositories(c.Repositories) {
		if repository.Owner == owner && repository.Name == name {
			return true
		}
	}
	return false
}

func (c Config) CanPushBranch(owner string) bool {
	return containsOwner(c.WritableBranchOwners, owner)
}

func (c Config) CanForcePushBranch(owner string) bool {
	return containsOwner(c.ForcePushBranchOwners, owner)
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

func validateOwners(owners []string, message string) error {
	for _, owner := range owners {
		if !validPart(owner) {
			return errors.New(message)
		}
	}
	return nil
}

func containsOwner(owners []string, owner string) bool {
	owner = strings.TrimSpace(owner)
	if owner == "" {
		return false
	}
	for _, allowedOwner := range normalize.Strings(owners) {
		if owner == allowedOwner {
			return true
		}
	}
	return false
}
