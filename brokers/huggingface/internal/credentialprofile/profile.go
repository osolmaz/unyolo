// Package credentialprofile owns the upstream Hugging Face credential ceiling
// required by the complete HF Broker operation surface.
package credentialprofile

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"sync"
)

// Requirements is the version-1 machine-readable credential profile.
type Requirements struct {
	Version                   int      `json:"version"`
	ProfileID                 string   `json:"profile_id"`
	TokenFormURL              string   `json:"token_form_url"`
	TokenType                 string   `json:"token_type"`
	RequiresGatedRepositories bool     `json:"requires_gated_repositories"`
	PersonalPermissions       []string `json:"personal_permissions"`
	GlobalPermissions         []string `json:"global_permissions"`
	OrganizationPermissions   []string `json:"organization_permissions"`
}

//go:embed requirements.json
var requirementsJSON []byte

var (
	loadOnce sync.Once
	loaded   Requirements
	loadErr  error
)

// Load returns a validated copy of the embedded requirements.
func Load() (Requirements, error) {
	loadOnce.Do(func() {
		if err := json.Unmarshal(requirementsJSON, &loaded); err != nil {
			loadErr = fmt.Errorf("decode HF credential requirements: %w", err)
			return
		}
		loadErr = Validate(loaded)
	})
	return clone(loaded), loadErr
}

// JSON returns the canonical, newline-terminated document after validation.
func JSON() ([]byte, error) {
	if _, err := Load(); err != nil {
		return nil, err
	}
	return slices.Clone(requirementsJSON), nil
}

// Validate rejects malformed or ambiguous credential profiles.
func Validate(profile Requirements) error {
	if err := validateProfileIdentity(profile); err != nil {
		return err
	}
	if err := validatePermissions("personal_permissions", profile.PersonalPermissions); err != nil {
		return err
	}
	if err := validatePermissions("global_permissions", profile.GlobalPermissions); err != nil {
		return err
	}
	return validatePermissions("organization_permissions", profile.OrganizationPermissions)
}

func validateProfileIdentity(profile Requirements) error {
	return firstError(
		validateVersion(profile.Version),
		validateProfileID(profile.ProfileID),
		validateTokenFormURL(profile.TokenFormURL),
		validateTokenType(profile.TokenType),
		validateGatedRepositories(profile.RequiresGatedRepositories),
	)
}

func validateVersion(version int) error {
	if version != 1 {
		return fmt.Errorf("credential requirements version must be 1")
	}
	return nil
}

func validateProfileID(profileID string) error {
	if strings.TrimSpace(profileID) == "" {
		return fmt.Errorf("credential requirements profile_id is required")
	}
	return nil
}

func validateTokenFormURL(endpoint string) error {
	if endpoint != "https://huggingface.co/settings/tokens/new" {
		return fmt.Errorf("credential requirements token_form_url must be the Hugging Face HTTPS token form")
	}
	return nil
}

func validateTokenType(tokenType string) error {
	if tokenType != "fineGrained" {
		return fmt.Errorf("credential requirements token_type must be fineGrained")
	}
	return nil
}

func validateGatedRepositories(required bool) error {
	if !required {
		return fmt.Errorf("credential requirements must require gated repository access")
	}
	return nil
}

func firstError(values ...error) error {
	for _, err := range values {
		if err != nil {
			return err
		}
	}
	return nil
}

func validatePermissions(name string, permissions []string) error {
	if len(permissions) == 0 {
		return fmt.Errorf("credential requirements %s must not be empty", name)
	}
	if !slices.IsSorted(permissions) {
		return fmt.Errorf("credential requirements %s must be sorted", name)
	}
	for index, permission := range permissions {
		if index > 0 && permissions[index-1] == permission {
			return fmt.Errorf("credential requirements %s contains duplicate %q", name, permission)
		}
		if err := validatePermission(name, permission); err != nil {
			return err
		}
	}
	return nil
}

func validatePermission(name, permission string) error {
	if strings.TrimSpace(permission) != permission || permission == "" {
		return fmt.Errorf("credential requirements %s contains an invalid permission", name)
	}
	return nil
}

func clone(profile Requirements) Requirements {
	profile.PersonalPermissions = slices.Clone(profile.PersonalPermissions)
	profile.GlobalPermissions = slices.Clone(profile.GlobalPermissions)
	profile.OrganizationPermissions = slices.Clone(profile.OrganizationPermissions)
	return profile
}
