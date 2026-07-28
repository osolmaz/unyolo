// Package appmanifest generates minimum GitHub App permission manifests.
package appmanifest

import (
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"slices"

	"github.com/osolmaz/unyolo/brokers/github/internal/opcatalog"
)

type Profiles struct {
	Version    int                          `json:"version"`
	APIVersion string                       `json:"api_version"`
	Profiles   map[string]map[string]string `json:"profiles"`
}
type Manifest struct {
	APIVersion  string            `json:"api_version"`
	Permissions map[string]string `json:"permissions"`
}

//go:embed profiles.json
var raw []byte

func LoadProfiles() (Profiles, error) {
	var value Profiles
	if err := json.Unmarshal(raw, &value); err != nil {
		return value, err
	}
	if value.Version != 1 || value.APIVersion != "2026-03-10" || len(value.Profiles) != 5 {
		return value, errors.New("GitHub App permission profiles are invalid")
	}
	return value, nil
}

func Minimum(operationNames []string) (Manifest, error) {
	permissions := map[string]string{}
	for _, name := range operationNames {
		descriptor, found := opcatalog.ByName(name)
		if !found {
			return Manifest{}, fmt.Errorf("unknown GitHub operation %q", name)
		}
		if descriptor.CredentialKind != "installation" {
			continue
		}
		for permission, access := range descriptor.RequiredGitHubPermissions {
			if permissions[permission] != "write" || access == "write" {
				permissions[permission] = access
			}
		}
	}
	return Manifest{APIVersion: "2026-03-10", Permissions: permissions}, nil
}

func ProfileNames() ([]string, error) {
	profiles, err := LoadProfiles()
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(profiles.Profiles))
	for name := range profiles.Profiles {
		names = append(names, name)
	}
	slices.Sort(names)
	return names, nil
}
