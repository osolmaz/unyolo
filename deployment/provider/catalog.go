// Package provider loads provider-neutral guided setup choices from a verified release.
package provider

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"

	"github.com/osolmaz/unyolo/internal/strictjson"
)

const APIVersion = "unyolo.io/setup-provider/v1"

var idPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$`)

// Option is one release-declared component available to guided setup.
type Option struct {
	APIVersion string `json:"api_version"`
	ID         string `json:"id"`
	Label      string `json:"label"`
	Hint       string `json:"hint,omitempty"`
	Selected   bool   `json:"selected"`
}

// LoadDirectory loads and validates every provider option in a verified staging directory.
func LoadDirectory(root string) ([]Option, error) {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return nil, errors.New("provider catalog directory must be absolute and clean")
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, fmt.Errorf("read provider catalog: %w", err)
	}
	options := make([]Option, 0, len(entries))
	seen := map[string]bool{}
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			return nil, errors.New("provider catalog contains an unexpected entry")
		}
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() > 16*1024 {
			return nil, errors.New("provider catalog entry is not a bounded regular file")
		}
		data, err := os.ReadFile(filepath.Join(root, entry.Name())) // #nosec G304 -- entry is a direct regular child of the validated root.
		if err != nil {
			return nil, err
		}
		var option Option
		if err := strictjson.Decode(data, &option, true); err != nil {
			return nil, fmt.Errorf("decode provider catalog entry %q: %w", entry.Name(), err)
		}
		if err := option.validate(); err != nil {
			return nil, fmt.Errorf("provider catalog entry %q: %w", entry.Name(), err)
		}
		if seen[option.ID] {
			return nil, fmt.Errorf("provider %q is duplicated", option.ID)
		}
		seen[option.ID] = true
		options = append(options, option)
	}
	if len(options) == 0 || len(options) > 32 {
		return nil, errors.New("provider catalog must contain 1 to 32 entries")
	}
	slices.SortFunc(options, func(a, b Option) int {
		if a.Selected != b.Selected {
			if a.Selected {
				return -1
			}
			return 1
		}
		if a.Label < b.Label {
			return -1
		}
		if a.Label > b.Label {
			return 1
		}
		return 0
	})
	return options, nil
}

func (option Option) validate() error {
	if option.APIVersion != APIVersion {
		return fmt.Errorf("unsupported provider option API %q", option.APIVersion)
	}
	if !idPattern.MatchString(option.ID) || option.Label == "" || len(option.Label) > 128 || len(option.Hint) > 256 {
		return errors.New("provider option fields are invalid")
	}
	return nil
}
