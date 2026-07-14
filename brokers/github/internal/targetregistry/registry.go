// Package targetregistry owns GitHub target kinds and safe policy fields.
package targetregistry

import (
	_ "embed"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"sync"
)

type Descriptor struct {
	Kind         string   `json:"kind"`
	Schema       string   `json:"schema"`
	PolicyFields []string `json:"policy_fields"`
}

//go:embed targets.json
var raw []byte

var once sync.Once
var values []Descriptor
var loadErr error

//nolint:cyclop // Target safety fields are validated atomically during load.
func All() ([]Descriptor, error) {
	once.Do(func() {
		if err := json.Unmarshal(raw, &values); err != nil {
			loadErr = err
			return
		}
		previous := ""
		for _, value := range values {
			if value.Kind == "" || value.Schema != "target."+value.Kind+".v1" || len(value.PolicyFields) == 0 || previous >= value.Kind {
				loadErr = errors.New("GitHub target registry is invalid")
				return
			}
			previous = value.Kind
			if slices.Contains(value.PolicyFields, "url") || slices.Contains(value.PolicyFields, "body") || slices.Contains(value.PolicyFields, "graphql") || slices.Contains(value.PolicyFields, "secret") {
				loadErr = errors.New("GitHub target registry exposes unsafe policy fields")
				return
			}
		}
	})
	return slices.Clone(values), loadErr
}

func Known(kind string) bool {
	values, err := All()
	if err != nil {
		return false
	}
	_, found := slices.BinarySearchFunc(values, kind, func(value Descriptor, target string) int { return strings.Compare(value.Kind, target) })
	return found
}

// String returns one normalized string target field.
func String(values map[string]any, key string) string {
	value, _ := values[key].(string)
	return strings.TrimSpace(value)
}

// RepositoryIdentity returns the canonical owner/name pair when both fields
// are present.
func RepositoryIdentity(values map[string]any) (string, string, bool) {
	owner, repo := String(values, "owner"), String(values, "repo")
	if repo == "" {
		repo = String(values, "name")
	}
	return owner, repo, owner != "" && repo != ""
}
