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

func All() ([]Descriptor, error) {
	once.Do(func() {
		if err := json.Unmarshal(raw, &values); err != nil {
			loadErr = err
			return
		}
		previous := ""
		for _, value := range values {
			if !validDescriptor(value, previous) {
				loadErr = errors.New("GitHub target registry is invalid")
				return
			}
			previous = value.Kind
			if hasUnsafePolicyField(value.PolicyFields) {
				loadErr = errors.New("GitHub target registry exposes unsafe policy fields")
				return
			}
		}
	})
	return slices.Clone(values), loadErr
}

func validDescriptor(value Descriptor, previous string) bool {
	return value.Kind != "" && value.Schema == "target."+value.Kind+".v1" && len(value.PolicyFields) > 0 && previous < value.Kind
}

func hasUnsafePolicyField(fields []string) bool {
	return slices.Contains(fields, "url") || slices.Contains(fields, "body") || slices.Contains(fields, "graphql") || slices.Contains(fields, "secret")
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
