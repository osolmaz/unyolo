// Package opcatalog owns the generated GitHub capability vocabulary.
package opcatalog

import (
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"

	"github.com/osolmaz/brokerkit/brokers/github/internal/targetregistry"
	"github.com/osolmaz/brokerkit/capability"
)

const ExpectedCount = 1436

type Descriptor struct {
	capability.Descriptor
	RequiredGitHubPermissions   map[string]string `json:"required_github_permissions,omitempty"`
	RequiredRepositorySelection bool              `json:"required_repository_selection,omitempty"`
}
type AuthorizationMode = capability.AuthorizationMode
type ImplementationStatus = capability.ImplementationStatus
type Risk = capability.Risk

const (
	ModeWindow    = capability.ModeWindow
	ModeExecution = capability.ModeExecution
	RiskLow       = capability.RiskLow
	RiskMedium    = capability.RiskMedium
	RiskHigh      = capability.RiskHigh
	RiskCritical  = capability.RiskCritical
)

//go:embed catalog.json
var raw []byte

var once sync.Once
var values []Descriptor
var loadErr error

func All() ([]Descriptor, error) {
	once.Do(func() {
		decoder := json.NewDecoder(strings.NewReader(string(raw)))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&values); err != nil {
			loadErr = fmt.Errorf("decode GitHub operation catalog: %w", err)
			return
		}
		loadErr = Validate(values)
	})
	return slices.Clone(values), loadErr
}

func MustAll() []Descriptor {
	values, err := All()
	if err != nil {
		panic(err)
	}
	return values
}

func ByName(name string) (Descriptor, bool) {
	values, err := All()
	if err != nil {
		return Descriptor{}, false
	}
	index, found := slices.BinarySearchFunc(values, name, func(value Descriptor, target string) int { return strings.Compare(value.Name, target) })
	if !found {
		return Descriptor{}, false
	}
	return values[index], true
}

//nolint:cyclop // Provider-specific catalog invariants are intentionally explicit.
func Validate(values []Descriptor) error {
	if err := capability.Validate(CapabilityDescriptors(values), capability.ValidationOptions{Provider: "GitHub", ExpectedCount: ExpectedCount, MCPToolPrefix: "gh_"}); err != nil {
		return err
	}
	for _, value := range values {
		if value.Summary == "" || !targetregistry.Known(value.TargetKind) || value.TargetSchema == "" || value.ArgumentSchema == "" || value.ResultSchema == "" || value.CredentialKind == "" || len(value.UpstreamBindingIDs) != 1 || value.ExecutorKind == "" || value.ReconcilerKind == "" {
			return fmt.Errorf("GitHub operation %q has incomplete generated metadata", value.Name)
		}
		if value.CredentialKind != "installation" && value.CredentialKind != "user" && value.CredentialKind != "app-jwt" && value.CredentialKind != "development-token" {
			return fmt.Errorf("GitHub operation %q has invalid credential kind", value.Name)
		}
		if (value.Risk == capability.RiskHigh || value.Risk == capability.RiskCritical) && value.AuthorizationMode == capability.ModeExecution && !value.ExplicitOnly {
			return fmt.Errorf("high-risk GitHub operation %q is not explicit-only", value.Name)
		}
		if value.Sealed != (len(value.SealedInputPaths) > 0) {
			return errors.New("GitHub sealed-input metadata drifted")
		}
	}
	return nil
}

func CapabilityDescriptors(values []Descriptor) []capability.Descriptor {
	result := make([]capability.Descriptor, len(values))
	for index := range values {
		result[index] = values[index].Descriptor
	}
	return result
}
