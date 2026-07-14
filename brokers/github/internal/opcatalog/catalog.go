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
	"github.com/osolmaz/brokerkit/internal/sortedlookup"
)

const ExpectedCount = 1436

type Descriptor struct {
	capability.Descriptor
	RequiredGitHubPermissions         map[string]string `json:"required_github_permissions,omitempty"`
	RequiredRepositorySelection       bool              `json:"required_repository_selection,omitempty"`
	AllowEmptyInstallationPermissions bool              `json:"allow_empty_installation_permissions,omitempty"`
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
	return sortedlookup.LoadString(All, name, func(value Descriptor) string { return value.Name })
}

func Validate(values []Descriptor) error {
	if err := capability.Validate(CapabilityDescriptors(values), capability.ValidationOptions{Provider: "GitHub", ExpectedCount: ExpectedCount, MCPToolPrefix: "gh_"}); err != nil {
		return err
	}
	for _, value := range values {
		if err := validateProviderMetadata(value); err != nil {
			return err
		}
	}
	return nil
}

func validateProviderMetadata(value Descriptor) error {
	if incompleteProviderMetadata(value) {
		return fmt.Errorf("GitHub operation %q has incomplete generated metadata", value.Name)
	}
	if !validCredentialKind(value.CredentialKind) {
		return fmt.Errorf("GitHub operation %q has invalid credential kind", value.Name)
	}
	if invalidPermissionlessInstallation(value) {
		return fmt.Errorf("GitHub operation %q has invalid permissionless installation metadata", value.Name)
	}
	if invalidHighRiskMetadata(value) {
		return fmt.Errorf("high-risk GitHub operation %q is not explicit-only", value.Name)
	}
	if invalidSealedMetadata(value) {
		return errors.New("GitHub sealed-input metadata drifted")
	}
	return nil
}

func incompleteProviderMetadata(value Descriptor) bool {
	return incompleteProviderIdentity(value) || incompleteProviderSchema(value)
}

func incompleteProviderIdentity(value Descriptor) bool {
	return value.Summary == "" || !targetregistry.Known(value.TargetKind) || value.CredentialKind == "" || len(value.UpstreamBindingIDs) != 1
}

func incompleteProviderSchema(value Descriptor) bool {
	return value.TargetSchema == "" || value.ArgumentSchema == "" || value.ResultSchema == "" || value.ExecutorKind == "" || value.ReconcilerKind == ""
}

func validCredentialKind(kind string) bool {
	return kind == "installation" || kind == "user" || kind == "app-jwt" || kind == "development-token"
}

func invalidPermissionlessInstallation(value Descriptor) bool {
	return value.AllowEmptyInstallationPermissions && (value.CredentialKind != "installation" || len(value.RequiredGitHubPermissions) != 0)
}

func invalidHighRiskMetadata(value Descriptor) bool {
	return (value.Risk == capability.RiskHigh || value.Risk == capability.RiskCritical) && value.AuthorizationMode == capability.ModeExecution && !value.ExplicitOnly
}

func invalidSealedMetadata(value Descriptor) bool {
	return value.Sealed != (len(value.SealedInputPaths) > 0 || value.CredentialOutputKind != nil)
}

func CapabilityDescriptors(values []Descriptor) []capability.Descriptor {
	result := make([]capability.Descriptor, len(values))
	for index := range values {
		result[index] = values[index].Descriptor
	}
	return result
}
