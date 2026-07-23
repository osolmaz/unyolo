// Package opcatalog owns the complete Hugging Face capability vocabulary.
package opcatalog

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"sync"

	"github.com/osolmaz/brokerkit/operation/capability"
)

const ExpectedCount = 258

type AuthorizationMode = capability.AuthorizationMode
type ImplementationStatus = capability.ImplementationStatus
type Risk = capability.Risk
type DefaultPolicyEffect = capability.DefaultPolicyEffect
type Descriptor = capability.Descriptor

const (
	ModeWindow            = capability.ModeWindow
	ModeExecution         = capability.ModeExecution
	StatusImplemented     = capability.StatusImplemented
	StatusProtocol        = capability.StatusProtocol
	StatusInternal        = capability.StatusInternal
	StatusOperatorOnly    = capability.StatusOperatorOnly
	StatusLocal           = capability.StatusLocal
	StatusBlockedUpstream = capability.StatusBlockedUpstream
	RiskLow               = capability.RiskLow
	RiskMedium            = capability.RiskMedium
	RiskHigh              = capability.RiskHigh
	RiskCritical          = capability.RiskCritical
	DefaultEffectAllow    = capability.DefaultEffectAllow
	DefaultEffectRequest  = capability.DefaultEffectRequest
	DefaultEffectDeny     = capability.DefaultEffectDeny
)

//go:embed catalog.json
var catalogJSON []byte

var (
	loadOnce sync.Once
	loaded   []Descriptor
	loadErr  error
)

// All returns the validated, name-sorted capability catalog.
func All() ([]Descriptor, error) {
	loadOnce.Do(func() {
		if err := json.Unmarshal(catalogJSON, &loaded); err != nil {
			loadErr = fmt.Errorf("decode HF operation catalog: %w", err)
			return
		}
		loadErr = Validate(loaded)
	})
	return slices.Clone(loaded), loadErr
}

// MustAll returns the catalog or panics during broker startup.
func MustAll() []Descriptor {
	values, err := All()
	if err != nil {
		panic(err)
	}
	return values
}

// ByName returns one immutable descriptor.
func ByName(name string) (Descriptor, bool) {
	values, err := All()
	if err != nil {
		return Descriptor{}, false
	}
	index, found := slices.BinarySearchFunc(values, name, func(value Descriptor, target string) int {
		return strings.Compare(value.Name, target)
	})
	if !found {
		return Descriptor{}, false
	}
	return values[index], true
}

// Validate rejects catalog drift that could weaken policy or expose an unsafe
// operation through broad families.
func Validate(values []Descriptor) error {
	if err := capability.Validate(values, capability.ValidationOptions{
		Provider: "HF", ExpectedCount: ExpectedCount, MCPToolPrefix: "hf_", RequireDefaultPolicyEffect: true,
	}); err != nil {
		return err
	}
	for _, value := range values {
		if err := validateExecutorBinding(value); err != nil {
			return err
		}
	}
	return nil
}

func validateExecutorBinding(value Descriptor) error {
	if value.Implementation == StatusProtocol {
		return fmt.Errorf("HF operation %q has an unresolved protocol placeholder", value.Name)
	}
	if value.Implementation != StatusImplemented {
		return validateUnimplementedExecutor(value)
	}
	switch value.ExecutorKind {
	case "inline":
		return validateInlineExecutor(value)
	case "credential":
		return validateCredentialExecutor(value)
	case "native-protocol":
		return validateNativeExecutor(value)
	case "bounded-stream":
		return validateBoundedStreamExecutor(value)
	default:
		return fmt.Errorf("HF operation %q has no valid executor binding", value.Name)
	}
}

func validateUnimplementedExecutor(value Descriptor) error {
	if value.ExecutorKind != "" {
		return fmt.Errorf("HF operation %q has an executor binding without an implementation", value.Name)
	}
	return nil
}

func validateInlineExecutor(value Descriptor) error {
	if value.CredentialOutputKind != nil {
		return fmt.Errorf("HF credential operation %q must use the credential executor", value.Name)
	}
	return nil
}

func validateCredentialExecutor(value Descriptor) error {
	if value.CredentialOutputKind == nil {
		return fmt.Errorf("HF operation %q has an invalid credential executor", value.Name)
	}
	return nil
}

func validateNativeExecutor(value Descriptor) error {
	if value.AuthorizationMode != ModeWindow {
		return fmt.Errorf("HF operation %q has an invalid native protocol executor", value.Name)
	}
	return nil
}

func validateBoundedStreamExecutor(value Descriptor) error {
	if value.AuthorizationMode != ModeWindow || value.Sealed || value.CredentialOutputKind != nil {
		return fmt.Errorf("HF operation %q has an invalid bounded stream executor", value.Name)
	}
	return nil
}
