// Package opcatalog owns the complete Hugging Face capability vocabulary.
package opcatalog

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"sync"

	"github.com/osolmaz/brokerkit/capability"
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
	return capability.Validate(values, capability.ValidationOptions{
		Provider: "HF", ExpectedCount: ExpectedCount, MCPToolPrefix: "hf_", RequireDefaultPolicyEffect: true,
	})
}
