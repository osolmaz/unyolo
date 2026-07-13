// Package operationruntime owns the provider-neutral capability adapter
// registry and Agent Operations V1 lifecycle orchestration.
package operationruntime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"

	"github.com/osolmaz/brokerkit/agentv1"
	"github.com/osolmaz/brokerkit/capability"
)

// Outcome is the stable result of execution or reconciliation. Proven must be
// true before the runtime records a successful operation.
type Outcome struct {
	Proven bool
	Result json.RawMessage
}

// PossiblePartialError marks a multi-call operation that may have changed
// upstream state before a later call failed. The runtime reconciles it instead
// of treating the wrapped error as a definitive refusal.
type PossiblePartialError struct{ Err error }

func (e *PossiblePartialError) Error() string { return e.Err.Error() }
func (e *PossiblePartialError) Unwrap() error { return e.Err }

// IsPossiblePartial reports whether an execution error requires
// reconciliation.
func IsPossiblePartial(err error) bool {
	var partial *PossiblePartialError
	return errors.As(err, &partial)
}

// Adapter is the provider-neutral operation contract. Providers retain their
// own concrete input, immutable plan, and authorization request types.
type Adapter[I, P, A any] interface {
	Descriptor() capability.Descriptor
	Decode(target, arguments json.RawMessage) (I, error)
	Resolve(context.Context, I) (P, error)
	Authorize(P) A
	Present(P) agentv1.Presentation
	Execute(context.Context, P) (Outcome, error)
	Reconcile(context.Context, P) (Outcome, error)
}

// ClientBoundAdapter binds requester-owned external references after the
// authenticated client is known and before provider resolution begins.
type ClientBoundAdapter[I any] interface {
	ValidateClient(I, string, string) error
}

// PlanCleaner removes transient provider material when an operation reaches a
// terminal state without consuming it.
type PlanCleaner[P any] interface {
	Cleanup(P) error
}

// RegistryOptions supplies provider catalog ownership without teaching the
// shared registry provider vocabulary.
type RegistryOptions struct {
	Provider   string
	Descriptor func(string) (capability.Descriptor, bool)
}

// Registry is an immutable adapter registry keyed by catalog operation name.
type Registry[I, P, A any] struct {
	byName map[string]Adapter[I, P, A]
	names  []string
}

// NewRegistry validates adapters against their provider-owned catalog.
func NewRegistry[I, P, A any](options RegistryOptions, adapters ...Adapter[I, P, A]) (*Registry[I, P, A], error) {
	if strings.TrimSpace(options.Provider) == "" || options.Descriptor == nil {
		return nil, errors.New("operation registry options are incomplete")
	}
	registry := &Registry[I, P, A]{byName: make(map[string]Adapter[I, P, A], len(adapters))}
	for _, adapter := range adapters {
		if adapter == nil {
			return nil, fmt.Errorf("nil %s operation adapter", options.Provider)
		}
		descriptor := adapter.Descriptor()
		canonical, found := options.Descriptor(descriptor.Name)
		if !found || !reflect.DeepEqual(canonical, descriptor) || canonical.AuthorizationMode != capability.ModeExecution {
			return nil, fmt.Errorf("adapter %q does not match the capability catalog", descriptor.Name)
		}
		if _, exists := registry.byName[descriptor.Name]; exists {
			return nil, fmt.Errorf("duplicate adapter %q", descriptor.Name)
		}
		registry.byName[descriptor.Name] = adapter
		registry.names = append(registry.names, descriptor.Name)
	}
	slices.Sort(registry.names)
	return registry, nil
}

// Lookup returns the adapter for one exact operation name.
func (r *Registry[I, P, A]) Lookup(name string) (Adapter[I, P, A], bool) {
	if r == nil {
		return nil, false
	}
	adapter, found := r.byName[name]
	return adapter, found
}

// Names returns the sorted registered operation names.
func (r *Registry[I, P, A]) Names() []string {
	if r == nil {
		return nil
	}
	return slices.Clone(r.names)
}

// ValidateCoverage ensures every catalog entry advertised as an implemented
// execution operation has an adapter.
func (r *Registry[I, P, A]) ValidateCoverage(provider string, descriptors []capability.Descriptor) error {
	var missing []string
	for _, descriptor := range descriptors {
		if descriptor.AuthorizationMode != capability.ModeExecution || descriptor.Implementation != capability.StatusImplemented {
			continue
		}
		if _, found := r.Lookup(descriptor.Name); !found {
			missing = append(missing, descriptor.Name)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("missing %s operation adapters: %s", provider, strings.Join(missing, ", "))
	}
	return nil
}
