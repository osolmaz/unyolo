// Package operations owns Hugging Face operation adapters and their registry.
package operations

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/osolmaz/brokerkit/agentv1"
	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/opcatalog"
	hfpolicy "github.com/osolmaz/brokerkit/brokers/huggingface/internal/policy"
)

type Input struct {
	Target    json.RawMessage
	Arguments json.RawMessage
}

// Plan is the provider-owned portion of the immutable execution envelope.
type Plan struct {
	Operation         string
	OperationRevision int
	Target            json.RawMessage
	Arguments         json.RawMessage
	Preconditions     json.RawMessage
	Presentation      agentv1.Presentation
	Policy            hfpolicy.Request
	PolicyDecision    PolicyDecision
}

// PolicyDecision is the immutable policy context selected at submission.
type PolicyDecision struct {
	Effect  string
	RuleIDs []string
}

type Outcome struct {
	Proven bool
	Result json.RawMessage
}

// PossiblePartialError marks a multi-call operation that may have changed
// upstream state before a later call failed. Workers must reconcile it instead
// of treating the wrapped error as a definitive refusal.
type PossiblePartialError struct{ Err error }

func (e *PossiblePartialError) Error() string { return e.Err.Error() }
func (e *PossiblePartialError) Unwrap() error { return e.Err }

// IsPossiblePartial reports whether an execution error requires reconciliation.
func IsPossiblePartial(err error) bool {
	var partial *PossiblePartialError
	return errors.As(err, &partial)
}

type reconstructedPlan struct {
	presentation agentv1.Presentation
	request      hfpolicy.Request
}

func reconstructPlan[T any](target, arguments json.RawMessage, decode func(json.RawMessage) (T, error),
	present func(T, json.RawMessage) (agentv1.Presentation, hfpolicy.Request)) reconstructedPlan {
	decoded, err := decode(target)
	if err != nil {
		return reconstructedPlan{}
	}
	presentation, request := present(decoded, arguments)
	return reconstructedPlan{presentation: presentation, request: request}
}

func reconstructPlanWithError[T any](plan Plan, decode func(json.RawMessage) (T, error),
	present func(T, json.RawMessage) (agentv1.Presentation, hfpolicy.Request, error)) reconstructedPlan {
	return reconstructPlan(plan.Target, plan.Arguments, decode,
		func(target T, arguments json.RawMessage) (agentv1.Presentation, hfpolicy.Request) {
			presentation, request, _ := present(target, arguments)
			return presentation, request
		})
}

func authorizeReconstructed(plan Plan, rebuilt reconstructedPlan) hfpolicy.Request {
	return preferCached(plan.Policy, plan.Policy.Operation != "", rebuilt.request)
}

func presentReconstructed(plan Plan, rebuilt reconstructedPlan) agentv1.Presentation {
	return preferCached(plan.Presentation, plan.Presentation.Title != "", rebuilt.presentation)
}

func preferCached[T any](cached T, available bool, rebuilt T) T {
	if available {
		return cached
	}
	return rebuilt
}

func adaptersForNames(names []string, build func(opcatalog.Descriptor) Adapter) ([]Adapter, error) {
	adapters := make([]Adapter, 0, len(names))
	for _, name := range names {
		descriptor, found := opcatalog.ByName(name)
		if !found {
			return nil, fmt.Errorf("operation %q is absent from the catalog", name)
		}
		adapters = append(adapters, build(descriptor))
	}
	return adapters, nil
}

func adaptersForClient(invalid bool, message string, names []string, build func(opcatalog.Descriptor) Adapter) ([]Adapter, error) {
	if invalid {
		return nil, errors.New(message)
	}
	return adaptersForNames(names, build)
}

func decodeValidated[T any](raw json.RawMessage, maximum int, valid func(T) bool, message string) (T, error) {
	var value T
	if err := decodeClosed(raw, &value, maximum); err != nil || !valid(value) {
		return value, errors.New(message)
	}
	return value, nil
}

func decodePlanState[T, P any](plan Plan, decodeTarget func(json.RawMessage) (T, error), maximum int,
	valid func(P) bool, message string) (T, P, error) {
	target, err := decodeTarget(plan.Target)
	var preconditions P
	if err != nil {
		return target, preconditions, err
	}
	if err := decodeClosed(plan.Preconditions, &preconditions, maximum); err != nil || !valid(preconditions) {
		return target, preconditions, errors.New(message)
	}
	return target, preconditions, nil
}

func digestValue[T any](value T) string {
	encoded, _ := canonical(value)
	return digest(encoded)
}

type Adapter interface {
	Descriptor() opcatalog.Descriptor
	Decode(target, arguments json.RawMessage) (Input, error)
	Resolve(context.Context, Input) (Plan, error)
	Authorize(Plan) hfpolicy.Request
	Present(Plan) agentv1.Presentation
	Execute(context.Context, Plan) (Outcome, error)
	Reconcile(context.Context, Plan) (Outcome, error)
}

// ClientBoundAdapter binds requester-owned external references after the
// authenticated client is known and before provider resolution begins.
type ClientBoundAdapter interface {
	ValidateClient(Input, string) error
}

// PlanCleaner removes transient provider material when an operation reaches a
// terminal state without consuming it.
type PlanCleaner interface {
	Cleanup(Plan) error
}

type Registry struct {
	byName map[string]Adapter
	names  []string
}

func NewRegistry(adapters ...Adapter) (*Registry, error) {
	registry := &Registry{byName: make(map[string]Adapter, len(adapters))}
	for _, adapter := range adapters {
		if adapter == nil {
			return nil, errors.New("nil Hugging Face operation adapter")
		}
		descriptor := adapter.Descriptor()
		canonical, found := opcatalog.ByName(descriptor.Name)
		if !found || canonical != descriptor || canonical.AuthorizationMode != opcatalog.ModeExecution {
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

func (r *Registry) Lookup(name string) (Adapter, bool) {
	if r == nil {
		return nil, false
	}
	adapter, found := r.byName[name]
	return adapter, found
}

func (r *Registry) Names() []string {
	if r == nil {
		return nil
	}
	return slices.Clone(r.names)
}

// ValidateCoverage ensures every catalog entry advertised as an implemented
// execution operation has an adapter. Existing bounded protocol operations do
// not enter this registry.
func (r *Registry) ValidateCoverage() error {
	var missing []string
	for _, descriptor := range opcatalog.MustAll() {
		if descriptor.AuthorizationMode != opcatalog.ModeExecution || descriptor.Implementation != opcatalog.StatusImplemented {
			continue
		}
		if _, found := r.Lookup(descriptor.Name); !found {
			missing = append(missing, descriptor.Name)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("missing Hugging Face operation adapters: %s", strings.Join(missing, ", "))
	}
	return nil
}
