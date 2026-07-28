// Package operations owns Hugging Face operation adapters and their registry.
package operations

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/osolmaz/unyolo/agent/v1"
	"github.com/osolmaz/unyolo/authorization/grants"
	"github.com/osolmaz/unyolo/brokers/huggingface/internal/opcatalog"
	hfpolicy "github.com/osolmaz/unyolo/brokers/huggingface/internal/policy"
	"github.com/osolmaz/unyolo/operation/runtime"
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
	ReservedGrant     *grants.Grant
}

// PolicyDecision is the immutable policy context selected at submission.
type PolicyDecision struct {
	Effect  string
	RuleIDs []string
}

type Outcome = operationruntime.Outcome
type PossiblePartialError = operationruntime.PossiblePartialError

var IsPossiblePartial = operationruntime.IsPossiblePartial

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

func decodeInput[T any](targetRaw, argumentsRaw json.RawMessage, decodeTarget func(json.RawMessage) (T, error),
	decodeArguments func(T, json.RawMessage) (any, error)) (Input, error) {
	target, err := decodeTarget(targetRaw)
	if err != nil {
		return Input{}, err
	}
	arguments, err := decodeArguments(target, argumentsRaw)
	if err != nil {
		return Input{}, err
	}
	canonicalTarget, _ := canonical(target)
	canonicalArguments, _ := canonical(arguments)
	return Input{Target: canonicalTarget, Arguments: canonicalArguments}, nil
}

func decodeNamedArguments(name string, decoders map[string]func(json.RawMessage) (any, error), raw json.RawMessage, message string) (any, error) {
	decode, found := decoders[name]
	if !found {
		return nil, errors.New(message)
	}
	return decode(raw)
}

func decodeEmptyArguments(raw json.RawMessage, message string) (any, error) {
	return decodeValidated(raw, maxArgumentsBytes, alwaysValid[emptyArguments], message)
}

func decodeValidatedArguments[T any](raw json.RawMessage, valid func(T) bool, message string) (any, error) {
	return decodeValidated(raw, maxArgumentsBytes, valid, message)
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

type Adapter = operationruntime.Adapter[Input, Plan, hfpolicy.Request]
type ClientBoundAdapter = operationruntime.ClientBoundAdapter[Input]
type PlanCleaner = operationruntime.PlanCleaner[Plan]
type Runtime = operationruntime.Runtime[Input, Plan, hfpolicy.Request]
type RuntimeOptions = operationruntime.Options[Input, Plan, hfpolicy.Request]
type Preparation = operationruntime.Preparation[Plan, hfpolicy.Request]

type Registry struct {
	*operationruntime.Registry[Input, Plan, hfpolicy.Request]
}

func NewRegistry(adapters ...Adapter) (*Registry, error) {
	registry, err := operationruntime.NewRegistry(operationruntime.RegistryOptions{
		Provider: "Hugging Face", Descriptor: opcatalog.ByName, RequiresAdapter: AgentRuntimeBound,
	}, adapters...)
	if err != nil {
		return nil, err
	}
	return &Registry{Registry: registry}, nil
}

// AgentRuntimeBound reports whether the catalog explicitly binds an operation
// to an Agent Operations executor. Native protocol bindings remain on their
// provider data plane and are not advertised as bounded MCP executions.
func AgentRuntimeBound(descriptor opcatalog.Descriptor) bool {
	return descriptor.Implementation == opcatalog.StatusImplemented &&
		(descriptor.ExecutorKind == "inline" || descriptor.ExecutorKind == "credential" || descriptor.ExecutorKind == "bounded-stream")
}

// ValidateCoverage ensures every catalog entry advertised as an implemented
// operation with an Agent Operations binding has an adapter.
func (r *Registry) ValidateCoverage() error {
	return r.Registry.ValidateCoverage("Hugging Face", opcatalog.MustAll())
}
