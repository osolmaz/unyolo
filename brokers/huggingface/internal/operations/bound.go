package operations

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/osolmaz/brokerkit/agentv1"
	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/hubclient"
	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/opbinding"
	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/opcatalog"
	hfpolicy "github.com/osolmaz/brokerkit/brokers/huggingface/internal/policy"
)

type boundClient interface {
	WhoAmI(context.Context) (hubclient.Identity, error)
	ExecuteBound(context.Context, string, json.RawMessage, json.RawMessage) error
	ObserveBound(context.Context, string, json.RawMessage) (json.RawMessage, bool, error)
}

type boundAdapter struct {
	descriptor opcatalog.Descriptor
	binding    opbinding.Binding
	client     boundClient
}

type boundPreconditions struct {
	CredentialIdentity string `json:"credential_identity"`
	ObservationDigest  string `json:"observation_digest,omitempty"`
	ObservedAbsent     bool   `json:"observed_absent,omitempty"`
}

func NewBoundAdapters(client boundClient) ([]Adapter, error) {
	if client == nil {
		return nil, errors.New("Hugging Face bound operation client is required")
	}
	bindings, err := opbinding.All()
	if err != nil {
		return nil, err
	}
	adapters := make([]Adapter, 0, len(bindings))
	for _, binding := range bindings {
		descriptor, found := opcatalog.ByName(binding.Operation)
		if !found || descriptor.AuthorizationMode != opcatalog.ModeExecution || descriptor.Sealed {
			continue
		}
		adapters = append(adapters, &boundAdapter{descriptor: descriptor, binding: binding, client: client})
	}
	return adapters, nil
}

func (a *boundAdapter) Descriptor() opcatalog.Descriptor { return a.descriptor }

func (a *boundAdapter) Decode(target, arguments json.RawMessage) (Input, error) {
	if len(target) > maxTargetBytes || len(arguments) > maxArgumentsBytes || a.binding.Validate(target, arguments) != nil {
		return Input{}, errors.New("operation input does not match its closed schema")
	}
	canonicalTarget, err := canonicalJSON(target)
	if err != nil {
		return Input{}, err
	}
	canonicalArguments, err := canonicalJSON(arguments)
	if err != nil {
		return Input{}, err
	}
	return Input{Target: canonicalTarget, Arguments: canonicalArguments}, nil
}

func (a *boundAdapter) Resolve(ctx context.Context, input Input) (Plan, error) {
	preconditions, err := resolveBoundPreconditions(ctx, a.client, a.descriptor.Name, input.Target, a.binding.ObserveMethod != "")
	if err != nil {
		return Plan{}, err
	}
	encoded, _ := canonical(preconditions)
	presentation, request := a.presentationAndPolicy(input.Target, input.Arguments, preconditions)
	return Plan{Operation: a.descriptor.Name, OperationRevision: a.descriptor.OperationRevision,
		Target: input.Target, Arguments: input.Arguments, Preconditions: encoded,
		Presentation: presentation, Policy: request}, nil
}

func (a *boundAdapter) Authorize(plan Plan) hfpolicy.Request {
	return authorizeReconstructed(plan, a.reconstruct(plan))
}

func (a *boundAdapter) Present(plan Plan) agentv1.Presentation {
	return presentReconstructed(plan, a.reconstruct(plan))
}

func (a *boundAdapter) reconstruct(plan Plan) reconstructedPlan {
	return reconstructBoundPlan(plan, plan.Arguments, a.presentationAndPolicy)
}

func (a *boundAdapter) Execute(ctx context.Context, plan Plan) (Outcome, error) {
	var expected boundPreconditions
	if err := decodeClosed(plan.Preconditions, &expected, maxTargetBytes); err != nil || expected.CredentialIdentity == "" {
		return Outcome{}, errors.New("operation plan preconditions are invalid")
	}
	if err := checkBoundPreconditions(ctx, a.client, a.descriptor.Name, plan.Target, expected, a.binding.ObserveMethod != ""); err != nil {
		return Outcome{}, err
	}
	if err := a.client.ExecuteBound(ctx, a.descriptor.Name, plan.Target, plan.Arguments); err != nil {
		return Outcome{}, err
	}
	result, _ := canonical(map[string]any{"accepted": true, "operation": a.descriptor.Name})
	return Outcome{Proven: true, Result: result}, nil
}

func resolveBoundPreconditions(ctx context.Context, client boundClient, operation string, target json.RawMessage, observe bool) (boundPreconditions, error) {
	identity, err := client.WhoAmI(ctx)
	if err != nil {
		return boundPreconditions{}, err
	}
	preconditions := boundPreconditions{CredentialIdentity: identity.Name}
	if !observe {
		return preconditions, nil
	}
	observed, absent, err := client.ObserveBound(ctx, operation, target)
	if err != nil {
		return boundPreconditions{}, err
	}
	preconditions.ObservedAbsent = absent
	if !absent {
		preconditions.ObservationDigest = digest(observed)
	}
	return preconditions, nil
}

func checkBoundPreconditions(ctx context.Context, client boundClient, operation string, target json.RawMessage, expected boundPreconditions, observe bool) error {
	identity, err := client.WhoAmI(ctx)
	if err != nil {
		return err
	}
	if identity.Name != expected.CredentialIdentity {
		return errors.New("operation_precondition_failed")
	}
	if !observe {
		return nil
	}
	observed, absent, err := client.ObserveBound(ctx, operation, target)
	if err != nil {
		return err
	}
	if absent != expected.ObservedAbsent || !absent && digest(observed) != expected.ObservationDigest {
		return errors.New("operation_precondition_failed")
	}
	return nil
}

func reconstructBoundPlan(plan Plan, arguments json.RawMessage,
	present func(json.RawMessage, json.RawMessage, boundPreconditions) (agentv1.Presentation, hfpolicy.Request)) reconstructedPlan {
	var preconditions boundPreconditions
	if decodeClosed(plan.Preconditions, &preconditions, maxTargetBytes) != nil {
		return reconstructedPlan{}
	}
	presentation, request := present(plan.Target, arguments, preconditions)
	return reconstructedPlan{presentation: presentation, request: request}
}

func (a *boundAdapter) Reconcile(ctx context.Context, plan Plan) (Outcome, error) {
	if a.binding.ObserveMethod == "" {
		return Outcome{Proven: false}, nil
	}
	_, absent, err := a.client.ObserveBound(ctx, a.descriptor.Name, plan.Target)
	if err != nil {
		return Outcome{}, err
	}
	proven := a.binding.Reconcile == "absent" && absent || a.binding.Reconcile == "present" && !absent
	result, _ := canonical(map[string]any{"reconciled": proven, "operation": a.descriptor.Name})
	return Outcome{Proven: proven, Result: result}, nil
}

func (a *boundAdapter) presentationAndPolicy(targetRaw, argumentsRaw json.RawMessage, preconditions boundPreconditions) (agentv1.Presentation, hfpolicy.Request) {
	var target map[string]any
	var arguments map[string]any
	_ = json.Unmarshal(targetRaw, &target)
	_ = json.Unmarshal(argumentsRaw, &arguments)
	owner, name := policyIdentity(target, preconditions.CredentialIdentity, a.descriptor.TargetKind)
	request := hfpolicy.Request{Operation: hfpolicy.Operation(a.descriptor.Name), Target: hfpolicy.Target{
		Kind: hfpolicy.TargetKind(a.descriptor.TargetKind), Owner: owner, Name: name,
	}, Attrs: policyAttributes(target, arguments)}
	if request.Target.Kind == hfpolicy.KindRepo {
		request.Target.Type = policyRepoType(target)
	}
	title := strings.ReplaceAll(a.descriptor.Name, ".", " ")
	summary := fmt.Sprintf("%s on %s/%s", title, owner, name)
	return agentv1.Presentation{Title: title, Summary: summary}, request
}

func policyIdentity(target map[string]any, fallback, kind string) (string, string) {
	owner := firstString(target, "namespace", "owner", "organization", "name", "username")
	name := firstString(target, "repo", "endpoint", "jobId", "resourceGroupId", "serviceAccountId", "webhookId", "paperId", "id", "slug")
	if owner == "" {
		owner = fallback
	}
	if name == "" || name == owner {
		name = kind
	}
	return owner, name
}

func firstString(values map[string]any, names ...string) string {
	for _, name := range names {
		if value, ok := values[name].(string); ok && value != "" {
			return value
		}
	}
	return ""
}

func policyRepoType(target map[string]any) hfpolicy.RepoType {
	value := strings.TrimSuffix(firstString(target, "repoType", "type"), "s")
	if value == "" {
		value = "model"
	}
	return hfpolicy.RepoType(value)
}

func policyAttributes(target, arguments map[string]any) map[string]any {
	attributes := make(map[string]any, len(target)+len(arguments))
	for key, value := range target {
		if scalarPolicyValue(value) {
			attributes["target_"+key] = value
		}
	}
	for key, value := range arguments {
		if scalarPolicyValue(value) {
			attributes[key] = value
		}
	}
	return attributes
}

func scalarPolicyValue(value any) bool {
	switch value.(type) {
	case string, bool, float64:
		return true
	default:
		return false
	}
}

func canonicalJSON(raw json.RawMessage) (json.RawMessage, error) {
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		return nil, err
	}
	return canonical(value)
}
