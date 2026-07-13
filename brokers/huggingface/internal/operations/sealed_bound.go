package operations

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/osolmaz/brokerkit/agentv1"
	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/opbinding"
	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/opcatalog"
	hfpolicy "github.com/osolmaz/brokerkit/brokers/huggingface/internal/policy"
	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/sealedstore"
)

type sealedPayloadStore interface {
	Validate(sealedstore.Reference) error
	Consume(sealedstore.Reference) ([]byte, error)
	Delete(sealedstore.Reference) error
}

type sealedBoundAdapter struct {
	descriptor opcatalog.Descriptor
	binding    opbinding.Binding
	client     boundClient
	store      sealedPayloadStore
	paths      []string
	public     *opbinding.ArgumentsValidator
}

type sealedBoundArguments struct {
	Public         json.RawMessage        `json:"public"`
	SealedPayload  *sealedstore.Reference `json:"sealed_payload,omitempty"`
	CredentialSlot string                 `json:"credential_slot,omitempty"`
}

var sealedInputPaths = map[string][]string{
	"endpoint.create":                      {"model.secrets"},
	"endpoint.update":                      {"model.secrets"},
	"job.run":                              {"secrets"},
	"job.uv.run":                           {"secrets"},
	"organization.member.token.revoke":     {"token"},
	"provisioning.account.request":         {"confirmation_secret"},
	"provisioning.resource.create":         {"payment_credentials"},
	"provisioning.resource.service.update": {"payment_credentials"},
	"repo.duplicate":                       {"secrets"},
	"scheduled_job.create":                 {"jobSpec.secrets"},
	"scheduled_job.uv.create":              {"secrets"},
	"space.secret.set":                     {"value"},
	"webhook.create":                       {"secret", "job.secrets"},
	"webhook.update":                       {"secret", "job.secrets"},
}

var mandatorySealedInputs = map[string]bool{
	"space.secret.set": true,
}

// SealedInputPaths returns the argument paths that must be supplied through
// the encrypted payload boundary for a bound operation.
func SealedInputPaths(operation string) []string {
	return append([]string(nil), sealedInputPaths[operation]...)
}

// RequiresSealedInput reports operations whose provider schema is looser than
// the operation semantics and must still receive protected input.
func RequiresSealedInput(operation string) bool { return mandatorySealedInputs[operation] }

func NewSealedBoundAdapters(client boundClient, store sealedPayloadStore) ([]Adapter, error) {
	if client == nil || store == nil {
		return nil, errors.New("hugging face sealed operation dependencies are required")
	}
	bindings, err := opbinding.All()
	if err != nil {
		return nil, err
	}
	return sealedBoundAdaptersForBindings(client, store, bindings)
}

func sealedBoundAdaptersForBindings(client boundClient, store sealedPayloadStore, bindings []opbinding.Binding) ([]Adapter, error) {
	var adapters []Adapter
	for _, binding := range bindings {
		descriptor, found := opcatalog.ByName(binding.Operation)
		if !found || descriptor.AuthorizationMode != opcatalog.ModeExecution || !descriptor.Sealed {
			continue
		}
		if descriptor.CredentialOutputKind != nil {
			continue
		}
		adapter, err := newSealedBoundAdapter(descriptor, binding, client, store)
		if err != nil {
			return nil, err
		}
		adapters = append(adapters, adapter)
	}
	return adapters, nil
}

func newSealedBoundAdapter(descriptor opcatalog.Descriptor, binding opbinding.Binding, client boundClient, store sealedPayloadStore) (*sealedBoundAdapter, error) {
	paths := sealedInputPaths[binding.Operation]
	validator, err := binding.PublicArgumentsValidator(paths)
	if err != nil {
		return nil, fmt.Errorf("compile %s public arguments: %w", binding.Operation, err)
	}
	return &sealedBoundAdapter{descriptor: descriptor, binding: binding, client: client, store: store, paths: paths, public: validator}, nil
}

func (a *sealedBoundAdapter) Descriptor() opcatalog.Descriptor { return a.descriptor }

//nolint:cyclop // Sealed binding checks are explicit and tracked by the exact HF CRAP baseline.
func (a *sealedBoundAdapter) Decode(targetRaw, argumentsRaw json.RawMessage) (Input, error) {
	if len(targetRaw) > maxTargetBytes || len(argumentsRaw) > maxArgumentsBytes || a.binding.ValidateTarget(targetRaw) != nil {
		return Input{}, errors.New("operation target does not match its closed schema")
	}
	var arguments sealedBoundArguments
	if err := decodeClosed(argumentsRaw, &arguments, maxArgumentsBytes); err != nil || len(arguments.Public) == 0 || arguments.CredentialSlot != "" ||
		RequiresSealedInput(a.descriptor.Name) && arguments.SealedPayload == nil {
		return Input{}, errors.New("sealed operation arguments are invalid")
	}
	public, err := decodeObject(arguments.Public)
	if err != nil || containsSecretPath(public, a.paths) || len(a.paths) == 0 && arguments.SealedPayload != nil {
		return Input{}, errors.New("sealed operation public arguments contain protected fields")
	}
	canonicalTarget, err := canonicalJSON(targetRaw)
	if err != nil {
		return Input{}, err
	}
	arguments.Public, err = canonical(public)
	if err != nil {
		return Input{}, err
	}
	canonicalArguments, err := canonical(arguments)
	return Input{Target: canonicalTarget, Arguments: canonicalArguments}, err
}

func (a *sealedBoundAdapter) ValidateClient(input Input, client, requestKey string) error {
	arguments, err := decodeSealedArguments(input.Arguments)
	if err != nil {
		return err
	}
	if arguments.SealedPayload == nil {
		return nil
	}
	if err := validateSealedReference(arguments.SealedPayload, client, a.descriptor.Name, requestKey); err != nil {
		return err
	}
	return a.store.Validate(*arguments.SealedPayload)
}

func (a *sealedBoundAdapter) Resolve(ctx context.Context, input Input) (Plan, error) {
	arguments, err := decodeSealedArguments(input.Arguments)
	if err != nil || a.validatePublicArguments(arguments) != nil {
		return Plan{}, errors.New("sealed operation public arguments do not match the operation schema")
	}
	preconditions, err := resolveBoundPreconditions(ctx, a.client, a.descriptor.Name, input.Target, a.binding.ObserveMethod != "")
	if err != nil {
		return Plan{}, err
	}
	encoded, _ := canonical(preconditions)
	presentation, request := a.presentationAndPolicy(input.Target, arguments.Public, preconditions)
	return Plan{Operation: a.descriptor.Name, OperationRevision: a.descriptor.OperationRevision, Target: input.Target,
		Arguments: input.Arguments, Preconditions: encoded, Presentation: presentation, Policy: request}, nil
}

func (a *sealedBoundAdapter) validatePublicArguments(arguments sealedBoundArguments) error {
	if arguments.SealedPayload == nil {
		return a.binding.ValidateArguments(arguments.Public)
	}
	return a.public.Validate(arguments.Public)
}

func (a *sealedBoundAdapter) Authorize(plan Plan) hfpolicy.Request {
	return authorizeReconstructed(plan, a.reconstruct(plan))
}

func (a *sealedBoundAdapter) Present(plan Plan) agentv1.Presentation {
	return presentReconstructed(plan, a.reconstruct(plan))
}

func (a *sealedBoundAdapter) reconstruct(plan Plan) reconstructedPlan {
	arguments, _ := decodeSealedArguments(plan.Arguments)
	return reconstructBoundPlan(plan, arguments.Public, a.presentationAndPolicy)
}

func (a *sealedBoundAdapter) Execute(ctx context.Context, plan Plan) (Outcome, error) {
	merged, err := a.prepareExecution(ctx, plan)
	if err != nil {
		return Outcome{}, err
	}
	if err := a.client.ExecuteBound(ctx, a.descriptor.Name, plan.Target, merged); err != nil {
		return Outcome{}, err
	}
	result, _ := canonical(map[string]any{"accepted": true, "operation": a.descriptor.Name})
	return Outcome{Proven: true, Result: result}, nil
}

func (a *sealedBoundAdapter) prepareExecution(ctx context.Context, plan Plan) (json.RawMessage, error) {
	var expected boundPreconditions
	if err := decodeClosed(plan.Preconditions, &expected, maxTargetBytes); err != nil || expected.CredentialIdentity == "" {
		return nil, errors.New("operation plan preconditions are invalid")
	}
	if err := checkBoundPreconditions(ctx, a.client, a.descriptor.Name, plan.Target, expected, a.binding.ObserveMethod != ""); err != nil {
		return nil, err
	}
	merged, _, err := a.materialize(plan.Arguments)
	if err != nil || a.binding.Validate(plan.Target, merged) != nil {
		return nil, errors.New("sealed operation payload is invalid")
	}
	return merged, nil
}

func (a *sealedBoundAdapter) Reconcile(ctx context.Context, plan Plan) (Outcome, error) {
	if a.binding.ObserveMethod == "" {
		return Outcome{Proven: false}, nil
	}
	observed, absent, err := a.client.ObserveBound(ctx, a.descriptor.Name, plan.Target)
	if err != nil {
		return Outcome{}, err
	}
	proven, err := a.reconciliationProven(plan, observed, absent)
	if err != nil {
		return Outcome{}, err
	}
	var result json.RawMessage
	if proven {
		result, _ = canonical(map[string]any{"operation": a.descriptor.Name, "reconciled": true})
	}
	return Outcome{Proven: proven, Result: result}, nil
}

func (a *sealedBoundAdapter) reconciliationProven(plan Plan, observed json.RawMessage, absent bool) (bool, error) {
	if a.binding.Reconcile == "absent" {
		return absent, nil
	}
	if a.binding.Reconcile != "present" || absent {
		return false, nil
	}
	arguments, err := decodeSealedArguments(plan.Arguments)
	if err != nil || arguments.SealedPayload != nil {
		return false, err
	}
	return requestedStateMatches(arguments.Public, observed), nil
}

func (a *sealedBoundAdapter) Cleanup(plan Plan) error {
	arguments, err := decodeSealedArguments(plan.Arguments)
	if err != nil || arguments.SealedPayload == nil {
		return err
	}
	return a.store.Delete(*arguments.SealedPayload)
}

func (a *sealedBoundAdapter) materialize(raw json.RawMessage) (json.RawMessage, sealedBoundArguments, error) {
	arguments, err := decodeSealedArguments(raw)
	if err != nil {
		return nil, arguments, err
	}
	public, err := decodeObject(arguments.Public)
	if err != nil {
		return nil, arguments, err
	}
	if arguments.SealedPayload == nil {
		merged, encodeErr := canonical(public)
		return merged, arguments, encodeErr
	}
	payload, err := a.store.Consume(*arguments.SealedPayload)
	if err != nil {
		return nil, arguments, err
	}
	defer zero(payload)
	secret, err := decodeObject(payload)
	if err != nil || !onlySecretPaths(secret, a.paths, "") {
		return nil, arguments, errors.New("sealed payload contains unsupported fields")
	}
	if err := mergeObjects(public, secret); err != nil {
		return nil, arguments, err
	}
	merged, err := canonical(public)
	return merged, arguments, err
}

func (a *sealedBoundAdapter) presentationAndPolicy(targetRaw, publicRaw json.RawMessage, preconditions boundPreconditions) (agentv1.Presentation, hfpolicy.Request) {
	var target map[string]any
	var public map[string]any
	_ = json.Unmarshal(targetRaw, &target)
	_ = json.Unmarshal(publicRaw, &public)
	owner, name := policyIdentity(target, preconditions.CredentialIdentity, a.descriptor.TargetKind)
	request := hfpolicy.Request{Operation: hfpolicy.Operation(a.descriptor.Name), Target: hfpolicy.Target{Kind: hfpolicy.TargetKind(a.descriptor.TargetKind), Owner: owner, Name: name}, Attrs: policyAttributes(target, public)}
	if request.Target.Kind == hfpolicy.KindRepo {
		request.Target.Type = policyRepoType(target)
	}
	title := strings.ReplaceAll(a.descriptor.Name, ".", " ")
	return agentv1.Presentation{Title: title, Summary: fmt.Sprintf("%s on %s/%s", title, owner, name)}, request
}

func decodeSealedArguments(raw json.RawMessage) (sealedBoundArguments, error) {
	var arguments sealedBoundArguments
	if err := decodeClosed(raw, &arguments, maxArgumentsBytes); err != nil || len(arguments.Public) == 0 {
		return sealedBoundArguments{}, errors.New("sealed operation arguments are invalid")
	}
	return arguments, nil
}

func validateSealedReference(reference *sealedstore.Reference, client, operation, requestKey string) error {
	if reference.Owner != client || reference.Purpose != operation || reference.RequestKey != requestKey {
		return errors.New("sealed payload does not belong to this client, operation, and request")
	}
	return nil
}

func decodeObject(raw []byte) (map[string]any, error) {
	var value map[string]any
	if err := decodeClosed(raw, &value, maxArgumentsBytes); err != nil || value == nil {
		return nil, errors.New("sealed operation fragment must be a JSON object")
	}
	return value, nil
}

func containsSecretPath(value map[string]any, paths []string) bool {
	for _, path := range paths {
		current := any(value)
		parts := strings.Split(path, ".")
		for index, part := range parts {
			object, ok := current.(map[string]any)
			if !ok {
				break
			}
			current, ok = object[part]
			if !ok {
				break
			}
			if index == len(parts)-1 {
				return true
			}
		}
	}
	return false
}

func onlySecretPaths(value map[string]any, paths []string, prefix string) bool {
	for key, child := range value {
		path := key
		if prefix != "" {
			path = prefix + "." + key
		}
		if slicesContains(paths, path) {
			continue
		}
		object, ok := child.(map[string]any)
		if !ok || !hasPathPrefix(paths, path+".") || !onlySecretPaths(object, paths, path) {
			return false
		}
	}
	return len(value) > 0
}

func hasPathPrefix(paths []string, prefix string) bool {
	for _, path := range paths {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}

func slicesContains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func mergeObjects(destination, source map[string]any) error {
	for key, value := range source {
		if existing, found := destination[key]; found {
			destinationObject, destinationOK := existing.(map[string]any)
			sourceObject, sourceOK := value.(map[string]any)
			if !destinationOK || !sourceOK {
				return errors.New("sealed payload overlaps public arguments")
			}
			if err := mergeObjects(destinationObject, sourceObject); err != nil {
				return err
			}
			continue
		}
		destination[key] = value
	}
	return nil
}

func zero(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
