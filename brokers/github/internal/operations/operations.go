// Package operations owns generated GitHub operation adapters.
package operations

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/osolmaz/brokerkit/agentv1"
	"github.com/osolmaz/brokerkit/brokers/github/internal/githubauth"
	"github.com/osolmaz/brokerkit/brokers/github/internal/graphqlmanifest"
	"github.com/osolmaz/brokerkit/brokers/github/internal/opbinding"
	"github.com/osolmaz/brokerkit/brokers/github/internal/opcatalog"
	"github.com/osolmaz/brokerkit/brokers/github/internal/schemaregistry"
	"github.com/osolmaz/brokerkit/capability"
	"github.com/osolmaz/brokerkit/credentialstore"
	"github.com/osolmaz/brokerkit/internal/strictjson"
	"github.com/osolmaz/brokerkit/operationruntime"
	"github.com/osolmaz/brokerkit/sealedstore"
)

type Input struct {
	Target    json.RawMessage
	Arguments json.RawMessage
}

type Authorization struct {
	Client         string
	Operation      string
	TargetKind     string
	TargetFields   map[string]string
	Attrs          map[string]string
	CredentialKind string
}

type Plan struct {
	Operation         string
	OperationRevision int
	Target            json.RawMessage
	Arguments         json.RawMessage
	Preconditions     json.RawMessage
	Credential        githubauth.Metadata
	Presentation      agentv1.Presentation
	Authorization     Authorization
	PolicyDecision    PolicyDecision
}

// PolicyDecision is the immutable policy context selected at submission.
type PolicyDecision struct {
	Effect  string
	RuleIDs []string
}

type Outcome = operationruntime.Outcome
type PossiblePartialError = operationruntime.PossiblePartialError

var IsPossiblePartial = operationruntime.IsPossiblePartial

type Adapter = operationruntime.Adapter[Input, Plan, Authorization]
type Runtime = operationruntime.Runtime[Input, Plan, Authorization]
type RuntimeOptions = operationruntime.Options[Input, Plan, Authorization]
type Preparation = operationruntime.Preparation[Plan, Authorization]
type PlanCleaner = operationruntime.PlanCleaner[Plan]
type ClientBoundAdapter = operationruntime.ClientBoundAdapter[Input]

type Options struct {
	RequestingUserID int64
	SealedStore      sealedPayloadStore
	CredentialStore  credentialOutputStore
}

type sealedPayloadStore interface {
	Validate(sealedstore.Reference) error
	Consume(sealedstore.Reference) ([]byte, error)
	Delete(sealedstore.Reference) error
}

type credentialOutputStore interface {
	Put(string, string, []byte) (credentialstore.Metadata, error)
}

type sealedArguments struct {
	Public         json.RawMessage        `json:"public"`
	SealedPayload  *sealedstore.Reference `json:"sealed_payload,omitempty"`
	CredentialSlot string                 `json:"credential_slot,omitempty"`
}

type Registry struct {
	*operationruntime.Registry[Input, Plan, Authorization]
}

func NewRegistry(adapters ...Adapter) (*Registry, error) {
	registry, err := operationruntime.NewRegistry(operationruntime.RegistryOptions{
		Provider: "GitHub", Descriptor: func(name string) (capability.Descriptor, bool) {
			descriptor, found := opcatalog.ByName(name)
			return descriptor.Descriptor, found
		},
		RequiresAdapter: func(descriptor capability.Descriptor) bool {
			return descriptor.Implementation == capability.StatusImplemented || descriptor.Implementation == capability.StatusGraphQL || descriptor.Implementation == capability.StatusProtocol
		},
	}, adapters...)
	if err != nil {
		return nil, err
	}
	return &Registry{Registry: registry}, nil
}

func (r *Registry) ValidateCoverage() error {
	return r.Registry.ValidateCoverage("GitHub", opcatalog.CapabilityDescriptors(opcatalog.MustAll()))
}

func NewGeneratedAdapters(manager *githubauth.Manager, options Options) ([]Adapter, error) {
	descriptors := opcatalog.MustAll()
	adapters := make([]Adapter, 0, len(descriptors))
	for _, descriptor := range descriptors {
		if !shouldHaveAdapter(descriptor) {
			continue
		}
		if descriptor.Sealed && options.SealedStore == nil {
			return nil, fmt.Errorf("GitHub sealed operation %q requires a sealed payload store", descriptor.Name)
		}
		if descriptor.CredentialOutputKind != nil && options.CredentialStore == nil {
			return nil, fmt.Errorf("GitHub credential output operation %q requires a credential store", descriptor.Name)
		}
		switch descriptor.ExecutorKind {
		case "rest-binding", "bounded-stream":
			bindings := opbinding.ByOperation(descriptor.Name)
			if len(bindings) != 1 {
				return nil, fmt.Errorf("GitHub REST operation %q has %d bindings", descriptor.Name, len(bindings))
			}
			adapters = append(adapters, generatedAdapter{descriptor: descriptor, binding: &bindings[0], manager: manager, options: options})
		case "persisted-graphql":
			document, found := graphqlmanifest.ByOperation(descriptor.Name)
			if !found {
				return nil, fmt.Errorf("GitHub GraphQL operation %q is missing its persisted document", descriptor.Name)
			}
			adapters = append(adapters, generatedAdapter{descriptor: descriptor, document: &document, manager: manager, options: options})
		default:
			return nil, fmt.Errorf("GitHub operation %q has unsupported executor %q", descriptor.Name, descriptor.ExecutorKind)
		}
	}
	return adapters, nil
}

type generatedAdapter struct {
	descriptor opcatalog.Descriptor
	binding    *opbinding.Binding
	document   *graphqlmanifest.Document
	manager    *githubauth.Manager
	options    Options
}

func (a generatedAdapter) Descriptor() capability.Descriptor { return a.descriptor.Descriptor }

func (a generatedAdapter) Decode(target, arguments json.RawMessage) (Input, error) {
	decodedArguments, validationArguments, err := a.decodeArguments(target, arguments)
	if err != nil {
		return Input{}, err
	}
	if a.binding != nil {
		argumentMap, err := decodeObject(validationArguments)
		if err != nil {
			return Input{}, errors.New("GitHub operation arguments are invalid")
		}
		targetMap, err := decodeObject(target)
		if err != nil {
			return Input{}, errors.New("GitHub operation target is invalid")
		}
		for _, name := range a.binding.TargetPathParameters {
			if _, found := argumentMap[name]; found && targetSuppliesPathParameter(name, targetMap) {
				return Input{}, fmt.Errorf("GitHub path parameter %q must come from the validated target", name)
			}
		}
	}
	return Input{Target: cloneRaw(target), Arguments: decodedArguments}, nil
}

func targetSuppliesPathParameter(name string, target map[string]any) bool {
	switch name {
	case "owner":
		return stringValue(target, "owner") != ""
	case "repo", "org", "enterprise", "username", "user", "team_slug", "environment_name", "package_name", "codespace_name", "ghsa_id", "ref":
		return stringValue(target, "name") != "" || name == "org" && stringValue(target, "owner") != ""
	}
	if strings.HasSuffix(name, "_id") {
		return integerString(target, "id") != ""
	}
	return (strings.HasSuffix(name, "_number") || name == "number") && integerString(target, "number") != ""
}

func (a generatedAdapter) decodeArguments(target, arguments json.RawMessage) (json.RawMessage, json.RawMessage, error) {
	if !a.descriptor.Sealed {
		if err := schemaregistry.ValidateSubmission(a.descriptor.Name, target, arguments); err != nil {
			return nil, nil, err
		}
		return cloneRaw(arguments), arguments, nil
	}
	var protected sealedArguments
	if err := strictjson.Decode(arguments, &protected, true); err != nil || len(protected.Public) == 0 {
		return nil, nil, errors.New("GitHub sealed operation arguments are invalid")
	}
	if a.descriptor.CredentialOutputKind != nil {
		if protected.SealedPayload != nil || !credentialstore.ValidSlot(protected.CredentialSlot) {
			return nil, nil, errors.New("GitHub credential output requires one valid destination slot")
		}
	} else if protected.SealedPayload == nil || protected.CredentialSlot != "" {
		return nil, nil, errors.New("GitHub sealed operation arguments are invalid")
	}
	if err := schemaregistry.ValidatePublicSubmission(a.descriptor.Name, target, protected.Public); err != nil {
		return nil, nil, err
	}
	encoded, err := json.Marshal(protected)
	if err != nil {
		return nil, nil, errors.New("GitHub sealed operation arguments are invalid")
	}
	return encoded, protected.Public, nil
}

func (a generatedAdapter) ValidateClient(input Input, client, requestKey string) error {
	if !a.descriptor.Sealed {
		return nil
	}
	arguments, err := decodeSealedArguments(input.Arguments)
	if err != nil {
		return err
	}
	reference := arguments.SealedPayload
	if a.descriptor.CredentialOutputKind != nil {
		return nil
	}
	if reference.Owner != client || reference.Purpose != a.descriptor.Name || reference.RequestKey != requestKey {
		return errors.New("sealed payload does not belong to this client, operation, and request")
	}
	return a.options.SealedStore.Validate(*reference)
}

func (a generatedAdapter) Resolve(ctx context.Context, input Input) (Plan, error) {
	if a.manager == nil {
		return Plan{}, errors.New("GitHub credential provider is unavailable")
	}
	targetMap, err := decodeObject(input.Target)
	if err != nil {
		return Plan{}, errors.New("GitHub operation target is invalid")
	}
	publicArguments, err := a.publicArguments(input.Arguments)
	if err != nil {
		return Plan{}, err
	}
	argumentsMap, err := decodeObject(publicArguments)
	if err != nil {
		return Plan{}, errors.New("GitHub operation arguments are invalid")
	}
	credential, err := a.manager.SelectMetadata(ctx, a.descriptor, targetMap, a.options.RequestingUserID)
	if err != nil {
		return Plan{}, err
	}
	presentation := presentDescriptor(a.descriptor, targetMap)
	authorization := authorizeDescriptor(a.descriptor, targetMap, argumentsMap)
	if a.descriptor.CredentialOutputKind != nil {
		protected, _ := decodeSealedArguments(input.Arguments)
		if authorization.Attrs == nil {
			authorization.Attrs = map[string]string{}
		}
		authorization.Attrs["credential_slot"] = protected.CredentialSlot
		authorization.Attrs["credential_kind"] = *a.descriptor.CredentialOutputKind
		presentation.Summary += " into broker credential slot " + protected.CredentialSlot
	}
	return Plan{
		Operation:         a.descriptor.Name,
		OperationRevision: a.descriptor.OperationRevision,
		Target:            cloneRaw(input.Target),
		Arguments:         cloneRaw(input.Arguments),
		Preconditions:     credentialPreconditions(credential),
		Credential:        credential,
		Presentation:      presentation,
		Authorization:     authorization,
	}, nil
}

func (a generatedAdapter) Authorize(plan Plan) Authorization {
	if plan.Authorization.Operation != "" {
		return plan.Authorization
	}
	targetMap, _ := decodeObject(plan.Target)
	publicArguments, _ := a.publicArguments(plan.Arguments)
	argumentsMap, _ := decodeObject(publicArguments)
	return authorizeDescriptor(a.descriptor, targetMap, argumentsMap)
}

func (a generatedAdapter) Present(plan Plan) agentv1.Presentation {
	if plan.Presentation.Title != "" {
		return plan.Presentation
	}
	targetMap, _ := decodeObject(plan.Target)
	return presentDescriptor(a.descriptor, targetMap)
}

func (a generatedAdapter) Execute(ctx context.Context, plan Plan) (Outcome, error) {
	targetMap, err := decodeObject(plan.Target)
	if err != nil {
		return Outcome{}, errors.New("GitHub operation target is invalid")
	}
	executionArguments, err := a.materializeArguments(plan.Arguments)
	if err != nil {
		return Outcome{}, err
	}
	argumentsMap, err := decodeObject(executionArguments)
	if err != nil {
		return Outcome{}, errors.New("GitHub operation arguments are invalid")
	}
	switch {
	case a.binding != nil:
		if a.descriptor.CredentialOutputKind != nil {
			return a.executeCredentialOutput(ctx, plan, targetMap, argumentsMap)
		}
		result, err := a.manager.ExecuteREST(ctx, plan.Credential, *a.binding, targetMap, argumentsMap)
		if err != nil {
			return Outcome{}, classifyExecutionError(a.binding.Method, err)
		}
		if result.StatusCode == 202 {
			return Outcome{}, &PossiblePartialError{Err: githubauth.APIError{Code: "accepted", StatusCode: result.StatusCode}}
		}
		if err := schemaregistry.ValidateResult(a.descriptor.Name, result.Body); err != nil {
			return Outcome{}, err
		}
		return Outcome{Proven: true, Result: result.Body}, nil
	case a.document != nil:
		result, err := a.manager.ExecuteGraphQL(ctx, plan.Credential, *a.document, argumentsMap)
		if err != nil {
			return Outcome{}, classifyExecutionError("POST", err)
		}
		if err := schemaregistry.ValidateResult(a.descriptor.Name, result.Body); err != nil {
			return Outcome{}, err
		}
		return Outcome{Proven: true, Result: result.Body}, nil
	default:
		return Outcome{}, errors.New("GitHub adapter is incomplete")
	}
}

func (a generatedAdapter) Reconcile(context.Context, Plan) (Outcome, error) {
	return Outcome{Proven: false}, nil
}

func (a generatedAdapter) Cleanup(plan Plan) error {
	if !a.descriptor.Sealed {
		return nil
	}
	arguments, err := decodeSealedArguments(plan.Arguments)
	if err != nil || arguments.SealedPayload == nil {
		return err
	}
	return a.options.SealedStore.Delete(*arguments.SealedPayload)
}

func (a generatedAdapter) publicArguments(arguments json.RawMessage) (json.RawMessage, error) {
	if !a.descriptor.Sealed {
		return arguments, nil
	}
	protected, err := decodeSealedArguments(arguments)
	if err != nil {
		return nil, err
	}
	return protected.Public, nil
}

func (a generatedAdapter) materializeArguments(arguments json.RawMessage) (json.RawMessage, error) {
	if !a.descriptor.Sealed {
		return arguments, nil
	}
	protected, err := decodeSealedArguments(arguments)
	if err != nil {
		return nil, err
	}
	if protected.SealedPayload == nil {
		return protected.Public, nil
	}
	payload, err := a.options.SealedStore.Consume(*protected.SealedPayload)
	if err != nil {
		return nil, err
	}
	defer zero(payload)
	if err := schemaregistry.ValidateSealedArguments(a.descriptor.Name, payload); err != nil {
		return nil, err
	}
	public, err := decodeObject(protected.Public)
	if err != nil {
		return nil, errors.New("GitHub sealed operation public arguments are invalid")
	}
	secret, err := decodeObject(payload)
	if err != nil {
		return nil, errors.New("GitHub sealed payload must be a JSON object")
	}
	if err := mergeObjects(public, secret); err != nil {
		return nil, err
	}
	merged, err := json.Marshal(public)
	if err != nil {
		return nil, errors.New("GitHub sealed payload is invalid")
	}
	if err := schemaregistry.ValidateArguments(a.descriptor.Name, merged); err != nil {
		return nil, err
	}
	return merged, nil
}

func decodeSealedArguments(raw json.RawMessage) (sealedArguments, error) {
	var arguments sealedArguments
	if err := strictjson.Decode(raw, &arguments, true); err != nil || len(arguments.Public) == 0 {
		return sealedArguments{}, errors.New("GitHub sealed operation arguments are invalid")
	}
	return arguments, nil
}

func (a generatedAdapter) executeCredentialOutput(ctx context.Context, plan Plan, target, arguments map[string]any) (Outcome, error) {
	protected, err := decodeSealedArguments(plan.Arguments)
	if err != nil || !credentialstore.ValidSlot(protected.CredentialSlot) || a.binding == nil || a.descriptor.CredentialOutputKind == nil {
		return Outcome{}, errors.New("GitHub credential output plan is invalid")
	}
	result, err := a.manager.ExecuteRESTRaw(ctx, plan.Credential, *a.binding, target, arguments)
	if err != nil {
		return Outcome{}, classifyExecutionError(a.binding.Method, err)
	}
	defer zero(result.Body)
	var upstream struct {
		Token     string `json:"token"`
		ExpiresAt string `json:"expires_at"`
	}
	if strictjson.Decode(result.Body, &upstream, true) != nil || upstream.Token == "" || upstream.ExpiresAt == "" {
		return Outcome{}, &PossiblePartialError{Err: errors.New("upstream_result_unknown")}
	}
	token := []byte(upstream.Token)
	defer zero(token)
	stored, err := a.options.CredentialStore.Put(protected.CredentialSlot, *a.descriptor.CredentialOutputKind, token)
	if err != nil {
		return Outcome{}, &PossiblePartialError{Err: errors.New("upstream_result_unknown")}
	}
	encoded, _ := json.Marshal(map[string]any{"stored": true, "slot": stored.Slot, "kind": stored.Kind})
	if err := schemaregistry.ValidateResult(a.descriptor.Name, encoded); err != nil {
		return Outcome{}, err
	}
	return Outcome{Proven: true, Result: encoded}, nil
}

func mergeObjects(destination, source map[string]any) error {
	for key, value := range source {
		if _, exists := destination[key]; exists {
			return fmt.Errorf("sealed payload overlaps public field %q", key)
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

func shouldHaveAdapter(descriptor opcatalog.Descriptor) bool {
	if !descriptor.AgentFacing {
		return false
	}
	switch descriptor.ExecutorKind {
	case "rest-binding":
		return descriptor.Implementation == capability.StatusImplemented
	case "persisted-graphql":
		return descriptor.Implementation == capability.StatusGraphQL
	case "bounded-stream":
		return descriptor.Implementation == capability.StatusProtocol
	default:
		return false
	}
}

func credentialPreconditions(metadata githubauth.Metadata) json.RawMessage {
	encoded, _ := json.Marshal(metadata)
	return encoded
}

// CredentialFromPreconditions restores the opaque credential selector bound
// into an immutable plan. It never contains a token or private key.
func CredentialFromPreconditions(raw json.RawMessage) (githubauth.Metadata, error) {
	var metadata githubauth.Metadata
	if err := strictjson.Decode(raw, &metadata, true); err != nil {
		return githubauth.Metadata{}, errors.New("GitHub credential preconditions are invalid")
	}
	if strings.TrimSpace(string(metadata.Kind)) == "" {
		return githubauth.Metadata{}, errors.New("GitHub credential preconditions are incomplete")
	}
	return metadata, nil
}

func decodeObject(raw json.RawMessage) (map[string]any, error) {
	var value map[string]any
	if err := strictjson.Decode(raw, &value, false); err != nil {
		return nil, err
	}
	if value == nil {
		return map[string]any{}, nil
	}
	return value, nil
}

func cloneRaw(raw json.RawMessage) json.RawMessage {
	if raw == nil {
		return nil
	}
	return append(json.RawMessage(nil), raw...)
}

func presentDescriptor(descriptor opcatalog.Descriptor, target map[string]any) agentv1.Presentation {
	return agentv1.Presentation{
		Title:   descriptor.Summary,
		Summary: descriptor.Name + " on " + targetSummary(descriptor.TargetKind, target),
	}
}

func targetSummary(kind string, target map[string]any) string {
	if owner, repo, ok := repoName(target); ok {
		return owner + "/" + repo
	}
	if name := stringValue(target, "name"); name != "" {
		return kind + " " + name
	}
	if number := integerString(target, "number"); number != "" {
		return kind + " #" + number
	}
	if id := integerString(target, "id"); id != "" {
		return kind + " " + id
	}
	return kind
}

func authorizeDescriptor(descriptor opcatalog.Descriptor, target, arguments map[string]any) Authorization {
	return Authorization{
		Operation:      descriptor.Name,
		TargetKind:     descriptor.TargetKind,
		TargetFields:   authorizationTargetFields(target),
		Attrs:          authorizationAttrs(arguments),
		CredentialKind: descriptor.CredentialKind,
	}
}

func authorizationTargetFields(target map[string]any) map[string]string {
	fields := map[string]string{}
	for _, key := range []string{"owner", "name", "node_id"} {
		if value := stringValue(target, key); value != "" {
			fields[key] = value
		}
	}
	for _, key := range []string{"id", "number"} {
		if value := integerString(target, key); value != "" {
			fields[key] = value
		}
	}
	if len(fields) == 0 {
		return nil
	}
	return fields
}

func authorizationAttrs(arguments map[string]any) map[string]string {
	fields := map[string]string{}
	for _, key := range []string{"ref", "path", "base", "head", "base_ref", "head_ref"} {
		if value := stringValue(arguments, key); value != "" {
			fields[key] = value
		}
	}
	if input, ok := arguments["input"].(map[string]any); ok {
		for _, pair := range []struct {
			source string
			dest   string
		}{
			{"base", "base_ref"},
			{"head", "head_ref"},
			{"path", "path"},
			{"ref", "ref"},
		} {
			if value := stringValue(input, pair.source); value != "" {
				fields[pair.dest] = value
			}
		}
	}
	if len(fields) == 0 {
		return nil
	}
	return fields
}

func classifyExecutionError(method string, err error) error {
	var apiErr githubauth.APIError
	if !strings.EqualFold(method, "GET") && !strings.EqualFold(method, "HEAD") {
		if errors.As(err, &apiErr) && (apiErr.StatusCode >= 500 || apiErr.StatusCode == 0) {
			return &PossiblePartialError{Err: err}
		}
	}
	return err
}

func repoName(values map[string]any) (string, string, bool) {
	owner, repo := stringValue(values, "owner"), stringValue(values, "name")
	return owner, repo, owner != "" && repo != ""
}

func stringValue(values map[string]any, key string) string {
	value, _ := values[key].(string)
	return strings.TrimSpace(value)
}

func integerString(values map[string]any, key string) string {
	value, found := values[key]
	if !found {
		return ""
	}
	number, ok := integerValue(value)
	if !ok || number <= 0 {
		return ""
	}
	return fmt.Sprintf("%d", number)
}

func integerValue(value any) (int64, bool) {
	switch typed := value.(type) {
	case float64:
		return int64(typed), typed == float64(int64(typed))
	case json.Number:
		number, err := typed.Int64()
		return number, err == nil
	default:
		return 0, false
	}
}
