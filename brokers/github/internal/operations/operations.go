// Package operations owns generated GitHub operation adapters.
package operations

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/osolmaz/brokerkit/agentv1"
	"github.com/osolmaz/brokerkit/brokers/github/internal/githubauth"
	"github.com/osolmaz/brokerkit/brokers/github/internal/graphqlmanifest"
	"github.com/osolmaz/brokerkit/brokers/github/internal/opbinding"
	"github.com/osolmaz/brokerkit/brokers/github/internal/opcatalog"
	"github.com/osolmaz/brokerkit/brokers/github/internal/schemaregistry"
	"github.com/osolmaz/brokerkit/brokers/github/internal/targetregistry"
	"github.com/osolmaz/brokerkit/capability"
	"github.com/osolmaz/brokerkit/credentialstore"
	"github.com/osolmaz/brokerkit/internal/strictjson"
	"github.com/osolmaz/brokerkit/operationruntime"
	"github.com/osolmaz/brokerkit/sealedstore"
	"github.com/osolmaz/brokerkit/streamstore"
)

type Input struct {
	Target    json.RawMessage
	Arguments json.RawMessage
}

type Authorization struct {
	Client         string
	Operation      string
	TargetKind     string
	TargetFields   map[string][]string
	Attrs          map[string][]string
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
	StreamStore      streamStore
}

type sealedPayloadStore interface {
	Validate(sealedstore.Reference) error
	Consume(sealedstore.Reference) ([]byte, error)
	Delete(sealedstore.Reference) error
}

type credentialOutputStore interface {
	Put(string, string, []byte) (credentialstore.Metadata, error)
}

type streamStore interface {
	Validate(streamstore.Reference) error
	OpenStream(streamstore.Reference) (*os.File, error)
	Put(string, string, string, string, io.Reader, int64, time.Time) (streamstore.Reference, error)
	Delete(streamstore.Reference) error
}

type sealedArguments struct {
	Public         json.RawMessage        `json:"public"`
	SealedPayload  *sealedstore.Reference `json:"sealed_payload,omitempty"`
	CredentialSlot string                 `json:"credential_slot,omitempty"`
}

type streamArguments struct {
	Public      json.RawMessage        `json:"public"`
	StreamInput *streamstore.Reference `json:"stream_input"`
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

//nolint:cyclop // Catalog-to-adapter construction validates every executor dependency in one startup pass.
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
		if descriptor.ExecutorKind == "bounded-stream" && options.StreamStore == nil {
			return nil, fmt.Errorf("GitHub stream operation %q requires a stream store", descriptor.Name)
		}
		switch descriptor.ExecutorKind {
		case "rest-binding", "bounded-stream":
			bindings := opbinding.ByOperation(descriptor.Name)
			if len(bindings) != 1 {
				return nil, fmt.Errorf("GitHub REST operation %q has %d bindings", descriptor.Name, len(bindings))
			}
			var reconciliation *opbinding.Binding
			if id := bindings[0].ReconciliationBindingID; id != "" {
				readback, found := opbinding.ByID(id)
				if !found {
					return nil, fmt.Errorf("GitHub REST operation %q has no reconciliation binding", descriptor.Name)
				}
				reconciliation = &readback
			}
			adapters = append(adapters, generatedAdapter{descriptor: descriptor, binding: &bindings[0], reconciliation: reconciliation, manager: manager, options: options})
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
	descriptor     opcatalog.Descriptor
	binding        *opbinding.Binding
	reconciliation *opbinding.Binding
	document       *graphqlmanifest.Document
	manager        *githubauth.Manager
	options        Options
}

func (a generatedAdapter) Descriptor() capability.Descriptor { return a.descriptor.Descriptor }

//nolint:cyclop // Closed schemas and target-owned path parameters are enforced together at decode time.
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
		for _, name := range a.binding.PathParameters {
			_, argumentFound := argumentMap[name]
			field, targetOwned := targetFieldForPath(name, a.binding.TargetPathParameters)
			targetFound := targetOwned && targetFieldPresent(field, targetMap)
			if targetOwned && argumentFound {
				return Input{}, fmt.Errorf("GitHub path parameter %q must come from the validated target", name)
			}
			if !targetOwned && !argumentFound || targetOwned && !targetFound {
				return Input{}, fmt.Errorf("GitHub path parameter %q is missing", name)
			}
		}
	}
	return Input{Target: cloneRaw(target), Arguments: decodedArguments}, nil
}

func targetFieldForPath(name string, parameters []opbinding.TargetParameter) (string, bool) {
	index := slices.IndexFunc(parameters, func(parameter opbinding.TargetParameter) bool { return parameter.Name == name })
	if index < 0 {
		return "", false
	}
	return parameters[index].Field, true
}

func targetFieldPresent(field string, target map[string]any) bool {
	if field == "id" || field == "number" {
		return integerString(target, field) != ""
	}
	return stringValue(target, field) != ""
}

//nolint:cyclop // Public, sealed, credential-output, and stream envelopes are mutually exclusive trust forms.
func (a generatedAdapter) decodeArguments(target, arguments json.RawMessage) (json.RawMessage, json.RawMessage, error) {
	if a.streamDirection() == "upload" {
		var stream streamArguments
		if strictjson.Decode(arguments, &stream, true) != nil || len(stream.Public) == 0 || stream.StreamInput == nil {
			return nil, nil, errors.New("GitHub stream upload arguments are invalid")
		}
		if err := schemaregistry.ValidateStreamPublic(a.descriptor.Name, target, stream.Public); err != nil {
			return nil, nil, err
		}
		encoded, _ := json.Marshal(stream)
		return encoded, stream.Public, nil
	}
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

//nolint:cyclop // Stored sealed and stream references must match every client-owned binding.
func (a generatedAdapter) ValidateClient(input Input, client, requestKey string) error {
	if a.streamDirection() == "upload" {
		stream, err := decodeStreamArguments(input.Arguments)
		if err != nil {
			return err
		}
		reference := stream.StreamInput
		if reference.Owner != client || reference.Purpose != a.descriptor.Name || reference.RequestKey != requestKey {
			return errors.New("stream input does not belong to this client, operation, and request")
		}
		return a.options.StreamStore.Validate(*reference)
	}
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
	credential, err := a.resolveCredential(ctx, targetMap)
	if err != nil {
		return Plan{}, err
	}
	presentation := presentDescriptor(a.descriptor, targetMap)
	authorization := authorizeDescriptor(a.descriptor, targetMap, argumentsMap)
	if a.descriptor.CredentialOutputKind != nil {
		protected, _ := decodeSealedArguments(input.Arguments)
		if authorization.Attrs == nil {
			authorization.Attrs = map[string][]string{}
		}
		authorization.Attrs["credential_slot"] = []string{protected.CredentialSlot}
		authorization.Attrs["credential_kind"] = []string{*a.descriptor.CredentialOutputKind}
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

func (a generatedAdapter) resolveCredential(ctx context.Context, target map[string]any) (githubauth.Metadata, error) {
	credential, err := a.manager.SelectMetadata(ctx, a.descriptor, target, a.options.RequestingUserID)
	if err != nil || a.descriptor.TargetKind != "user" {
		return credential, err
	}
	return credential, a.manager.ValidateAuthenticatedUserTarget(ctx, credential, target)
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

//nolint:cyclop // Executor dispatch stays closed over catalog-declared REST, GraphQL, and stream kinds.
func (a generatedAdapter) Execute(ctx context.Context, plan Plan) (Outcome, error) {
	targetMap, err := decodeObject(plan.Target)
	if err != nil {
		return Outcome{}, errors.New("GitHub operation target is invalid")
	}
	if a.streamDirection() == "upload" {
		return a.executeStreamUpload(ctx, plan, targetMap)
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
		if a.streamDirection() == "download" {
			return a.executeStreamDownload(ctx, plan, targetMap, argumentsMap)
		}
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

func (a generatedAdapter) Reconcile(ctx context.Context, plan Plan) (Outcome, error) {
	if a.binding == nil || a.binding.Reconciliation != "absence-proof" || a.reconciliation == nil {
		return Outcome{Proven: false}, nil
	}
	target, err := decodeObject(plan.Target)
	if err != nil {
		return Outcome{}, errors.New("GitHub reconciliation target is invalid")
	}
	public, err := a.publicArguments(plan.Arguments)
	if err != nil {
		return Outcome{}, err
	}
	arguments, err := decodeObject(public)
	if err != nil {
		return Outcome{}, errors.New("GitHub reconciliation arguments are invalid")
	}
	_, err = a.manager.ExecuteREST(ctx, plan.Credential, *a.reconciliation, target, arguments)
	if githubauth.IsNotFound(err) {
		result := json.RawMessage(`{}`)
		if validationErr := schemaregistry.ValidateResult(a.descriptor.Name, result); validationErr != nil {
			return Outcome{}, validationErr
		}
		return Outcome{Proven: true, Result: result}, nil
	}
	if err != nil {
		return Outcome{}, err
	}
	return Outcome{Proven: false}, nil
}

func (a generatedAdapter) Cleanup(plan Plan) error {
	if a.streamDirection() == "upload" {
		stream, err := decodeStreamArguments(plan.Arguments)
		if err != nil {
			return err
		}
		return a.options.StreamStore.Delete(*stream.StreamInput)
	}
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
	if a.streamDirection() == "upload" {
		stream, err := decodeStreamArguments(arguments)
		if err != nil {
			return nil, err
		}
		return stream.Public, nil
	}
	if !a.descriptor.Sealed {
		return arguments, nil
	}
	protected, err := decodeSealedArguments(arguments)
	if err != nil {
		return nil, err
	}
	return protected.Public, nil
}

func (a generatedAdapter) streamDirection() string {
	if a.binding == nil {
		return ""
	}
	return a.binding.StreamDirection
}

func decodeStreamArguments(raw json.RawMessage) (streamArguments, error) {
	var arguments streamArguments
	if strictjson.Decode(raw, &arguments, true) != nil || len(arguments.Public) == 0 || arguments.StreamInput == nil {
		return streamArguments{}, errors.New("GitHub stream upload arguments are invalid")
	}
	return arguments, nil
}

func (a generatedAdapter) executeStreamUpload(ctx context.Context, plan Plan, target map[string]any) (Outcome, error) {
	arguments, err := decodeStreamArguments(plan.Arguments)
	if err != nil || a.binding == nil {
		return Outcome{}, errors.New("GitHub stream upload plan is invalid")
	}
	public, err := decodeObject(arguments.Public)
	if err != nil {
		return Outcome{}, errors.New("GitHub stream upload arguments are invalid")
	}
	file, err := a.options.StreamStore.OpenStream(*arguments.StreamInput)
	if err != nil {
		return Outcome{}, err
	}
	defer func() { _ = file.Close() }()
	result, err := a.manager.ExecuteRESTUpload(ctx, plan.Credential, *a.binding, target, public, file, arguments.StreamInput.Size, arguments.StreamInput.MediaType)
	if err != nil {
		return Outcome{}, classifyExecutionError(a.binding.Method, err)
	}
	if err := schemaregistry.ValidateResult(a.descriptor.Name, result.Body); err != nil {
		return Outcome{}, err
	}
	_ = a.options.StreamStore.Delete(*arguments.StreamInput)
	return Outcome{Proven: true, Result: result.Body}, nil
}

func (a generatedAdapter) executeStreamDownload(ctx context.Context, plan Plan, target, arguments map[string]any) (Outcome, error) {
	if a.binding == nil || plan.Authorization.Client == "" {
		return Outcome{}, errors.New("GitHub stream download plan is invalid")
	}
	response, err := a.manager.ExecuteRESTDownload(ctx, plan.Credential, *a.binding, target, arguments)
	if err != nil {
		return Outcome{}, classifyExecutionError(a.binding.Method, err)
	}
	defer func() { _ = response.Body.Close() }()
	mediaType := strings.TrimSpace(strings.Split(response.Header.Get("Content-Type"), ";")[0])
	if mediaType == "" {
		mediaType = "application/octet-stream"
	}
	reference, err := a.options.StreamStore.Put(plan.Authorization.Client, a.descriptor.Name, a.descriptor.Name+"-result", mediaType,
		response.Body, a.binding.ResponseBytesLimit, time.Now().Add(15*time.Minute))
	if err != nil {
		return Outcome{}, err
	}
	encoded, _ := json.Marshal(map[string]any{"stream": reference})
	if err := schemaregistry.ValidateResult(a.descriptor.Name, encoded); err != nil {
		_ = a.options.StreamStore.Delete(reference)
		return Outcome{}, err
	}
	return Outcome{Proven: true, Result: encoded}, nil
}

//nolint:cyclop // Sealed payload consumption, zeroing, merge, and schema checks form one security boundary.
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

//nolint:cyclop // Credential extraction, encrypted storage, zeroing, and redacted result checks stay atomic.
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
	if owner, repo, ok := targetregistry.RepositoryIdentity(target); ok {
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

func authorizationTargetFields(target map[string]any) map[string][]string {
	fields := map[string][]string{}
	for _, key := range []string{"owner", "name", "node_id"} {
		if value := stringValue(target, key); value != "" {
			fields[key] = []string{value}
		}
	}
	for _, key := range []string{"id", "number"} {
		if value := integerString(target, key); value != "" {
			fields[key] = []string{value}
		}
	}
	if len(fields) == 0 {
		return nil
	}
	return fields
}

func authorizationAttrs(arguments map[string]any) map[string][]string {
	fields := map[string][]string{}
	collectAuthorizationAttrs(arguments, fields)
	for key, values := range fields {
		slices.Sort(values)
		fields[key] = slices.Compact(values)
	}
	if len(fields) == 0 {
		return nil
	}
	return fields
}

// collectAuthorizationAttrs walks only decoded, schema-validated input and
// maps reviewed GitHub field names into the closed policy vocabulary.
func collectAuthorizationAttrs(value any, fields map[string][]string) {
	switch typed := value.(type) {
	case map[string]any:
		for name, child := range typed {
			if attribute, found := authorizationAttributeName(name); found {
				fields[attribute] = append(fields[attribute], scalarStrings(child)...)
			}
			collectAuthorizationAttrs(child, fields)
		}
	case []any:
		for _, child := range typed {
			collectAuthorizationAttrs(child, fields)
		}
	}
}

func authorizationAttributeName(name string) (string, bool) {
	aliases := map[string]string{
		"actor_id": "actor_id", "actorId": "actor_id", "actor_login": "actor_login", "actorLogin": "actor_login",
		"base": "base_ref", "base_ref": "base_ref", "baseRef": "base_ref", "environment": "environment",
		"environment_name": "environment", "environmentName": "environment", "head": "head_ref", "head_ref": "head_ref",
		"headRef": "head_ref", "label": "label", "labels": "label", "merge_method": "merge_method", "mergeMethod": "merge_method",
		"path": "path", "paths": "path", "permission": "permission", "ref": "ref", "release_state": "release_state",
		"releaseState": "release_state", "resource_id": "resource_id", "resourceId": "resource_id", "role": "role",
		"visibility": "visibility", "workflow": "workflow", "workflow_ref": "workflow_ref", "workflowRef": "workflow_ref",
	}
	attribute, found := aliases[name]
	return attribute, found
}

func scalarStrings(value any) []string {
	switch typed := value.(type) {
	case string:
		if value := strings.TrimSpace(typed); value != "" {
			return []string{value}
		}
	case json.Number:
		return []string{typed.String()}
	case float64:
		return []string{fmt.Sprintf("%g", typed)}
	case bool:
		return []string{fmt.Sprintf("%t", typed)}
	case []any:
		values := []string{}
		for _, child := range typed {
			values = append(values, scalarStrings(child)...)
		}
		return values
	}
	return nil
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

func stringValue(values map[string]any, key string) string {
	return targetregistry.String(values, key)
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
