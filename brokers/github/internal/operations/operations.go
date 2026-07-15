// Package operations owns generated GitHub operation adapters.
package operations

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/osolmaz/brokerkit/agentops"
	"github.com/osolmaz/brokerkit/agentv1"
	"github.com/osolmaz/brokerkit/brokers/github/internal/githubauth"
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
	ExecutionID       string
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
	Retire(streamstore.Reference, time.Time) error
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

func NewGeneratedAdapters(manager *githubauth.Manager, options Options) ([]Adapter, error) {
	descriptors := opcatalog.MustAll()
	adapters := make([]Adapter, 0, len(descriptors))
	for _, descriptor := range descriptors {
		adapter, ok, err := newGeneratedAdapter(descriptor, manager, options)
		if err != nil {
			return nil, err
		}
		if !ok {
			continue
		}
		adapters = append(adapters, adapter)
	}
	return adapters, nil
}

func newGeneratedAdapter(descriptor opcatalog.Descriptor, manager *githubauth.Manager, options Options) (Adapter, bool, error) {
	if !shouldHaveAdapter(descriptor) {
		return nil, false, nil
	}
	if err := validateGeneratedAdapterStores(descriptor, options); err != nil {
		return nil, false, err
	}
	binding, err := generatedBinding(descriptor)
	if err != nil {
		return nil, false, err
	}
	reconciliation, err := generatedReconciliation(descriptor.Name, binding)
	if err != nil {
		return nil, false, err
	}
	return generatedAdapter{descriptor: descriptor, binding: binding, reconciliation: reconciliation, manager: manager, options: options}, true, nil
}

func validateGeneratedAdapterStores(descriptor opcatalog.Descriptor, options Options) error {
	for _, requirement := range generatedAdapterStoreRequirements(descriptor, options) {
		if requirement.missing {
			return requirement.err
		}
	}
	return nil
}

type generatedAdapterStoreRequirement struct {
	missing bool
	err     error
}

func generatedAdapterStoreRequirements(descriptor opcatalog.Descriptor, options Options) []generatedAdapterStoreRequirement {
	return []generatedAdapterStoreRequirement{
		{missing: descriptor.Sealed && options.SealedStore == nil, err: fmt.Errorf("GitHub sealed operation %q requires a sealed payload store", descriptor.Name)},
		{missing: descriptor.CredentialOutputKind != nil && options.CredentialStore == nil, err: fmt.Errorf("GitHub credential output operation %q requires a credential store", descriptor.Name)},
		{missing: descriptor.ExecutorKind == "bounded-stream" && options.StreamStore == nil, err: fmt.Errorf("GitHub stream operation %q requires a stream store", descriptor.Name)},
	}
}

func generatedBinding(descriptor opcatalog.Descriptor) (*opbinding.Binding, error) {
	switch descriptor.ExecutorKind {
	case "rest-binding", "bounded-stream":
		bindings := opbinding.ByOperation(descriptor.Name)
		if len(bindings) != 1 {
			return nil, fmt.Errorf("GitHub REST operation %q has %d bindings", descriptor.Name, len(bindings))
		}
		return &bindings[0], nil
	default:
		return nil, fmt.Errorf("GitHub operation %q has unsupported executor %q", descriptor.Name, descriptor.ExecutorKind)
	}
}

func generatedReconciliation(operation string, binding *opbinding.Binding) (*opbinding.Binding, error) {
	if binding.ReconciliationBindingID == "" {
		return nil, nil
	}
	readback, found := opbinding.ByID(binding.ReconciliationBindingID)
	if !found {
		return nil, fmt.Errorf("GitHub REST operation %q has no reconciliation binding", operation)
	}
	return &readback, nil
}

type generatedAdapter struct {
	descriptor     opcatalog.Descriptor
	binding        *opbinding.Binding
	reconciliation *opbinding.Binding
	manager        *githubauth.Manager
	options        Options
}

func (a generatedAdapter) Descriptor() capability.Descriptor { return a.descriptor.Descriptor }

func (a generatedAdapter) Decode(target, arguments json.RawMessage) (Input, error) {
	decodedArguments, validationArguments, err := a.decodeArguments(target, arguments)
	if err != nil {
		return Input{}, err
	}
	if err := a.validatePathParameters(target, validationArguments); err != nil {
		return Input{}, err
	}
	return Input{Target: cloneRaw(target), Arguments: decodedArguments}, nil
}

func (a generatedAdapter) validatePathParameters(target, arguments json.RawMessage) error {
	if a.binding == nil {
		return nil
	}
	argumentMap, err := decodeObject(arguments)
	if err != nil {
		return errors.New("GitHub operation arguments are invalid")
	}
	targetMap, err := decodeObject(target)
	if err != nil {
		return errors.New("GitHub operation target is invalid")
	}
	for _, name := range a.binding.PathParameters {
		if err := validatePathParameter(name, a.binding.TargetPathParameters, targetMap, argumentMap); err != nil {
			return err
		}
	}
	return nil
}

func validatePathParameter(name string, targetParameters []opbinding.TargetParameter, target, arguments map[string]any) error {
	presence := pathParameterPresenceFor(name, targetParameters, target, arguments)
	if presence.targetOwned {
		return validateTargetOwnedPathParameter(presence)
	}
	return validateArgumentOwnedPathParameter(presence)
}

type pathParameterPresence struct {
	name          string
	targetOwned   bool
	argumentFound bool
	targetFound   bool
}

func pathParameterPresenceFor(name string, targetParameters []opbinding.TargetParameter, target, arguments map[string]any) pathParameterPresence {
	_, argumentFound := arguments[name]
	field, targetOwned := targetFieldForPath(name, targetParameters)
	targetFound := targetOwned && targetFieldPresent(field, target)
	return pathParameterPresence{name: name, targetOwned: targetOwned, argumentFound: argumentFound, targetFound: targetFound}
}

func validateTargetOwnedPathParameter(presence pathParameterPresence) error {
	if presence.argumentFound {
		return fmt.Errorf("GitHub path parameter %q must come from the validated target", presence.name)
	}
	if !presence.targetFound {
		return fmt.Errorf("GitHub path parameter %q is missing", presence.name)
	}
	return nil
}

func validateArgumentOwnedPathParameter(presence pathParameterPresence) error {
	if !presence.argumentFound {
		return fmt.Errorf("GitHub path parameter %q is missing", presence.name)
	}
	return nil
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

func (a generatedAdapter) decodeArguments(target, arguments json.RawMessage) (json.RawMessage, json.RawMessage, error) {
	if a.streamDirection() == "upload" {
		return a.decodeStreamUploadArguments(target, arguments)
	}
	if !a.descriptor.Sealed {
		return a.decodePlainArguments(target, arguments)
	}
	return a.decodeSealedArguments(target, arguments)
}

func (a generatedAdapter) decodeStreamUploadArguments(target, arguments json.RawMessage) (json.RawMessage, json.RawMessage, error) {
	stream, err := decodeStreamArguments(arguments)
	if err != nil {
		return nil, nil, err
	}
	if err := schemaregistry.ValidateStreamPublic(a.descriptor.Name, target, stream.Public); err != nil {
		return nil, nil, err
	}
	encoded, _ := json.Marshal(stream)
	return encoded, stream.Public, nil
}

func (a generatedAdapter) decodePlainArguments(target, arguments json.RawMessage) (json.RawMessage, json.RawMessage, error) {
	if err := schemaregistry.ValidateSubmission(a.descriptor.Name, target, arguments); err != nil {
		return nil, nil, err
	}
	return cloneRaw(arguments), arguments, nil
}

func (a generatedAdapter) decodeSealedArguments(target, arguments json.RawMessage) (json.RawMessage, json.RawMessage, error) {
	var protected sealedArguments
	if err := strictjson.Decode(arguments, &protected, true); err != nil || len(protected.Public) == 0 {
		return nil, nil, errors.New("GitHub sealed operation arguments are invalid")
	}
	if err := a.validateSealedEnvelope(protected); err != nil {
		return nil, nil, err
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

func (a generatedAdapter) validateSealedEnvelope(protected sealedArguments) error {
	if a.descriptor.CredentialOutputKind != nil {
		if protected.SealedPayload != nil || !credentialstore.ValidSlot(protected.CredentialSlot) {
			return errors.New("GitHub credential output requires one valid destination slot")
		}
		return nil
	}
	required, err := schemaregistry.SealedArgumentsRequired(a.descriptor.Name)
	if err != nil || protected.CredentialSlot != "" || required && protected.SealedPayload == nil {
		return errors.New("GitHub sealed operation arguments are invalid")
	}
	return nil
}

func (a generatedAdapter) ValidateClient(input Input, client, requestKey string) error {
	if a.streamDirection() == "upload" {
		return a.validateStreamClient(input, client, requestKey)
	}
	if !a.descriptor.Sealed {
		return nil
	}
	return a.validateSealedClient(input, client, requestKey)
}

func (a generatedAdapter) validateStreamClient(input Input, client, requestKey string) error {
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

func (a generatedAdapter) validateSealedClient(input Input, client, requestKey string) error {
	arguments, err := decodeSealedArguments(input.Arguments)
	if err != nil {
		return err
	}
	reference := arguments.SealedPayload
	if a.descriptor.CredentialOutputKind != nil {
		return nil
	}
	if reference == nil {
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
	targetMap, argumentsMap, err := a.resolveInputMaps(input)
	if err != nil {
		return Plan{}, err
	}
	targetMap, credential, canonicalTarget, err := a.resolveTarget(ctx, targetMap, argumentsMap)
	if err != nil {
		return Plan{}, err
	}
	presentation := presentDescriptor(a.descriptor, targetMap)
	authorization := authorizeDescriptor(a.descriptor, a.binding, targetMap, argumentsMap, credential)
	if err := a.annotateCredentialOutput(input, &presentation, &authorization); err != nil {
		return Plan{}, err
	}
	return Plan{
		Operation:         a.descriptor.Name,
		OperationRevision: a.descriptor.OperationRevision,
		Target:            canonicalTarget,
		Arguments:         cloneRaw(input.Arguments),
		Preconditions:     credentialPreconditions(credential),
		Credential:        credential,
		Presentation:      presentation,
		Authorization:     authorization,
	}, nil
}

func (a generatedAdapter) resolveInputMaps(input Input) (map[string]any, map[string]any, error) {
	targetMap, err := decodeObject(input.Target)
	if err != nil {
		return nil, nil, errors.New("GitHub operation target is invalid")
	}
	publicArguments, err := a.publicArguments(input.Arguments)
	if err != nil {
		return nil, nil, err
	}
	argumentsMap, err := decodeObject(publicArguments)
	if err != nil {
		return nil, nil, errors.New("GitHub operation arguments are invalid")
	}
	return targetMap, argumentsMap, nil
}

func (a generatedAdapter) annotateCredentialOutput(input Input, presentation *agentv1.Presentation, authorization *Authorization) error {
	if a.descriptor.CredentialOutputKind == nil {
		return nil
	}
	protected, err := decodeSealedArguments(input.Arguments)
	if err != nil {
		return err
	}
	annotateCredentialOutputPlan(presentation, authorization, protected.CredentialSlot, *a.descriptor.CredentialOutputKind)
	return nil
}

func annotateCredentialOutputPlan(presentation *agentv1.Presentation, authorization *Authorization, slot, kind string) {
	if authorization.Attrs == nil {
		authorization.Attrs = map[string][]string{}
	}
	authorization.Attrs["credential_slot"] = []string{slot}
	authorization.Attrs["credential_kind"] = []string{kind}
	presentation.Summary += " into broker credential slot " + slot
}

func (a generatedAdapter) Authorize(plan Plan) Authorization {
	if plan.Authorization.Operation != "" {
		return plan.Authorization
	}
	targetMap, _ := decodeObject(plan.Target)
	publicArguments, _ := a.publicArguments(plan.Arguments)
	argumentsMap, _ := decodeObject(publicArguments)
	return authorizeDescriptor(a.descriptor, a.binding, targetMap, argumentsMap, plan.Credential)
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
	if a.binding == nil {
		return Outcome{}, errors.New("GitHub adapter is incomplete")
	}
	return a.executeBoundOperation(ctx, plan, targetMap, argumentsMap)
}

func (a generatedAdapter) executeBoundOperation(ctx context.Context, plan Plan, target, arguments map[string]any) (Outcome, error) {
	if a.streamDirection() == "download" {
		return a.executeStreamDownload(ctx, plan, target, arguments)
	}
	if a.descriptor.CredentialOutputKind != nil {
		return a.executeCredentialOutput(ctx, plan, target, arguments)
	}
	result, err := a.manager.ExecuteREST(ctx, plan.Credential, *a.binding, target, arguments)
	if err != nil {
		return Outcome{}, classifyExecutionError(a.binding.Method, err)
	}
	return validatedExecutionResult(*a.binding, a.descriptor.Name, result)
}

func (a generatedAdapter) Reconcile(ctx context.Context, plan Plan) (Outcome, error) {
	if !a.hasAbsenceProofReconciliation() {
		return Outcome{Proven: false}, nil
	}
	target, arguments, err := a.reconciliationInput(plan)
	if err != nil {
		return Outcome{}, err
	}
	execution, err := a.manager.ExecuteREST(ctx, plan.Credential, *a.reconciliation, target, arguments)
	if githubauth.IsNotFound(err) {
		return a.absenceProofOutcome()
	}
	if err != nil {
		return Outcome{}, err
	}
	return Outcome{Proven: false, UpstreamStatus: execution.StatusCode}, nil
}

func (a generatedAdapter) hasAbsenceProofReconciliation() bool {
	return a.binding != nil && a.binding.Reconciliation == "absence-proof" && a.reconciliation != nil
}

func (a generatedAdapter) reconciliationInput(plan Plan) (map[string]any, map[string]any, error) {
	target, err := decodeObject(plan.Target)
	if err != nil {
		return nil, nil, errors.New("GitHub reconciliation target is invalid")
	}
	public, err := a.publicArguments(plan.Arguments)
	if err != nil {
		return nil, nil, err
	}
	arguments, err := decodeObject(public)
	if err != nil {
		return nil, nil, errors.New("GitHub reconciliation arguments are invalid")
	}
	return target, arguments, nil
}

func (a generatedAdapter) absenceProofOutcome() (Outcome, error) {
	result := json.RawMessage(`{}`)
	if err := schemaregistry.ValidateResult(a.descriptor.Name, result); err != nil {
		return Outcome{}, err
	}
	return Outcome{Proven: true, Result: result, UpstreamStatus: http.StatusNotFound}, nil
}

func (a generatedAdapter) Cleanup(plan Plan) error {
	if a.streamDirection() == "upload" {
		stream, err := decodeStreamArguments(plan.Arguments)
		if err != nil {
			return err
		}
		return a.options.StreamStore.Retire(*stream.StreamInput, time.Now().Add(agentops.TerminalRetention))
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
	return validatedExecutionResult(*a.binding, a.descriptor.Name, result)
}

func (a generatedAdapter) executeStreamDownload(ctx context.Context, plan Plan, target, arguments map[string]any) (Outcome, error) {
	if err := a.validateStreamDownloadPlan(plan); err != nil {
		return Outcome{}, err
	}
	response, err := a.manager.ExecuteRESTDownload(ctx, plan.Credential, *a.binding, target, arguments)
	if err != nil {
		return Outcome{}, classifyExecutionError(a.binding.Method, err)
	}
	defer func() { _ = response.Body.Close() }()
	return a.storeStreamDownloadResult(plan, response)
}

func (a generatedAdapter) validateStreamDownloadPlan(plan Plan) error {
	if a.binding == nil || plan.Authorization.Client == "" || strings.TrimSpace(plan.ExecutionID) == "" {
		return errors.New("GitHub stream download plan is invalid")
	}
	return nil
}

func (a generatedAdapter) storeStreamDownloadResult(plan Plan, response *http.Response) (Outcome, error) {
	reference, err := a.options.StreamStore.Put(plan.Authorization.Client, a.descriptor.Name, plan.ExecutionID+"-result", downloadMediaType(response.Header.Get("Content-Type")),
		response.Body, a.binding.ResponseBytesLimit, time.Now().Add(15*time.Minute))
	if err != nil {
		return Outcome{}, err
	}
	encoded, _ := json.Marshal(map[string]any{"stream": reference})
	if err := schemaregistry.ValidateResult(a.descriptor.Name, encoded); err != nil {
		_ = a.options.StreamStore.Delete(reference)
		return Outcome{}, err
	}
	return Outcome{Proven: true, Result: encoded, UpstreamStatus: response.StatusCode}, nil
}

func downloadMediaType(value string) string {
	mediaType := strings.TrimSpace(strings.Split(value, ";")[0])
	if mediaType == "" {
		return "application/octet-stream"
	}
	return mediaType
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
	return a.materializeSealedPayload(protected)
}

func (a generatedAdapter) materializeSealedPayload(protected sealedArguments) (json.RawMessage, error) {
	payload, err := a.options.SealedStore.Consume(*protected.SealedPayload)
	if err != nil {
		return nil, err
	}
	defer zero(payload)
	if err := schemaregistry.ValidateSealedArguments(a.descriptor.Name, payload); err != nil {
		return nil, err
	}
	return a.mergeSealedPayload(protected.Public, payload)
}

func (a generatedAdapter) mergeSealedPayload(publicRaw, payload []byte) (json.RawMessage, error) {
	public, err := decodeObject(publicRaw)
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
	protected, err := a.validateCredentialOutputPlan(plan)
	if err != nil {
		return Outcome{}, err
	}
	result, err := a.manager.ExecuteRESTRaw(ctx, plan.Credential, *a.binding, target, arguments)
	if err != nil {
		return Outcome{}, classifyExecutionError(a.binding.Method, err)
	}
	defer zero(result.Body)
	upstream, err := decodeCredentialResponse(*a.binding, result)
	if err != nil {
		return Outcome{}, err
	}
	return a.storeCredentialOutput(protected.CredentialSlot, result.StatusCode, upstream.Token)
}

func (a generatedAdapter) validateCredentialOutputPlan(plan Plan) (sealedArguments, error) {
	protected, err := decodeSealedArguments(plan.Arguments)
	if err != nil || !credentialstore.ValidSlot(protected.CredentialSlot) || a.binding == nil || a.descriptor.CredentialOutputKind == nil {
		return sealedArguments{}, errors.New("GitHub credential output plan is invalid")
	}
	return protected, nil
}

func (a generatedAdapter) storeCredentialOutput(slot string, statusCode int, upstreamToken string) (Outcome, error) {
	token := []byte(upstreamToken)
	defer zero(token)
	stored, err := a.options.CredentialStore.Put(slot, *a.descriptor.CredentialOutputKind, token)
	if err != nil {
		return Outcome{}, &PossiblePartialError{Err: errors.New("upstream_result_unknown")}
	}
	encoded, _ := json.Marshal(map[string]any{"stored": true, "slot": stored.Slot, "kind": stored.Kind})
	if err := schemaregistry.ValidateResult(a.descriptor.Name, encoded); err != nil {
		return Outcome{}, classifyResponseValidationError(a.binding.Method, err)
	}
	return Outcome{Proven: true, Result: encoded, UpstreamStatus: statusCode}, nil
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

func authorizeDescriptor(descriptor opcatalog.Descriptor, binding *opbinding.Binding, target, arguments map[string]any,
	credential githubauth.Metadata) Authorization {
	attrs := authorizationAttrs(arguments)
	attrs = normalizeOperationAuthorizationAttrs(descriptor.Name, attrs)
	selectors := authorizationSelectorAttrs(binding, arguments)
	if attrs == nil && (len(selectors) > 0 || credential.UserID > 0) {
		attrs = map[string][]string{}
	}
	for key, values := range selectors {
		attrs[key] = values
	}
	if credential.UserID > 0 {
		attrs["actor_id"] = []string{fmt.Sprint(credential.UserID)}
	}
	return Authorization{
		Operation:      descriptor.Name,
		TargetKind:     descriptor.TargetKind,
		TargetFields:   authorizationTargetFields(binding, target, credential),
		Attrs:          attrs,
		CredentialKind: descriptor.CredentialKind,
	}
}

func authorizationSelectorAttrs(binding *opbinding.Binding, arguments map[string]any) map[string][]string {
	if binding == nil || len(binding.AuthorizationParameters) == 0 {
		return nil
	}
	result := make(map[string][]string, len(binding.AuthorizationParameters))
	for _, parameter := range binding.AuthorizationParameters {
		if values := scalarStrings(arguments[parameter.Name]); len(values) > 0 {
			result[parameter.Attribute] = values
		}
	}
	return result
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
				values := scalarStrings(child)
				if name == "branch" {
					for index, value := range values {
						values[index] = canonicalBranchRef(value)
					}
				}
				fields[attribute] = append(fields[attribute], values...)
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
		"branch": "ref", "path": "path", "paths": "path", "permission": "permission", "ref": "ref", "release_state": "release_state",
		"releaseState": "release_state", "resource_id": "resource_id", "resourceId": "resource_id", "role": "role",
		"visibility": "visibility", "workflow": "workflow", "workflow_ref": "workflow_ref", "workflowRef": "workflow_ref",
		"name": "resource_name", "owner": "resource_owner",
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
