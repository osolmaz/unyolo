package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/osolmaz/unyolo/agent/api"
	"github.com/osolmaz/unyolo/agent/v1"
	unyoloauthorization "github.com/osolmaz/unyolo/authorization"
	"github.com/osolmaz/unyolo/authorization/grants"
	corepolicy "github.com/osolmaz/unyolo/authorization/policy"
	"github.com/osolmaz/unyolo/brokers/huggingface/internal/credentialauth"
	"github.com/osolmaz/unyolo/brokers/huggingface/internal/hfgrant"
	"github.com/osolmaz/unyolo/brokers/huggingface/internal/hfplan"
	"github.com/osolmaz/unyolo/brokers/huggingface/internal/hubclient"
	"github.com/osolmaz/unyolo/brokers/huggingface/internal/opcatalog"
	"github.com/osolmaz/unyolo/brokers/huggingface/internal/operations"
	"github.com/osolmaz/unyolo/brokers/huggingface/internal/policy"
	"github.com/osolmaz/unyolo/credential/provider"
	"github.com/osolmaz/unyolo/internal/storage/state"
	"github.com/osolmaz/unyolo/operation/runtime"
	"github.com/osolmaz/unyolo/telemetry/audit"
)

const operationAuthorizationGrace = 30 * time.Second

func (s *Server) newOperationRuntime() (*operations.Runtime, error) {
	return operationruntime.New(operations.RuntimeOptions{
		Broker:        "hf-broker",
		Operations:    s.operations,
		Admission:     s.admission,
		Registry:      s.operationRegistry.Registry,
		Authorization: s.authorization,
		Grants:        s.grants,
		Decide:        s.policy.DecideAuthorization,
		Project:       policy.AuthorizationRequest,
		SetClient: func(plan *operations.Plan, client string) {
			plan.Policy.Client = client
		},
		InputData: func(input operations.Input) (json.RawMessage, json.RawMessage) {
			return input.Target, input.Arguments
		},
		PlanData: func(plan operations.Plan) (json.RawMessage, json.RawMessage) {
			return plan.Target, plan.Arguments
		},
		Prepare:             s.prepareRuntimePlan,
		Load:                s.loadRuntimePlan,
		PlanDigest:          func(grant grants.Grant) string { return grant.Metadata[hfplan.MetadataDigest] },
		StoredPlan:          func(digest string) (state.PlanRecord, error) { return s.database.Plan(context.Background(), digest) },
		ValidateExecution:   s.planValidator.ValidateExecution,
		MapSubmissionError:  mapOperationSubmissionError,
		DefinitiveFailure:   definitiveExecutionFailure,
		ExecutionFailure:    operationExecutionFailure,
		RecordPolicyRefusal: s.recordOperationPolicyRefusal,
		RecordOutcome:       s.recordOperationOutcome,
		Notifier:            s.notifier,
		ApprovalMessage:     grantApprovalMessage,
		OperatorConfigured:  s.operatorConfigured,
		Now:                 s.utcNow,
		AuthorizationGrace:  operationAuthorizationGrace,
		Observer:            s.control.Metrics,
		Diagnostics:         s.control.Diagnostics,
	})
}

func (s *Server) prepareRuntimePlan(preparation operations.Preparation) (unyoloauthorization.GrantIntent, error) {
	adapter, descriptor, err := s.runtimePlanComponents(preparation.DescriptorName)
	if err != nil {
		return unyoloauthorization.GrantIntent{}, err
	}
	mode := runtimeGrantMode(descriptor)
	duration, pending, maxUses, err := preparationBounds(preparation, adapter, mode)
	if err != nil {
		return unyoloauthorization.GrantIntent{}, err
	}
	request, err := hfgrant.CanonicalRequest(hfgrant.Input{
		Client: preparation.Client, ClientRequestID: preparation.OperationID, Operation: preparation.DescriptorName,
		Mode: string(mode), PolicyTarget: &preparation.Auth.Target, Attrs: preparation.Auth.Attrs,
		Reason: preparation.Reason, RequestedDuration: duration, PendingTimeout: pending,
		MaxUses: maxUses, MaxUsesSpecified: true,
	})
	if err != nil {
		return unyoloauthorization.GrantIntent{}, err
	}
	ruleIDs := runtimePolicyRuleIDs(preparation)
	binding, err := runtimeCredentialBinding(s.credential)
	if err != nil {
		return unyoloauthorization.GrantIntent{}, err
	}
	prepared, err := prepareAdapterPlan(preparation.Plan, request, adapter.Present(preparation.Plan),
		string(preparation.Decision.Effect), ruleIDs, preparation.CreatedAt, binding)
	if err != nil {
		return unyoloauthorization.GrantIntent{}, err
	}
	if !preparation.Direct {
		hfplan.BindPrepared(&request, prepared)
		hfplan.BindPresentation(&request, adapter.Present(preparation.Plan))
	}
	return unyoloauthorization.GrantIntent{Mode: mode, Authorization: preparation.Core, Request: request, Plan: prepared}, nil
}

func runtimeCredentialBinding(credential *providercredential.Service) (providercredential.Binding, error) {
	if credential == nil {
		return providercredential.Binding{}, nil
	}
	binding, err := credential.Binding()
	if err != nil {
		return providercredential.Binding{}, errors.New("HF credential binding is unavailable")
	}
	return binding, nil
}

func (s *Server) runtimePlanComponents(name string) (operations.Adapter, opcatalog.Descriptor, error) {
	adapter, found := s.operationRegistry.Lookup(name)
	if !found {
		return nil, opcatalog.Descriptor{}, errors.New("operation adapter is unavailable")
	}
	descriptor, found := opcatalog.ByName(name)
	if !found {
		return nil, opcatalog.Descriptor{}, errors.New("operation descriptor is unavailable")
	}
	return adapter, descriptor, nil
}

func runtimePolicyRuleIDs(preparation operations.Preparation) []string {
	if preparation.Direct {
		return preparation.Decision.MatchedAllowRuleIDs
	}
	if preparation.ReusedGrant != nil {
		return preparation.Decision.MatchedGrantRuleIDs
	}
	return preparation.Decision.MatchedRequestRuleIDs
}

func runtimeGrantMode(descriptor opcatalog.Descriptor) corepolicy.GrantMode {
	if descriptor.AuthorizationMode == opcatalog.ModeExecution {
		return corepolicy.GrantModeExecution
	}
	return corepolicy.GrantModeWindow
}

func preparationBounds(preparation operations.Preparation, descriptor operations.Adapter, mode corepolicy.GrantMode) (time.Duration, time.Duration, int, error) {
	duration := time.Duration(descriptor.Descriptor().ApprovalTTLSeconds) * time.Second
	pending := time.Duration(descriptor.Descriptor().RequestTTLSeconds) * time.Second
	if preparation.Direct {
		return duration, pending, 1, nil
	}
	if preparation.ReusedGrant != nil {
		return reusedPreparationBounds(*preparation.ReusedGrant, mode)
	}
	bounds := preparation.Decision.GrantPolicy
	if bounds == nil || corepolicy.GrantMode(bounds.Mode) != mode {
		return 0, 0, 0, errors.New("operation approval mode does not match policy")
	}
	duration = min(time.Duration(bounds.DefaultMinutes)*time.Minute, duration)
	pending = min(time.Duration(bounds.RequestTTLMinutes)*time.Minute, pending)
	maxUses := 1
	if mode == corepolicy.GrantModeWindow {
		maxUses = int(bounds.DefaultMaxUses)
	}
	return duration, pending, maxUses, nil
}

func reusedPreparationBounds(grant grants.Grant, mode corepolicy.GrantMode) (time.Duration, time.Duration, int, error) {
	if corepolicy.GrantMode(hfgrant.Mode(grant)) != mode || mode != corepolicy.GrantModeWindow {
		return 0, 0, 0, errors.New("active grant approval mode does not match operation")
	}
	duration := grant.RequestedDuration
	if duration <= 0 {
		duration = grant.Duration
	}
	return duration, grant.PendingTimeout, int(grant.RequestedMaxUses), nil
}

func prepareAdapterPlan(provider operations.Plan, request grants.Request, presentation agentv1.Presentation, policyEffect string, policyRuleIDs []string, createdAt time.Time, bindings ...providercredential.Binding) (grants.ImmutablePlan, error) {
	expiresAt := createdAt.Add(request.PendingTimeout + request.Duration)
	var binding providercredential.Binding
	if len(bindings) > 0 {
		binding = bindings[0]
	}
	return hfplan.Prepare(hfplan.Plan{
		APIVersion: hfplan.SchemaV1, Operation: provider.Operation, OperationRevision: provider.OperationRevision,
		ClientID: request.Client, ClientRequestID: request.ClientRequestID, Target: provider.Target, Arguments: provider.Arguments,
		Preconditions: provider.Preconditions, CredentialSelector: hfplan.CredentialSelector{Name: "primary", Binding: binding}, Presentation: presentation,
		Authorization: hfplan.Authorization{Mode: request.Metadata["hf_grant_mode"], RequestedDurationSeconds: int64(request.Duration.Seconds()),
			RequestedMaxUses: request.MaxUses, RequestedMaxUsesDefaulted: request.MaxUsesDefaulted,
			Target: hfplan.GrantTarget{Kind: request.Target.Kind, Fields: request.Target.Fields}, Attributes: request.Attrs,
			PolicyEffect: policyEffect, PolicyRuleIDs: append([]string(nil), policyRuleIDs...)},
		CreatedAt: createdAt, ExpiresAt: expiresAt,
	})
}

func (s *Server) loadRuntimePlan(operation agentv1.Operation, adapter operations.Adapter) (operations.Plan, error) {
	envelope, err := s.plans.Get(operation.PlanDigest)
	if err != nil || !s.runtimePlanEnvelopeMatches(envelope, operation, adapter) {
		return operations.Plan{}, errors.New("operation plan binding is invalid")
	}
	if err := s.planValidator.ValidateCredential(envelope); err != nil {
		return operations.Plan{}, errors.New("operation credential binding is stale or insufficient")
	}
	plan := operations.Plan{Operation: envelope.Operation, OperationRevision: envelope.OperationRevision, Target: envelope.Target,
		Arguments: envelope.Arguments, Preconditions: envelope.Preconditions, Presentation: envelope.Presentation,
		PolicyDecision: operations.PolicyDecision{Effect: envelope.Authorization.PolicyEffect, RuleIDs: envelope.Authorization.PolicyRuleIDs}}
	if err := validateRuntimePlanPayload(plan, operation, adapter); err != nil {
		return operations.Plan{}, err
	}
	plan.Policy = adapter.Authorize(plan)
	plan.Policy.Client = operation.ClientID
	if plan.Policy.Operation == "" {
		return operations.Plan{}, errors.New("operation policy metadata is invalid")
	}
	return plan, nil
}

func (s *Server) runtimePlanEnvelopeMatches(envelope hfplan.Plan, operation agentv1.Operation, adapter operations.Adapter) bool {
	return envelope.Operation == operation.Operation &&
		envelope.OperationRevision == adapter.Descriptor().OperationRevision &&
		envelope.ClientID == operation.ClientID &&
		envelope.ClientRequestID == operation.ID &&
		!envelope.ExpiresAt.Before(s.utcNow())
}

func validateRuntimePlanPayload(plan operations.Plan, operation agentv1.Operation, adapter operations.Adapter) error {
	input, err := adapter.Decode(plan.Target, plan.Arguments)
	if err != nil || !operationruntime.EqualJSONObject(input.Target, plan.Target) || !operationruntime.EqualJSONObject(input.Arguments, plan.Arguments) {
		return errors.New("operation plan payload is invalid")
	}
	return validateRuntimePlanClient(input, operation, adapter)
}

func validateRuntimePlanClient(input operations.Input, operation agentv1.Operation, adapter operations.Adapter) error {
	if bound, ok := adapter.(operations.ClientBoundAdapter); ok {
		if err := bound.ValidateClient(input, operation.ClientID, operation.IdempotencyKey); err != nil {
			return errors.New("operation client binding is invalid")
		}
	}
	return nil
}

func (s *Server) recordOperationPolicyRefusal(operation agentv1.Operation, plan operations.Plan, decision corepolicy.Decision, code string) {
	s.recordPolicyDecision(operation.ClientID, operation.Operation, operationPolicyTarget(plan.Policy), audit.DecisionRefused,
		code, 0, s.policy.AuthorizationDecision(decision))
}

func definitiveExecutionFailure(err error) bool {
	if err == nil || operations.IsPossiblePartial(err) {
		return false
	}
	var upstream *hubclient.Error
	return !errors.As(err, &upstream) || upstream.Definitive()
}

func operationExecutionFailure(executionErr, reconcileErr error) operationruntime.Failure {
	failure := operationruntime.Failure{Code: "upstream_result_unknown", Message: "Operation result is unknown and was not retried"}
	var upstream *hubclient.Error
	if errors.As(executionErr, &upstream) && !upstream.Ambiguous {
		failure.Code, failure.Message = string(upstream.Code), "Hugging Face rejected the operation"
	} else if executionErr != nil && strings.Contains(executionErr.Error(), "operation_precondition_failed") {
		failure.Code, failure.Message = "operation_precondition_failed", "Operation target changed after approval"
	} else if executionErr == nil && reconcileErr != nil {
		failure.Code, failure.Message = "operation_reconciliation_failed", "Operation completed but reconciliation failed"
	}
	return failure
}

func mapOperationSubmissionError(err error) error {
	var upstream *hubclient.Error
	if errors.As(err, &upstream) {
		status := http.StatusBadGateway
		if upstream.Code == hubclient.CodeNotFound {
			status = http.StatusNotFound
		}
		return operationAPIError(status, string(upstream.Code), "Could not resolve operation target")
	}
	if strings.Contains(err.Error(), "already exists") {
		return operationAPIError(http.StatusConflict, "operation_precondition_failed", err.Error())
	}
	return operationAPIError(http.StatusBadRequest, "operation_input_invalid", err.Error())
}

func operationAPIError(status int, code, message string) error {
	return &agentapi.Error{Status: status, Code: code, Message: message}
}

func operationPolicyTarget(request policy.Request) string {
	parts := []string{string(request.Target.Type), request.Target.Owner, request.Target.Name}
	if parts[0] == "" {
		parts = parts[1:]
	}
	return strings.Join(parts, "/")
}

func (s *Server) agentLifecycleContext(fallback context.Context) context.Context {
	if s.lifecycleContext != nil {
		return s.lifecycleContext
	}
	return fallback
}

func (s *Server) submitAgentOperation(ctx context.Context, client string, request agentv1.SubmitRequest) (agentv1.Operation, bool, error) {
	if s.credential != nil {
		requirement, found := (credentialauth.Adapter{}).Requirement(request.Operation)
		target, err := operationCredentialTarget(request.Operation, request.Target)
		if !found || err != nil {
			return agentv1.Operation{}, false, operationAPIError(http.StatusBadRequest, "operation_input_invalid", "Operation credential requirement is unavailable")
		}
		if evaluation := s.credential.Evaluate(requirement, target); !evaluation.Allowed {
			return agentv1.Operation{}, false, operationAPIError(http.StatusForbidden, "operation_credential_capability_missing", "Provider credential does not cover this operation target: "+strings.Join(evaluation.Missing, ", "))
		}
	}
	return s.operationRuntime.Submit(s.agentLifecycleContext(ctx), client, request)
}

func operationCredentialTarget(operation string, raw json.RawMessage) (providercredential.Target, error) {
	target, err := providercredential.TargetFromJSON(raw)
	if err != nil {
		return nil, err
	}
	descriptor, found := opcatalog.ByName(operation)
	if !found {
		return nil, errors.New("operation credential target kind is unavailable")
	}
	if target["resource"] != "" {
		target["resource_kind"] = descriptor.TargetKind
	}
	return target, nil
}

func (s *Server) discoverAgent(_ string) agentv1.Descriptor {
	descriptor := agentv1.Descriptor{APIVersion: agentv1.APIVersion, Operations: []string{}}
	if s.credential == nil {
		return descriptor
	}
	snapshot, err := s.credential.Snapshot()
	if err != nil {
		return descriptor
	}
	descriptor.Credential = agentv1.CredentialDescriptor{Ready: snapshot.VerificationState == providercredential.VerificationValid,
		Provider: snapshot.Provider, CredentialKind: snapshot.CredentialKind, Generation: snapshot.Generation,
		VerificationState: string(snapshot.VerificationState)}
	adapter := credentialauth.Adapter{}
	for _, operation := range opcatalog.MustAll() {
		if !operation.AgentFacing || !operations.AgentRuntimeBound(operation) {
			continue
		}
		requirement, found := adapter.Requirement(operation.Name)
		if found && s.credential.CanSatisfy(requirement, s.utcNow()) {
			descriptor.Operations = append(descriptor.Operations, operation.Name)
		}
	}
	return descriptor
}

func (s *Server) cancelAgentOperation(ctx context.Context, client, id string) (agentv1.Operation, error) {
	return s.operationRuntime.Cancel(ctx, client, id)
}

func (s *Server) cancelGrantForClient(grant grants.Grant, client string) error {
	return s.operationRuntime.CancelGrant(grant, client)
}

// The following narrow delegations keep HF's provider-level behavior tests
// focused while all lifecycle state transitions are owned by operationruntime.
func (s *Server) reconcileInterruptedOperation(ctx context.Context, operation agentv1.Operation) {
	s.operationRuntime.ReconcileInterrupted(ctx, operation)
}

func (s *Server) advanceOperations(ctx context.Context) { s.operationRuntime.AdvanceAll(ctx) }

func (s *Server) advanceOperation(ctx context.Context, operation agentv1.Operation) {
	s.operationRuntime.Advance(ctx, operation)
}

func (s *Server) recoverOperationApproval(operation agentv1.Operation) agentv1.Operation {
	return s.operationRuntime.RecoverApproval(operation)
}

func (s *Server) executeOperation(ctx context.Context, operation agentv1.Operation) {
	s.operationRuntime.Execute(ctx, operation)
}

func (s *Server) succeedExecutedOperation(operation agentv1.Operation, plan operations.Plan, result json.RawMessage, reserved bool, detail string) {
	s.operationRuntime.Succeed(operation, plan, result, reserved, detail)
}

func (s *Server) failOperationExecution(operation agentv1.Operation, plan operations.Plan, executionErr, reconcileErr error) {
	s.operationRuntime.FailExecution(operation, plan, executionErr, reconcileErr)
}

func (s *Server) loadOperationPlan(operation agentv1.Operation) (operations.Adapter, operations.Plan, error) {
	return s.operationRuntime.Load(operation)
}

func normalizedOperationResult(operation string, result json.RawMessage) json.RawMessage {
	return operationruntime.NormalizedResult(operation, result)
}

func planRecord(plan grants.ImmutablePlan) state.PlanRecord { return operationruntime.PlanRecord(plan) }

func operationDebugID(operation agentv1.Operation) string {
	return fmt.Sprintf("%s:%s", operation.Operation, operation.ID)
}
