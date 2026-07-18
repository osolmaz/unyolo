package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/osolmaz/brokerkit/agentapi"
	"github.com/osolmaz/brokerkit/agentv1"
	bkauthorization "github.com/osolmaz/brokerkit/authorization"
	"github.com/osolmaz/brokerkit/brokers/github/internal/ghplan"
	"github.com/osolmaz/brokerkit/brokers/github/internal/githubauth"
	"github.com/osolmaz/brokerkit/brokers/github/internal/opcatalog"
	"github.com/osolmaz/brokerkit/brokers/github/internal/operations"
	"github.com/osolmaz/brokerkit/brokers/github/internal/policy"
	"github.com/osolmaz/brokerkit/grants"
	"github.com/osolmaz/brokerkit/operationruntime"
	corepolicy "github.com/osolmaz/brokerkit/policy"
	"github.com/osolmaz/brokerkit/state"
	"github.com/osolmaz/brokerkit/usebudget"
)

const operationAuthorizationGrace = 30 * time.Second

func (s *Server) newOperationRuntime() (*operations.Runtime, error) {
	return operationruntime.New(operations.RuntimeOptions{
		Broker:        "gh-broker",
		Operations:    s.operations,
		Admission:     s.admission,
		Registry:      s.operationRegistry.Registry,
		Authorization: s.authorization,
		Grants:        s.grants,
		Decide:        s.policy.DecideAuthorization,
		Project: func(auth operations.Authorization) corepolicy.Request {
			return policy.AuthorizationRequest(auth.Client, auth.Operation, auth.TargetKind, auth.TargetFields, auth.Attrs)
		},
		SetClient: func(plan *operations.Plan, client string) { plan.Authorization.Client = client },
		InputData: func(input operations.Input) (json.RawMessage, json.RawMessage) {
			return input.Target, input.Arguments
		},
		PlanData: func(plan operations.Plan) (json.RawMessage, json.RawMessage) {
			return plan.Target, plan.Arguments
		},
		Prepare:             s.prepareRuntimePlan,
		Load:                s.loadRuntimePlan,
		PlanDigest:          func(grant grants.Grant) string { return grant.Metadata[ghplan.MetadataDigest] },
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
		AuthorizationGrace:  operationAuthorizationGrace,
		Observer:            s.control.Metrics,
		Diagnostics:         s.control.Diagnostics,
	})
}

func (s *Server) prepareRuntimePlan(preparation operations.Preparation) (bkauthorization.GrantIntent, error) {
	adapter, descriptor, err := s.runtimePlanDescriptor(preparation.DescriptorName)
	if err != nil {
		return bkauthorization.GrantIntent{}, err
	}
	mode := runtimeGrantMode(descriptor)
	duration, pending, err := runtimeGrantBounds(adapter, preparation, mode)
	if err != nil {
		return bkauthorization.GrantIntent{}, err
	}
	request := runtimeGrantRequest(preparation, mode, duration, pending, runtimeGrantUses(preparation, mode))
	presentation := adapter.Present(preparation.Plan)
	prepared, err := prepareAdapterPlan(preparation.Plan, request, presentation, string(preparation.Decision.Effect),
		runtimePlanRuleIDs(preparation), preparation.CreatedAt)
	if err != nil {
		return bkauthorization.GrantIntent{}, err
	}
	bindPreparedRuntimePlan(&request, prepared, presentation, preparation.Direct)
	return bkauthorization.GrantIntent{Mode: mode, Authorization: preparation.Core, Request: request, Plan: prepared}, nil
}

func (s *Server) runtimePlanDescriptor(name string) (operations.Adapter, opcatalog.Descriptor, error) {
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

func runtimeGrantMode(descriptor opcatalog.Descriptor) corepolicy.GrantMode {
	if descriptor.AuthorizationMode == opcatalog.ModeExecution {
		return corepolicy.GrantModeExecution
	}
	return corepolicy.GrantModeWindow
}

func runtimeGrantBounds(adapter operations.Adapter, preparation operations.Preparation, mode corepolicy.GrantMode) (time.Duration, time.Duration, error) {
	duration := time.Duration(adapter.Descriptor().ApprovalTTLSeconds) * time.Second
	pending := time.Duration(adapter.Descriptor().RequestTTLSeconds) * time.Second
	if preparation.Direct {
		return duration, pending, nil
	}
	if preparation.ReusedGrant != nil {
		grant := *preparation.ReusedGrant
		if corepolicy.GrantMode(grant.Metadata["github_grant_mode"]) != mode || mode != corepolicy.GrantModeWindow {
			return 0, 0, errors.New("active grant approval mode does not match operation")
		}
		duration = grant.RequestedDuration
		if duration <= 0 {
			duration = grant.Duration
		}
		return duration, grant.PendingTimeout, nil
	}
	bounds := preparation.Decision.GrantPolicy
	if bounds == nil || corepolicy.GrantMode(bounds.Mode) != mode {
		return 0, 0, errors.New("operation approval mode does not match policy")
	}
	return min(time.Duration(bounds.DefaultMinutes)*time.Minute, duration),
		min(time.Duration(bounds.RequestTTLMinutes)*time.Minute, pending), nil
}

func runtimeGrantRequest(preparation operations.Preparation, mode corepolicy.GrantMode, duration time.Duration,
	pending time.Duration, maxUses usebudget.Limit) grants.Request {
	return grants.Request{
		Client: preparation.Client, ClientRequestID: preparation.OperationID, Operation: preparation.DescriptorName,
		Target: preparation.Core.Target, Attrs: preparation.Core.Attrs, Reason: preparation.Reason,
		Duration: duration, PendingTimeout: pending, MaxUses: maxUses, MaxUsesSpecified: true,
		Metadata: map[string]string{"github_grant_mode": string(mode)},
	}
}

func runtimeGrantUses(preparation operations.Preparation, mode corepolicy.GrantMode) usebudget.Limit {
	if preparation.Direct || mode == corepolicy.GrantModeExecution {
		return 1
	}
	if preparation.ReusedGrant != nil {
		return preparation.ReusedGrant.RequestedMaxUses
	}
	return preparation.Decision.GrantPolicy.DefaultMaxUses
}

func runtimePlanRuleIDs(preparation operations.Preparation) []string {
	if preparation.Direct {
		return preparation.Decision.MatchedAllowRuleIDs
	}
	if preparation.ReusedGrant != nil {
		return preparation.Decision.MatchedGrantRuleIDs
	}
	return preparation.Decision.MatchedRequestRuleIDs
}

func bindPreparedRuntimePlan(request *grants.Request, prepared grants.ImmutablePlan, presentation agentv1.Presentation, direct bool) {
	if direct {
		return
	}
	ghplan.BindPrepared(request, prepared)
	ghplan.BindPresentation(request, presentation)
}

func prepareAdapterPlan(provider operations.Plan, request grants.Request, presentation agentv1.Presentation, policyEffect string, policyRuleIDs []string, createdAt time.Time) (grants.ImmutablePlan, error) {
	kind := string(provider.Credential.Kind)
	return ghplan.Prepare(ghplan.Plan{
		APIVersion: ghplan.SchemaV1, Operation: provider.Operation, OperationRevision: provider.OperationRevision,
		ClientID: request.Client, ClientRequestID: request.ClientRequestID, Target: provider.Target, Arguments: provider.Arguments,
		Preconditions: provider.Preconditions, CredentialSelector: ghplan.CredentialSelector{Name: "primary", Kind: kind}, Presentation: presentation,
		Authorization: ghplan.Authorization{Mode: request.Metadata["github_grant_mode"], RequestedDurationSeconds: int64(request.Duration.Seconds()),
			RequestedMaxUses: request.MaxUses, RequestedMaxUsesDefaulted: request.MaxUsesDefaulted,
			Target: ghplan.GrantTarget{Kind: request.Target.Kind, Fields: request.Target.Fields}, Attributes: request.Attrs,
			PolicyEffect: policyEffect, PolicyRuleIDs: append([]string(nil), policyRuleIDs...)},
		CreatedAt: createdAt.UTC(), ExpiresAt: createdAt.Add(request.PendingTimeout + request.Duration).UTC(),
	})
}

func (s *Server) loadRuntimePlan(operation agentv1.Operation, adapter operations.Adapter) (operations.Plan, error) {
	envelope, err := s.plans.Get(operation.PlanDigest)
	if err != nil || !runtimeEnvelopeMatchesOperation(envelope, operation, adapter) {
		return operations.Plan{}, errors.New("operation plan binding is invalid")
	}
	credential, err := runtimeEnvelopeCredential(envelope)
	if err != nil {
		return operations.Plan{}, errors.New("operation credential binding is invalid")
	}
	plan := runtimePlanFromEnvelope(operation, envelope, credential)
	if !runtimePlanPayloadMatches(adapter, plan) {
		return operations.Plan{}, errors.New("operation plan payload is invalid")
	}
	plan.Authorization = runtimePlanAuthorization(adapter, operation, plan)
	if plan.Authorization.Operation == "" {
		return operations.Plan{}, errors.New("operation policy metadata is invalid")
	}
	return plan, nil
}

func runtimeEnvelopeMatchesOperation(envelope ghplan.Plan, operation agentv1.Operation, adapter operations.Adapter) bool {
	return envelope.Operation == operation.Operation &&
		envelope.OperationRevision == adapter.Descriptor().OperationRevision &&
		envelope.ClientID == operation.ClientID &&
		envelope.ClientRequestID == operation.ID &&
		!envelope.ExpiresAt.Before(time.Now().UTC())
}

func runtimeEnvelopeCredential(envelope ghplan.Plan) (githubauth.Metadata, error) {
	credential, err := operations.CredentialFromPreconditions(envelope.Preconditions)
	if err != nil || string(credential.Kind) != envelope.CredentialSelector.Kind {
		return githubauth.Metadata{}, errors.New("operation credential binding is invalid")
	}
	return credential, nil
}

func runtimePlanFromEnvelope(operation agentv1.Operation, envelope ghplan.Plan, credential githubauth.Metadata) operations.Plan {
	return operations.Plan{
		ExecutionID: operation.ID, Operation: envelope.Operation, OperationRevision: envelope.OperationRevision, Target: envelope.Target,
		Arguments: envelope.Arguments, Preconditions: envelope.Preconditions, Credential: credential, Presentation: envelope.Presentation,
		PolicyDecision: operations.PolicyDecision{Effect: envelope.Authorization.PolicyEffect, RuleIDs: envelope.Authorization.PolicyRuleIDs},
	}
}

func runtimePlanPayloadMatches(adapter operations.Adapter, plan operations.Plan) bool {
	input, err := adapter.Decode(plan.Target, plan.Arguments)
	return err == nil &&
		operationruntime.EqualJSONObject(input.Target, plan.Target) &&
		operationruntime.EqualJSONObject(input.Arguments, plan.Arguments)
}

func runtimePlanAuthorization(adapter operations.Adapter, operation agentv1.Operation, plan operations.Plan) operations.Authorization {
	authorization := adapter.Authorize(plan)
	authorization.Client = operation.ClientID
	return authorization
}

func definitiveExecutionFailure(err error) bool {
	return err != nil && !operations.IsPossiblePartial(err)
}

func operationExecutionFailure(executionErr, reconcileErr error) operationruntime.Failure {
	failure := operationruntime.Failure{Code: "upstream_result_unknown", Message: "Operation result is unknown and was not retried"}
	var upstream githubauth.APIError
	if errors.As(executionErr, &upstream) && upstream.StatusCode > 0 && upstream.StatusCode < http.StatusInternalServerError {
		failure.Code, failure.Message = upstream.Code, "GitHub rejected the operation"
	} else if executionErr == nil && reconcileErr != nil {
		failure.Code, failure.Message = "operation_reconciliation_failed", "Operation completed but reconciliation failed"
	}
	return failure
}

func mapOperationSubmissionError(err error) error {
	var upstream githubauth.APIError
	if errors.As(err, &upstream) {
		status := http.StatusBadGateway
		if upstream.StatusCode == http.StatusNotFound {
			status = http.StatusNotFound
		}
		return &agentapi.Error{Status: status, Code: upstream.Code, Message: "Could not resolve GitHub operation target"}
	}
	return &agentapi.Error{Status: http.StatusBadRequest, Code: "operation_input_invalid", Message: err.Error()}
}

func (s *Server) recordOperationPolicyRefusal(operation agentv1.Operation, plan operations.Plan, decision corepolicy.Decision, code string) {
	providerDecision := s.policy.AuthorizationDecision(decision)
	s.recordOperationPolicyDecision(operation.ClientID, operation.Operation, operationPolicyTarget(plan.Authorization), "denied", code, 0, providerDecision)
}

func (s *Server) agentLifecycleContext(fallback context.Context) context.Context {
	if s.lifecycleContext != nil {
		return s.lifecycleContext
	}
	return fallback
}

func (s *Server) submitAgentOperation(ctx context.Context, client string, request agentv1.SubmitRequest) (agentv1.Operation, bool, error) {
	return s.operationRuntime.Submit(s.agentLifecycleContext(ctx), client, request)
}

func (s *Server) cancelAgentOperation(ctx context.Context, client, id string) (agentv1.Operation, error) {
	return s.operationRuntime.Cancel(ctx, client, id)
}

func (s *Server) cancelGrantForClient(grant grants.Grant, client string) error {
	return s.operationRuntime.CancelGrant(grant, client)
}

func (s *Server) startOperationRuntime(ctx context.Context) {
	workerContext, cancel := context.WithCancel(ctx)
	s.lifecycleContext = workerContext
	s.lifecycleCancel = cancel
	s.operationRuntime.Start(workerContext)
}

func operationDebugID(operation agentv1.Operation) string {
	return fmt.Sprintf("%s:%s", operation.Operation, operation.ID)
}
