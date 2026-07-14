package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/osolmaz/brokerkit/agentapi"
	"github.com/osolmaz/brokerkit/agentv1"
	"github.com/osolmaz/brokerkit/audit"
	bkauthorization "github.com/osolmaz/brokerkit/authorization"
	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/hfgrant"
	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/hfplan"
	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/hubclient"
	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/operations"
	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/policy"
	"github.com/osolmaz/brokerkit/grants"
	"github.com/osolmaz/brokerkit/operationruntime"
	corepolicy "github.com/osolmaz/brokerkit/policy"
	"github.com/osolmaz/brokerkit/state"
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
	})
}

func (s *Server) prepareRuntimePlan(preparation operations.Preparation) (bkauthorization.GrantIntent, error) {
	descriptor, found := s.operationRegistry.Lookup(preparation.DescriptorName)
	if !found {
		return bkauthorization.GrantIntent{}, errors.New("operation adapter is unavailable")
	}
	duration := time.Duration(descriptor.Descriptor().ApprovalTTLSeconds) * time.Second
	pending := time.Duration(descriptor.Descriptor().RequestTTLSeconds) * time.Second
	if !preparation.Direct {
		bounds := preparation.Decision.GrantPolicy
		if bounds == nil || corepolicy.GrantMode(bounds.Mode) != corepolicy.GrantModeExecution {
			return bkauthorization.GrantIntent{}, errors.New("operation requires execution approval")
		}
		duration = min(time.Duration(bounds.DefaultMinutes)*time.Minute, duration)
		pending = min(time.Duration(bounds.RequestTTLMinutes)*time.Minute, pending)
	}
	request, err := hfgrant.CanonicalRequest(hfgrant.Input{
		Client: preparation.Client, ClientRequestID: preparation.OperationID, Operation: preparation.DescriptorName,
		Mode: hfgrant.ModeExecution, PolicyTarget: &preparation.Auth.Target, Attrs: preparation.Auth.Attrs,
		Reason: preparation.Reason, RequestedDuration: duration, PendingTimeout: pending,
		MaxUses: 1, MaxUsesSpecified: true,
	})
	if err != nil {
		return bkauthorization.GrantIntent{}, err
	}
	ruleIDs := preparation.Decision.MatchedRequestRuleIDs
	if preparation.Direct {
		ruleIDs = preparation.Decision.MatchedAllowRuleIDs
	}
	prepared, err := prepareAdapterPlan(preparation.Plan, request, descriptor.Present(preparation.Plan),
		string(preparation.Decision.Effect), ruleIDs, preparation.CreatedAt)
	if err != nil {
		return bkauthorization.GrantIntent{}, err
	}
	if !preparation.Direct {
		hfplan.BindPrepared(&request, prepared)
		hfplan.BindPresentation(&request, descriptor.Present(preparation.Plan))
	}
	return bkauthorization.GrantIntent{Mode: corepolicy.GrantModeExecution, Authorization: preparation.Core, Request: request, Plan: prepared}, nil
}

func prepareAdapterPlan(provider operations.Plan, request grants.Request, presentation agentv1.Presentation, policyEffect string, policyRuleIDs []string, createdAt time.Time) (grants.ImmutablePlan, error) {
	expiresAt := createdAt.Add(request.PendingTimeout + request.Duration)
	return hfplan.Prepare(hfplan.Plan{
		APIVersion: hfplan.SchemaV1, Operation: provider.Operation, OperationRevision: provider.OperationRevision,
		ClientID: request.Client, ClientRequestID: request.ClientRequestID, Target: provider.Target, Arguments: provider.Arguments,
		Preconditions: provider.Preconditions, CredentialSelector: hfplan.CredentialSelector{Name: "primary"}, Presentation: presentation,
		Authorization: hfplan.Authorization{Mode: hfgrant.ModeExecution, RequestedDurationSeconds: int64(request.Duration.Seconds()),
			RequestedMaxUses: 1, Target: hfplan.GrantTarget{Kind: request.Target.Kind, Fields: request.Target.Fields}, Attributes: request.Attrs,
			PolicyEffect: policyEffect, PolicyRuleIDs: append([]string(nil), policyRuleIDs...)},
		CreatedAt: createdAt, ExpiresAt: expiresAt,
	})
}

//nolint:cyclop // Immutable HF plan binding checks remain explicit at the provider boundary.
func (s *Server) loadRuntimePlan(operation agentv1.Operation, adapter operations.Adapter) (operations.Plan, error) {
	envelope, err := s.plans.Get(operation.PlanDigest)
	if err != nil || envelope.Operation != operation.Operation || envelope.OperationRevision != adapter.Descriptor().OperationRevision ||
		envelope.ClientID != operation.ClientID || envelope.ClientRequestID != operation.ID || envelope.ExpiresAt.Before(s.utcNow()) {
		return operations.Plan{}, errors.New("operation plan binding is invalid")
	}
	plan := operations.Plan{Operation: envelope.Operation, OperationRevision: envelope.OperationRevision, Target: envelope.Target,
		Arguments: envelope.Arguments, Preconditions: envelope.Preconditions, Presentation: envelope.Presentation,
		PolicyDecision: operations.PolicyDecision{Effect: envelope.Authorization.PolicyEffect, RuleIDs: envelope.Authorization.PolicyRuleIDs}}
	input, err := adapter.Decode(plan.Target, plan.Arguments)
	if err != nil || !operationruntime.EqualJSONObject(input.Target, plan.Target) || !operationruntime.EqualJSONObject(input.Arguments, plan.Arguments) {
		return operations.Plan{}, errors.New("operation plan payload is invalid")
	}
	if bound, ok := adapter.(operations.ClientBoundAdapter); ok {
		if err := bound.ValidateClient(input, operation.ClientID, operation.IdempotencyKey); err != nil {
			return operations.Plan{}, errors.New("operation client binding is invalid")
		}
	}
	plan.Policy = adapter.Authorize(plan)
	plan.Policy.Client = operation.ClientID
	if plan.Policy.Operation == "" {
		return operations.Plan{}, errors.New("operation policy metadata is invalid")
	}
	return plan, nil
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
	return s.operationRuntime.Submit(s.agentLifecycleContext(ctx), client, request)
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
