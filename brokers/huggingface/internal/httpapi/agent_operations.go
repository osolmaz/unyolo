package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/osolmaz/brokerkit/agentapi"
	"github.com/osolmaz/brokerkit/agentops"
	"github.com/osolmaz/brokerkit/agentv1"
	"github.com/osolmaz/brokerkit/audit"
	bkauthorization "github.com/osolmaz/brokerkit/authorization"
	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/hfgrant"
	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/hfplan"
	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/hubclient"
	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/operations"
	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/policy"
	"github.com/osolmaz/brokerkit/grants"
	corepolicy "github.com/osolmaz/brokerkit/policy"
	"github.com/osolmaz/brokerkit/state"
)

const operationAuthorizationGrace = 30 * time.Second

var errApprovalNotificationClaimed = errors.New("approval notification is already claimed")

func (s *Server) cancelAgentOperation(_ context.Context, client, id string) (agentv1.Operation, error) {
	lock := s.operationAuthorizationLock(id)
	lock.Lock()
	defer lock.Unlock()
	operation, err := s.operations.Get(client, id)
	if err != nil || operation.State.Terminal() {
		return operation, err
	}
	if operation.State == agentv1.StateExecuting {
		return agentv1.Operation{}, agentops.ErrNotCancelable
	}
	if err := s.cancelOperationApproval(operation, client); err != nil {
		return agentv1.Operation{}, err
	}
	operation, err = s.operations.Cancel(client, operation.ID)
	if err != nil {
		return agentv1.Operation{}, err
	}
	s.cleanupOperationPlan(operation)
	return operation, nil
}

func (s *Server) cancelOperationApproval(operation agentv1.Operation, client string) error {
	if operation.ApprovalID == "" {
		return nil
	}
	grant, err := s.grants.Get(operation.ApprovalID)
	if err != nil {
		return err
	}
	return s.cancelGrantForClient(grant, client)
}

func (s *Server) cancelGrantForClient(grant grants.Grant, client string) error {
	switch grant.Status {
	case grants.StatusPending:
		_, err := s.grants.CancelForClient(grant.ID, client)
		return err
	case grants.StatusActive:
		_, err := s.grants.RevokeForClient(grant.ID, client)
		return err
	default:
		return nil
	}
}

func (s *Server) submitAgentOperation(ctx context.Context, client string, request agentv1.SubmitRequest) (agentv1.Operation, bool, error) {
	ctx = s.agentLifecycleContext(ctx)
	adapter, input, err := s.decodeAgentOperation(request)
	if err != nil {
		return agentv1.Operation{}, false, err
	}
	submissionLock := stripedOperationLock("submit:"+client+":"+request.IdempotencyKey, s.operationSubmissionLocks[:])
	submissionLock.Lock()
	defer submissionLock.Unlock()
	if existing, found, err := s.replayedOperation(client, request, input); err != nil || found {
		return existing, false, err
	}
	if err := validateOperationClient(adapter, input, client); err != nil {
		return agentv1.Operation{}, false, err
	}
	resolved, err := adapter.Resolve(ctx, input)
	if err != nil {
		return agentv1.Operation{}, false, mapOperationSubmissionError(err)
	}
	resolved.Policy.Client = client
	return s.submitResolvedAgentOperation(ctx, client, request, adapter, resolved)
}

func (s *Server) submitResolvedAgentOperation(ctx context.Context, client string, request agentv1.SubmitRequest, adapter operations.Adapter, resolved operations.Plan) (agentv1.Operation, bool, error) {
	operationID, err := s.operations.NewID()
	if err != nil {
		s.cleanupResolvedOperation(adapter, resolved)
		return agentv1.Operation{}, false, err
	}
	submission := operationSubmission(operationID, client, request, adapter.Present(resolved), resolved)
	prepared, direct, err := s.prepareStaticDirectOperation(adapter, resolved, operationID, request.Reason)
	if err != nil {
		s.cleanupResolvedOperation(adapter, resolved)
		return agentv1.Operation{}, false, err
	}
	if direct {
		return s.submitDirectAgentOperation(submission, prepared, adapter, resolved)
	}
	operationLock := s.operationAuthorizationLock(operationID)
	operationLock.Lock()
	operation, created, err := s.operations.Submit(submission)
	if err != nil {
		operationLock.Unlock()
		s.cleanupResolvedOperation(adapter, resolved)
		return operation, created, err
	}
	if !created {
		operationLock.Unlock()
		return operation, created, err
	}
	operation, grant, err := s.authorizeAndSubmitOperation(adapter, resolved, operation, request.Reason)
	operationLock.Unlock()
	if err != nil || grant.ID == "" {
		return operation, true, err
	}
	return s.bindOperationApproval(ctx, operation, grant), true, nil
}

func (s *Server) submitDirectAgentOperation(submission agentops.Submit, prepared grants.ImmutablePlan, adapter operations.Adapter, resolved operations.Plan) (agentv1.Operation, bool, error) {
	operation, created, err := s.operations.SubmitApprovedWithPlan(submission, planRecord(prepared))
	if err != nil {
		s.cleanupResolvedOperation(adapter, resolved)
	}
	return operation, created, err
}

func (s *Server) decodeAgentOperation(request agentv1.SubmitRequest) (operations.Adapter, operations.Input, error) {
	adapter, found := s.operationRegistry.Lookup(request.Operation)
	if !found {
		return nil, operations.Input{}, operationAPIError(http.StatusBadRequest, "operation_not_registered", "Operation is not registered")
	}
	input, err := adapter.Decode(request.Target, request.Arguments)
	if err != nil {
		return nil, operations.Input{}, operationAPIError(http.StatusBadRequest, "operation_input_invalid", err.Error())
	}
	return adapter, input, nil
}

func validateOperationClient(adapter operations.Adapter, input operations.Input, client string) error {
	bound, ok := adapter.(operations.ClientBoundAdapter)
	if !ok {
		return nil
	}
	if err := bound.ValidateClient(input, client); err != nil {
		return operationAPIError(http.StatusBadRequest, "operation_input_invalid", err.Error())
	}
	return nil
}

func operationSubmission(operationID, client string, request agentv1.SubmitRequest, presentation agentv1.Presentation, plan operations.Plan) agentops.Submit {
	return agentops.Submit{
		ID: operationID, Broker: "hf-broker", ClientID: client, IdempotencyKey: request.IdempotencyKey,
		Operation: request.Operation, Target: plan.Target, Arguments: plan.Arguments, Reason: request.Reason, Presentation: presentation,
	}
}

func (s *Server) prepareStaticDirectOperation(adapter operations.Adapter, plan operations.Plan, operationID, reason string) (grants.ImmutablePlan, bool, error) {
	request := policy.AuthorizationRequest(adapter.Authorize(plan))
	decision := s.policy.DecideAuthorization(request, corepolicy.DecisionOptions{Now: s.utcNow()})
	if !decision.Allowed || len(decision.MatchedAllowRuleIDs) == 0 {
		return grants.ImmutablePlan{}, false, nil
	}
	prepared, err := s.prepareDirectOperationPlan(adapter, plan, request.Client, operationID, reason, decision)
	return prepared, true, err
}

func (s *Server) agentLifecycleContext(fallback context.Context) context.Context {
	if s.lifecycleContext != nil {
		return s.lifecycleContext
	}
	return fallback
}

func (s *Server) replayedOperation(client string, request agentv1.SubmitRequest, input operations.Input) (agentv1.Operation, bool, error) {
	existing, err := s.operations.GetByIdempotency(client, request.IdempotencyKey)
	if errors.Is(err, agentops.ErrNotFound) {
		return agentv1.Operation{}, false, nil
	}
	if err != nil {
		return agentv1.Operation{}, false, err
	}
	if existing.Operation != request.Operation || existing.Reason != strings.TrimSpace(request.Reason) ||
		!equalJSONObject(existing.Target, input.Target) || !equalJSONObject(existing.Arguments, input.Arguments) {
		return agentv1.Operation{}, false, agentops.ErrIdempotencyConflict
	}
	return existing, true, nil
}

func (s *Server) authorizeAndSubmitOperation(adapter operations.Adapter, plan operations.Plan, operation agentv1.Operation, reason string) (agentv1.Operation, grants.Grant, error) {
	authorizationRequest := policy.AuthorizationRequest(adapter.Authorize(plan))
	var prepared grants.ImmutablePlan
	result, authorizationErr := s.authorization.RequestApproval(authorizationRequest, func(decision corepolicy.Decision) (bkauthorization.GrantIntent, error) {
		intent, immutable, err := s.prepareOperationIntent(adapter, plan, operation.ClientID, operation.ID, reason, decision)
		prepared = immutable
		return intent, err
	})
	if authorizationErr != nil {
		_ = s.abandonOperationApproval(result.Request.Grant.ID, operation.ClientID)
		s.cleanupResolvedOperation(adapter, plan)
		return s.finishRefusedOperation(operation, plan, result, authorizationErr), grants.Grant{}, nil
	}
	if prepared.Digest == "" {
		s.cleanupResolvedOperation(adapter, plan)
		return s.failOperation(operation.ID, agentv1.StateFailed, "operation_plan_invalid", "Could not prepare immutable operation plan"), grants.Grant{}, nil
	}
	bound, err := s.operations.BindPlan(operation.ID, planRecord(prepared), result.Request.Grant.ID, false)
	if err != nil {
		_ = s.abandonOperationApproval(result.Request.Grant.ID, operation.ClientID)
		s.cleanupResolvedOperation(adapter, plan)
		return s.failOperation(operation.ID, agentv1.StateFailed, "operation_store_unavailable", "Could not bind operation plan"), grants.Grant{}, nil //nolint:nilerr // The durable operation carries the terminal failure.
	}
	return bound, result.Request.Grant, nil
}

func (s *Server) prepareOperationIntent(adapter operations.Adapter, plan operations.Plan, client, operationID, reason string, decision corepolicy.Decision) (bkauthorization.GrantIntent, grants.ImmutablePlan, error) {
	bounds := decision.GrantPolicy
	if bounds == nil || corepolicy.GrantMode(bounds.Mode) != corepolicy.GrantModeExecution {
		return bkauthorization.GrantIntent{}, grants.ImmutablePlan{}, errors.New("operation requires execution approval")
	}
	descriptor := adapter.Descriptor()
	duration := min(time.Duration(bounds.DefaultMinutes)*time.Minute, time.Duration(descriptor.ApprovalTTLSeconds)*time.Second)
	pending := min(time.Duration(bounds.RequestTTLMinutes)*time.Minute, time.Duration(descriptor.RequestTTLSeconds)*time.Second)
	request, err := hfgrant.CanonicalRequest(hfgrant.Input{
		Client: client, ClientRequestID: operationID, Operation: descriptor.Name, Mode: hfgrant.ModeExecution,
		PolicyTarget: &plan.Policy.Target, Attrs: plan.Policy.Attrs, Reason: reason,
		RequestedDuration: duration, PendingTimeout: pending, MaxUses: 1, MaxUsesSpecified: true,
	})
	if err != nil {
		return bkauthorization.GrantIntent{}, grants.ImmutablePlan{}, err
	}
	presentation := adapter.Present(plan)
	prepared, err := prepareAdapterPlan(plan, request, presentation, string(decision.Effect), decision.MatchedRequestRuleIDs, s.utcNow())
	if err != nil {
		return bkauthorization.GrantIntent{}, grants.ImmutablePlan{}, err
	}
	hfplan.BindPrepared(&request, prepared)
	hfplan.BindPresentation(&request, presentation)
	return bkauthorization.GrantIntent{Mode: corepolicy.GrantModeExecution, Authorization: policy.AuthorizationRequest(plan.Policy), Request: request, Plan: prepared}, prepared, nil
}

func (s *Server) prepareDirectOperationPlan(adapter operations.Adapter, plan operations.Plan, client, operationID, reason string, decision corepolicy.Decision) (grants.ImmutablePlan, error) {
	descriptor := adapter.Descriptor()
	request, err := hfgrant.CanonicalRequest(hfgrant.Input{
		Client: client, ClientRequestID: operationID, Operation: descriptor.Name, Mode: hfgrant.ModeExecution,
		PolicyTarget: &plan.Policy.Target, Attrs: plan.Policy.Attrs, Reason: reason,
		RequestedDuration: time.Duration(descriptor.ApprovalTTLSeconds) * time.Second,
		PendingTimeout:    time.Duration(descriptor.RequestTTLSeconds) * time.Second, MaxUses: 1, MaxUsesSpecified: true,
	})
	if err != nil {
		return grants.ImmutablePlan{}, err
	}
	return prepareAdapterPlan(plan, request, adapter.Present(plan), string(decision.Effect), decision.MatchedAllowRuleIDs, s.utcNow())
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

func (s *Server) finishRefusedOperation(operation agentv1.Operation, plan operations.Plan, result bkauthorization.Result, err error) agentv1.Operation {
	decision := s.policy.AuthorizationDecision(result.Decision)
	target := operationPolicyTarget(plan.Policy)
	if errors.Is(err, bkauthorization.ErrDenied) {
		s.recordPolicyDecision(operation.ClientID, operation.Operation, target, audit.DecisionRefused, "operation_policy_denied", 0, decision)
		return s.failOperation(operation.ID, agentv1.StateDenied, "operation_policy_denied", "Policy denied this operation")
	}
	if errors.Is(err, bkauthorization.ErrNoMatch) {
		s.recordPolicyDecision(operation.ClientID, operation.Operation, target, audit.DecisionRefused, "operation_policy_denied", 0, decision)
		return s.failOperation(operation.ID, agentv1.StateDenied, "operation_policy_denied", "No policy rule allows this operation")
	}
	return s.failOperation(operation.ID, agentv1.StateFailed, "approval_request_failed", "Could not create approval request")
}

func (s *Server) bindOperationApproval(ctx context.Context, operation agentv1.Operation, grant grants.Grant) agentv1.Operation {
	if s.notifier != nil {
		if err := s.notifyOperationApproval(ctx, grant); err != nil {
			if errors.Is(err, errApprovalNotificationClaimed) || s.operatorConfigured {
				return operation
			}
			return s.failUnnotifiedOperation(operation, grant, "approval_notification_failed", "Could not notify the operator")
		}
		return operation
	}
	if !s.operatorConfigured {
		return s.failUnnotifiedOperation(operation, grant, "approval_channel_not_configured", "Approval channel is not configured")
	}
	return operation
}

func (s *Server) failUnnotifiedOperation(operation agentv1.Operation, grant grants.Grant, code, message string) agentv1.Operation {
	if s.abandonOperationApproval(grant.ID, operation.ClientID) != nil {
		return operation
	}
	return s.failOperation(operation.ID, agentv1.StateFailed, code, message)
}

func (s *Server) abandonOperationApproval(id, client string) error {
	if id == "" {
		return nil
	}
	grant, err := s.grants.Get(id)
	if err != nil {
		return err
	}
	return s.cancelGrantForClient(grant, client)
}

func (s *Server) cleanupResolvedOperation(adapter operations.Adapter, plan operations.Plan) {
	cleaner, ok := adapter.(operations.PlanCleaner)
	if ok {
		_ = cleaner.Cleanup(plan)
	}
}

func (s *Server) notifyOperationApproval(ctx context.Context, grant grants.Grant) error {
	claim, claimed, err := s.grants.ClaimNotification(grant.ID, grantNotificationClaimLease)
	if err != nil {
		return err
	}
	if !claimed {
		current, getErr := s.grants.Get(grant.ID)
		if getErr == nil && current.Notification != nil {
			return nil
		}
		return errApprovalNotificationClaimed
	}
	ref, err := s.notifier.SendApproval(ctx, grantApprovalMessage(claim.Grant, claim.DecisionToken))
	if err != nil || ref.MessageID <= 0 {
		return s.settleOperationNotificationFailure(claim, err)
	}
	current, recorded, err := s.grants.SetNotificationIfClaimed(claim.Grant.ID, claim.Grant.NotificationClaimedAt, ref)
	if err != nil || !recorded && current.Notification == nil {
		return s.settleOperationNotificationFailure(claim, err)
	}
	return nil
}

func (s *Server) settleOperationNotificationFailure(claim grants.NotificationClaim, cause error) error {
	if s.operatorConfigured {
		_, _, err := s.grants.RetainNotificationClaim(claim.Grant.ID, claim.Grant.NotificationClaimedAt)
		return errors.Join(cause, err)
	}
	_, _, err := s.grants.CancelIfNotificationClaimed(claim.Grant.ID, claim.Grant.NotificationClaimedAt)
	return errors.Join(cause, err)
}

func (s *Server) operationAuthorizationLock(id string) *sync.Mutex {
	return stripedOperationLock(id, s.operationAuthLocks[:])
}

func stripedOperationLock(id string, locks []sync.Mutex) *sync.Mutex {
	var hash uint64 = 14695981039346656037
	for i := 0; i < len(id); i++ {
		hash ^= uint64(id[i])
		hash *= 1099511628211
	}
	return &locks[hash%uint64(len(locks))]
}

func (s *Server) failOperation(id string, state agentv1.State, code, message string) agentv1.Operation {
	operation, err := s.operations.Fail(id, state, code, message)
	if err != nil {
		operation, _ = s.operations.GetByID(id)
	}
	s.cleanupOperationPlan(operation)
	return operation
}

func (s *Server) cleanupOperationPlan(operation agentv1.Operation) {
	adapter, found := s.operationRegistry.Lookup(operation.Operation)
	cleaner, cleanable := adapter.(operations.PlanCleaner)
	if !found || !cleanable || operation.PlanDigest == "" {
		return
	}
	envelope, err := s.plans.Get(operation.PlanDigest)
	if err != nil {
		return
	}
	_ = cleaner.Cleanup(operations.Plan{Operation: envelope.Operation, OperationRevision: envelope.OperationRevision,
		Target: envelope.Target, Arguments: envelope.Arguments, Preconditions: envelope.Preconditions})
}

func (s *Server) startOperationWorker(ctx context.Context) {
	s.backgroundWorkers.Add(1)
	go func() {
		defer s.backgroundWorkers.Done()
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()
		s.recoverOperations(ctx)
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.advanceOperations(ctx)
			}
		}
	}()
}

func (s *Server) recoverOperations(ctx context.Context) {
	values, err := s.operations.ListUnfinished()
	if err != nil {
		return
	}
	for _, operation := range values {
		if operation.State == agentv1.StateExecuting {
			s.reconcileInterruptedOperation(ctx, operation)
			continue
		}
		s.advanceOperation(ctx, operation)
	}
}

func (s *Server) advanceOperations(ctx context.Context) {
	values, err := s.operations.ListUnfinished()
	if err != nil {
		return
	}
	for _, operation := range values {
		s.advanceOperation(ctx, operation)
	}
}

func (s *Server) advanceOperation(ctx context.Context, operation agentv1.Operation) {
	lock := s.operationAuthorizationLock(operation.ID)
	lock.Lock()
	defer lock.Unlock()
	current, err := s.operations.GetByID(operation.ID)
	if err != nil {
		return
	}
	if current.State == agentv1.StatePending && current.ApprovalID == "" {
		current = s.recoverOperationApproval(current)
	}
	if current.State == agentv1.StatePending && current.ApprovalID != "" {
		current = s.syncOperationApproval(current)
	}
	if current.State != agentv1.StateApproved {
		return
	}
	claimed, err := s.operations.Transition(current.ID, agentv1.StateExecuting)
	if err == nil {
		s.executeOperation(ctx, claimed)
	}
}

func (s *Server) recoverOperationApproval(operation agentv1.Operation) agentv1.Operation {
	values, err := s.grants.ListForClient(operation.ClientID)
	if err != nil {
		return operation
	}
	grant, found := operationApproval(values, operation)
	if !found {
		if s.utcNow().Sub(operation.UpdatedAt) < operationAuthorizationGrace {
			return operation
		}
		return s.failOperation(operation.ID, agentv1.StateFailed, "approval_missing", "Approval request is missing")
	}
	digest := grant.Metadata[hfplan.MetadataDigest]
	plan, err := s.database.Plan(context.Background(), digest)
	if err != nil {
		return operation
	}
	updated, err := s.operations.BindPlan(operation.ID, plan, grant.ID, false)
	if err != nil {
		return operation
	}
	return updated
}

func operationApproval(values []grants.Grant, operation agentv1.Operation) (grants.Grant, bool) {
	for _, grant := range values {
		digest := grant.Metadata[hfplan.MetadataDigest]
		if grant.ClientRequestID == operation.ID && grant.Operation == operation.Operation && digest != "" &&
			(operation.PlanDigest == "" || digest == operation.PlanDigest) {
			return grant, true
		}
	}
	return grants.Grant{}, false
}

func (s *Server) syncOperationApproval(operation agentv1.Operation) agentv1.Operation {
	grant, err := s.grants.Get(operation.ApprovalID)
	if err != nil {
		return operation
	}
	switch grant.Status {
	case grants.StatusActive:
		updated, _ := s.operations.Transition(operation.ID, agentv1.StateApproved)
		return updated
	case grants.StatusDenied:
		return s.failOperation(operation.ID, agentv1.StateDenied, "operation_approval_denied", "Approval was denied")
	case grants.StatusExpired:
		return s.failOperation(operation.ID, agentv1.StateExpired, "operation_approval_expired", "Approval request expired")
	case grants.StatusCanceled, grants.StatusRevoked:
		return s.failOperation(operation.ID, agentv1.StateCanceled, "operation_canceled", "Request was canceled")
	default:
		return operation
	}
}

//nolint:cyclop // Execution and reconciliation outcomes are explicit and tracked by the exact HF CRAP baseline.
func (s *Server) executeOperation(ctx context.Context, operation agentv1.Operation) {
	adapter, plan, err := s.loadOperationPlan(operation)
	if err != nil {
		s.failOperation(operation.ID, agentv1.StateFailed, "invalid_stored_operation", "Stored operation is invalid")
		return
	}
	reserved, ok := s.reserveOperationApproval(operation)
	if !ok {
		return
	}
	execution, executionErr := adapter.Execute(ctx, plan)
	if reserved {
		if _, err := s.grants.CommitUse(operation.ApprovalID); err != nil {
			s.failOperation(operation.ID, agentv1.StateFailed, "approval_commit_failed", "Operation ran but approval accounting failed")
			return
		}
	}
	if executionErr == nil && execution.Proven {
		_, _ = s.operations.Succeed(operation.ID, execution.Result)
		s.recordOperationOutcome(operation, plan, audit.DecisionAllowed, "", http.StatusOK)
		return
	}
	if definitiveExecutionFailure(executionErr) {
		s.failOperationExecution(operation, executionErr, nil)
		return
	}
	outcome, reconcileErr := adapter.Reconcile(ctx, plan)
	if reconcileErr == nil && outcome.Proven {
		if len(outcome.Result) == 0 {
			outcome.Result = execution.Result
		}
		_, _ = s.operations.Succeed(operation.ID, outcome.Result)
		s.recordOperationOutcome(operation, plan, audit.DecisionAllowed, "", http.StatusOK)
		return
	}
	s.failOperationExecution(operation, executionErr, reconcileErr)
}

func (s *Server) reconcileInterruptedOperation(ctx context.Context, operation agentv1.Operation) {
	adapter, plan, err := s.loadOperationPlan(operation)
	if err != nil {
		s.failOperation(operation.ID, agentv1.StateFailed, "invalid_stored_operation", "Stored operation is invalid")
		return
	}
	outcome, err := adapter.Reconcile(ctx, plan)
	if err == nil && outcome.Proven {
		if !s.settleRecoveredOperationApproval(operation) {
			return
		}
		_, _ = s.operations.Succeed(operation.ID, outcome.Result)
		s.recordOperationOutcome(operation, plan, audit.DecisionAllowed, "reconciled after restart", http.StatusOK)
		return
	}
	s.failOperation(operation.ID, agentv1.StateFailed, "upstream_result_unknown", "Operation result could not be proven after restart")
}

func definitiveExecutionFailure(err error) bool {
	if err == nil {
		return false
	}
	if operations.IsPossiblePartial(err) {
		return false
	}
	var upstream *hubclient.Error
	return !errors.As(err, &upstream) || upstream.Definitive()
}

func (s *Server) settleRecoveredOperationApproval(operation agentv1.Operation) bool {
	if operation.ApprovalID == "" {
		return true
	}
	grant, err := s.grants.Get(operation.ApprovalID)
	if err != nil || s.planValidator.ValidateExecution(grant) != nil {
		s.failOperation(operation.ID, agentv1.StateFailed, "approval_invalid", "Approval no longer matches the operation")
		return false
	}
	commit, valid := recoveredApprovalCommit(grant)
	if !valid {
		s.failOperation(operation.ID, agentv1.StateFailed, "approval_reservation_missing", "Approval was not reserved before execution")
		return false
	}
	if !commit {
		return true
	}
	if _, err := s.grants.CommitUse(grant.ID); err != nil {
		s.failOperation(operation.ID, agentv1.StateFailed, "approval_commit_failed", "Operation ran but approval accounting failed")
		return false
	}
	return true
}

func recoveredApprovalCommit(grant grants.Grant) (commit, valid bool) {
	if grant.UsedCount > 0 {
		return false, true
	}
	return grant.ReservedCount > 0, grant.ReservedCount > 0
}

//nolint:cyclop // Plan binding checks are explicit and tracked by the exact HF CRAP baseline.
func (s *Server) loadOperationPlan(operation agentv1.Operation) (operations.Adapter, operations.Plan, error) {
	adapter, found := s.operationRegistry.Lookup(operation.Operation)
	if !found || operation.PlanDigest == "" {
		return nil, operations.Plan{}, errors.New("operation adapter is unavailable")
	}
	envelope, err := s.plans.Get(operation.PlanDigest)
	if err != nil || envelope.Operation != operation.Operation || envelope.OperationRevision != adapter.Descriptor().OperationRevision ||
		envelope.ClientID != operation.ClientID || envelope.ClientRequestID != operation.ID || envelope.ExpiresAt.Before(s.utcNow()) {
		return nil, operations.Plan{}, errors.New("operation plan binding is invalid")
	}
	plan := operations.Plan{Operation: envelope.Operation, OperationRevision: envelope.OperationRevision, Target: envelope.Target,
		Arguments: envelope.Arguments, Preconditions: envelope.Preconditions, Presentation: envelope.Presentation,
		PolicyDecision: operations.PolicyDecision{Effect: envelope.Authorization.PolicyEffect, RuleIDs: envelope.Authorization.PolicyRuleIDs}}
	input, err := adapter.Decode(plan.Target, plan.Arguments)
	if err != nil || !equalJSONObject(input.Target, plan.Target) || !equalJSONObject(input.Arguments, plan.Arguments) {
		return nil, operations.Plan{}, errors.New("operation plan payload is invalid")
	}
	if bound, ok := adapter.(operations.ClientBoundAdapter); ok {
		if err := bound.ValidateClient(input, operation.ClientID); err != nil {
			return nil, operations.Plan{}, errors.New("operation client binding is invalid")
		}
	}
	plan.Policy = adapter.Authorize(plan)
	plan.Policy.Client = operation.ClientID
	if plan.Policy.Operation == "" {
		return nil, operations.Plan{}, errors.New("operation policy metadata is invalid")
	}
	return adapter, plan, nil
}

func (s *Server) reserveOperationApproval(operation agentv1.Operation) (bool, bool) {
	if operation.ApprovalID == "" {
		return false, true
	}
	grant, err := s.grants.Get(operation.ApprovalID)
	if err != nil || s.planValidator.ValidateExecution(grant) != nil {
		s.failOperation(operation.ID, agentv1.StateFailed, "approval_invalid", "Approval no longer matches the operation")
		return false, false
	}
	if _, err := s.grants.ReserveUse(grant.ID); err != nil {
		s.failOperation(operation.ID, agentv1.StateFailed, "approval_unavailable", "Approval could not be reserved")
		return false, false
	}
	return true, true
}

func (s *Server) failOperationExecution(operation agentv1.Operation, executionErr, reconcileErr error) {
	code := "upstream_result_unknown"
	message := "Operation result is unknown and was not retried"
	var upstream *hubclient.Error
	if errors.As(executionErr, &upstream) && !upstream.Ambiguous {
		code = string(upstream.Code)
		message = "Hugging Face rejected the operation"
	} else if executionErr != nil && strings.Contains(executionErr.Error(), "operation_precondition_failed") {
		code = "operation_precondition_failed"
		message = "Operation target changed after approval"
	} else if executionErr == nil && reconcileErr != nil {
		code = "operation_reconciliation_failed"
		message = "Operation completed but reconciliation failed"
	}
	s.failOperation(operation.ID, agentv1.StateFailed, code, message)
	s.record(operation.ClientID, operation.Operation, "", audit.DecisionRefused, code, 0)
}

func operationPolicyTarget(request policy.Request) string {
	parts := []string{string(request.Target.Type), request.Target.Owner, request.Target.Name}
	if parts[0] == "" {
		parts = parts[1:]
	}
	return strings.Join(parts, "/")
}

func equalJSONObject(left, right []byte) bool {
	var leftValue, rightValue any
	leftDecoder := json.NewDecoder(bytes.NewReader(left))
	leftDecoder.UseNumber()
	rightDecoder := json.NewDecoder(bytes.NewReader(right))
	rightDecoder.UseNumber()
	return leftDecoder.Decode(&leftValue) == nil && rightDecoder.Decode(&rightValue) == nil && reflect.DeepEqual(leftValue, rightValue)
}

func operationAPIError(status int, code, message string) error {
	return &agentapi.Error{Status: status, Code: code, Message: message}
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

func planRecord(plan grants.ImmutablePlan) state.PlanRecord {
	return state.PlanRecord{Digest: plan.Digest, SchemaName: plan.SchemaName, Canonical: plan.Canonical, CreatedAt: plan.CreatedAt}
}

func operationDebugID(operation agentv1.Operation) string {
	return fmt.Sprintf("%s:%s", operation.Operation, operation.ID)
}
