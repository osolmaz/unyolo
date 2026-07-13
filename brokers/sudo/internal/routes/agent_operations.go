package routes

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/osolmaz/brokerkit/agentapi"
	"github.com/osolmaz/brokerkit/agentops"
	"github.com/osolmaz/brokerkit/agentv1"
	"github.com/osolmaz/brokerkit/brokers/sudo/internal/catalog"
	"github.com/osolmaz/brokerkit/brokers/sudo/internal/executorclient"
	"github.com/osolmaz/brokerkit/brokers/sudo/internal/executorprotocol"
	"github.com/osolmaz/brokerkit/brokers/sudo/internal/plan"
	"github.com/osolmaz/brokerkit/brokers/sudo/internal/sudopolicy"
	"github.com/osolmaz/brokerkit/grants"
	"github.com/osolmaz/brokerkit/internal/strictjson"
	corepolicy "github.com/osolmaz/brokerkit/policy"
)

type commandTarget struct {
	Kind string `json:"kind"`
	Name string `json:"name"`
}

type commandArguments struct {
	CommandID string                     `json:"command_id"`
	Arguments map[string]json.RawMessage `json:"arguments"`
}

func (s *Server) cancelAgentOperation(_ context.Context, client, id string) (agentv1.Operation, error) {
	s.requestMu.Lock()
	defer s.requestMu.Unlock()
	operation, err := s.operations.Get(client, id)
	if err != nil || operation.State.Terminal() {
		return operation, err
	}
	if operation.State == agentv1.StateExecuting {
		return agentv1.Operation{}, agentops.ErrNotCancelable
	}
	if err := s.cancelAgentApproval(operation, client); err != nil {
		return agentv1.Operation{}, err
	}
	return s.operations.Cancel(client, id)
}

func (s *Server) cancelAgentApproval(operation agentv1.Operation, client string) error {
	if operation.ApprovalID == "" {
		return nil
	}
	grant, err := s.grants.Get(operation.ApprovalID)
	if err != nil {
		return err
	}
	switch grant.Status {
	case grants.StatusPending:
		_, err = s.grants.CancelForClient(grant.ID, client)
	case grants.StatusActive:
		_, err = s.grants.RevokeForClient(grant.ID, client)
	}
	return err
}

func (s *Server) submitAgentOperation(_ context.Context, client string, request agentv1.SubmitRequest) (agentv1.Operation, bool, error) {
	if request.Operation != sudopolicy.OperationExecCommand {
		return agentv1.Operation{}, false, &agentapi.Error{Status: http.StatusBadRequest, Code: "unsupported_operation", Message: "Unsupported agent operation"}
	}
	target, arguments, resolved, policyRequest, err := s.decodeCommandOperation(client, request)
	if err != nil {
		return agentv1.Operation{}, false, &agentapi.Error{Status: http.StatusBadRequest, Code: "invalid_request", Message: err.Error()}
	}
	operation, created, err := s.operations.Submit(agentops.Submit{Broker: "sudo-broker", ClientID: client,
		IdempotencyKey: request.IdempotencyKey, Operation: request.Operation, Target: request.Target, Arguments: request.Arguments,
		Reason: request.Reason, Presentation: agentv1.Presentation{Title: "Run approved Unix command",
			Summary: fmt.Sprintf("Run %s once as %s", arguments.CommandID, target.Name)}})
	if err != nil {
		return agentv1.Operation{}, false, err
	}
	if created || operation.State == agentv1.StatePending && operation.ApprovalID == "" {
		operation = s.authorizeCommand(s.agentLifecycleContext(), operation, resolved, policyRequest)
	}
	return operation, created, nil
}

func (s *Server) decodeCommandOperation(client string, request agentv1.SubmitRequest) (commandTarget, commandArguments, catalog.Resolved, corepolicy.Request, error) {
	var target commandTarget
	if strictjson.Decode(request.Target, &target, true) != nil || target.Kind != "user" || strings.TrimSpace(target.Name) == "" {
		return commandTarget{}, commandArguments{}, catalog.Resolved{}, corepolicy.Request{}, errors.New("command target must contain an exact Unix user")
	}
	var arguments commandArguments
	if len(request.Arguments) == 0 || len(request.Arguments) > int(maxBodyBytes) || strictjson.Decode(request.Arguments, &arguments, true) != nil {
		return commandTarget{}, commandArguments{}, catalog.Resolved{}, corepolicy.Request{}, errors.New("invalid command arguments")
	}
	resolved, policyRequest, err := s.classify(client, commandInput{CommandID: arguments.CommandID, TargetUser: target.Name, Arguments: arguments.Arguments})
	return target, arguments, resolved, policyRequest, err
}

func (s *Server) authorizeCommand(ctx context.Context, operation agentv1.Operation, resolved catalog.Resolved, policyRequest corepolicy.Request) agentv1.Operation {
	s.requestMu.Lock()
	defer s.requestMu.Unlock()
	current, err := s.operations.GetByID(operation.ID)
	if err != nil {
		return s.failOperation(operation.ID, agentv1.StateFailed, "operation_store_unavailable", "Could not read operation")
	}
	if current.State != agentv1.StatePending || current.ApprovalID != "" {
		return current
	}
	decision := s.policy.Decide(policyRequest, corepolicy.DecisionOptions{ForGrantRequest: true, Now: s.now().UTC()})
	if decision.Effect != corepolicy.EffectRequest || decision.GrantPolicy == nil {
		s.record(policyRequest, "denied", decision.Reason, "", decision.MatchedDenyRuleIDs)
		return s.failOperation(current.ID, agentv1.StateDenied, "policy_denied", "Policy denied this operation")
	}
	return s.requestCommandApproval(ctx, current, resolved, policyRequest, decision)
}

func (s *Server) requestCommandApproval(ctx context.Context, operation agentv1.Operation, resolved catalog.Resolved, policyRequest corepolicy.Request, decision corepolicy.Decision) agentv1.Operation {
	if s.notifier == nil && !s.operatorConfigured {
		return s.failOperation(operation.ID, agentv1.StateFailed, "approval_channel_not_configured", "Approval channel is not configured")
	}
	duration, pending, err := grantBounds(decision.GrantPolicy, 0)
	if err != nil {
		return s.failOperation(operation.ID, agentv1.StateFailed, "approval_policy_invalid", "Command approval policy is invalid")
	}
	request := grants.Request{Client: operation.ClientID, ClientRequestID: operation.ID, Operation: operation.Operation,
		Target: policyRequest.Target, Attrs: policyRequest.Attrs, Reason: operation.Reason, Duration: duration,
		PendingTimeout: pending, MaxUses: 1, MaxUsesSpecified: true}
	identity, err := s.identities.Lookup(resolved.TargetUser)
	if err != nil {
		return s.failOperation(operation.ID, agentv1.StateFailed, "target_identity_invalid", "Target user cannot be resolved")
	}
	value, err := plan.Build(request, resolved, identity, s.now().UTC())
	if err != nil {
		return s.failOperation(operation.ID, agentv1.StateFailed, "invalid_stored_operation", "Command plan is invalid")
	}
	immutable, err := s.plans.PrepareBind(&request, value)
	if err != nil {
		return s.failOperation(operation.ID, agentv1.StateFailed, "approval_request_failed", "Could not prepare approval request")
	}
	result, _, err := s.grants.RequestWithPlan(request, immutable)
	if err != nil {
		return s.failOperation(operation.ID, agentv1.StateFailed, "approval_request_failed", "Could not create approval request")
	}
	stored, err := s.notifyRequest(ctx, result)
	if err != nil {
		return s.failOperation(operation.ID, agentv1.StateFailed, "approval_notification_failed", "Could not notify the operator")
	}
	updated, err := s.operations.SetApproval(operation.ID, stored.ID)
	if err != nil {
		return s.failOperation(operation.ID, agentv1.StateFailed, "operation_store_unavailable", "Could not bind approval")
	}
	s.record(policyRequest, "requires_approval", "requestable", stored.ID, decision.MatchedRequestRuleIDs)
	return updated
}

func (s *Server) agentLifecycleContext() context.Context {
	if s.lifecycleContext != nil {
		return s.lifecycleContext
	}
	return context.Background()
}

func (s *Server) startOperationWorker(ctx context.Context) {
	s.workerOnce.Do(func() {
		workerContext, cancel := context.WithCancel(ctx)
		s.lifecycleContext, s.lifecycleCancel = workerContext, cancel
		s.backgroundWorkers.Add(1)
		go func() {
			defer s.backgroundWorkers.Done()
			ticker := time.NewTicker(500 * time.Millisecond)
			defer ticker.Stop()
			s.recoverOperations(workerContext)
			for {
				select {
				case <-workerContext.Done():
					return
				case <-ticker.C:
					s.advanceOperations(workerContext)
				}
			}
		}()
	})
}

func (s *Server) recoverOperations(ctx context.Context) {
	operations, err := s.operations.ListUnfinished()
	if err != nil {
		return
	}
	for _, operation := range operations {
		if operation.State == agentv1.StateExecuting {
			s.failOperation(operation.ID, agentv1.StateFailed, "execution_interrupted", "Broker restarted during execution; result is unknown")
			continue
		}
		s.advanceOperation(ctx, operation)
	}
}

func (s *Server) advanceOperations(ctx context.Context) {
	operations, err := s.operations.ListUnfinished()
	if err != nil {
		return
	}
	for _, operation := range operations {
		s.advanceOperation(ctx, operation)
	}
}

func (s *Server) advanceOperation(ctx context.Context, operation agentv1.Operation) {
	if operation.State == agentv1.StatePending && operation.ApprovalID == "" {
		_, _, resolved, request, err := s.decodeCommandOperation(operation.ClientID, agentv1.SubmitRequest{Target: operation.Target, Arguments: operation.Arguments})
		if err != nil {
			s.failOperation(operation.ID, agentv1.StateFailed, "invalid_stored_operation", "Stored operation is invalid")
			return
		}
		operation = s.authorizeCommand(ctx, operation, resolved, request)
	}
	if operation.State == agentv1.StatePending && operation.ApprovalID != "" {
		operation = s.syncOperationApproval(operation)
	}
	if operation.State != agentv1.StateApproved {
		return
	}
	claimed, err := s.operations.Transition(operation.ID, agentv1.StateExecuting)
	if err == nil {
		s.executeOperation(ctx, claimed)
	}
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
		return s.failOperation(operation.ID, agentv1.StateDenied, "approval_denied", "Approval was denied")
	case grants.StatusExpired:
		return s.failOperation(operation.ID, agentv1.StateExpired, "approval_expired", "Approval request expired")
	case grants.StatusCanceled, grants.StatusRevoked:
		return s.failOperation(operation.ID, agentv1.StateCanceled, "approval_canceled", "Approval was canceled")
	default:
		return operation
	}
}

func (s *Server) executeOperation(ctx context.Context, operation agentv1.Operation) {
	_, _, _, policyRequest, err := s.decodeCommandOperation(operation.ClientID, agentv1.SubmitRequest{Target: operation.Target, Arguments: operation.Arguments})
	if err != nil {
		s.failOperation(operation.ID, agentv1.StateFailed, "invalid_stored_operation", "Stored operation is invalid")
		return
	}
	grant, err := s.grants.ReserveUse(operation.ApprovalID)
	if err != nil {
		s.failOperation(operation.ID, agentv1.StateFailed, "approval_unavailable", "Approval could not be reserved")
		return
	}
	value, err := s.validator.ValidateExecution(ctx, grant)
	if err != nil {
		_, _ = s.grants.ReleaseUse(grant.ID)
		s.failOperation(operation.ID, agentv1.StateFailed, "approval_invalid", "Approved command plan is invalid")
		return
	}
	reservationID := fmt.Sprintf("%s:r%d", grant.ID, grant.Revision)
	response, callErr := s.helper.Execute(ctx, operation.ID, value, grant.ID, reservationID, grant.ExpiresAt)
	s.settleOperation(operation, policyRequest, grant, response, callErr)
}

func (s *Server) settleOperation(operation agentv1.Operation, policyRequest corepolicy.Request, grant grants.Grant, response executorprotocol.Response, callErr error) {
	if callErr != nil {
		if executorclient.WasDispatched(callErr) {
			_, _ = s.grants.RetainUse(grant.ID)
			s.record(policyRequest, "ambiguous", "helper response unavailable", grant.ID, nil)
			s.failOperation(operation.ID, agentv1.StateFailed, "execution_result_unknown", "Command result is unknown; it was not retried")
		} else {
			_, _ = s.grants.ReleaseUse(grant.ID)
			s.record(policyRequest, "rejected", "helper unavailable before dispatch", grant.ID, nil)
			s.failOperation(operation.ID, agentv1.StateFailed, "helper_unavailable", "Privileged helper is unavailable")
		}
		return
	}
	if response.Status != executorprotocol.StatusCompleted || response.Outcome == nil || !response.Outcome.Started {
		s.settleNonCompletedOperation(operation, policyRequest, grant, response)
		return
	}
	if _, err := s.grants.CommitUse(grant.ID); err != nil {
		_, _ = s.grants.RetainUse(grant.ID)
		s.failOperation(operation.ID, agentv1.StateFailed, "approval_commit_failed", "Command ran but approval accounting failed")
		return
	}
	encoded, _ := json.Marshal(executionView(response))
	_, _ = s.operations.Succeed(operation.ID, encoded)
	s.record(policyRequest, "executed", "", grant.ID, nil)
}

func (s *Server) settleNonCompletedOperation(operation agentv1.Operation, policyRequest corepolicy.Request, grant grants.Grant, response executorprotocol.Response) {
	if response.Status == executorprotocol.StatusRejected || response.Status == executorprotocol.StatusCompleted && response.Outcome != nil {
		_, _ = s.grants.ReleaseUse(grant.ID)
		s.record(policyRequest, "rejected", response.ErrorCode, grant.ID, nil)
		s.failOperation(operation.ID, agentv1.StateFailed, "execution_rejected", "Command did not start")
		return
	}
	_, _ = s.grants.RetainUse(grant.ID)
	s.record(policyRequest, "ambiguous", response.ErrorCode, grant.ID, nil)
	s.failOperation(operation.ID, agentv1.StateFailed, "execution_result_unknown", "Command result is unknown; it was not retried")
}

func (s *Server) failOperation(id string, state agentv1.State, code, message string) agentv1.Operation {
	operation, err := s.operations.Fail(id, state, code, message)
	if err != nil {
		operation, _ = s.operations.GetByID(id)
	}
	return operation
}
