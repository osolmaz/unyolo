package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/osolmaz/brokerkit/agentapi"
	"github.com/osolmaz/brokerkit/agentops"
	"github.com/osolmaz/brokerkit/agentv1"
	"github.com/osolmaz/brokerkit/brokers/github/internal/policy"
	"github.com/osolmaz/brokerkit/grants"
	"github.com/osolmaz/brokerkit/internal/strictjson"
	corepolicy "github.com/osolmaz/brokerkit/policy"
	"github.com/osolmaz/brokerkit/usebudget"
)

const maxAgentGitHubBody = 64 * 1024

type pullRequestTarget struct {
	Kind  string `json:"kind"`
	Owner string `json:"owner"`
	Name  string `json:"name"`
}

type pullRequestArguments struct {
	Title               string `json:"title"`
	Body                string `json:"body,omitempty"`
	Head                string `json:"head"`
	Base                string `json:"base"`
	Draft               bool   `json:"draft,omitempty"`
	MaintainerCanModify *bool  `json:"maintainer_can_modify,omitempty"`
}

type pullRequestResult struct {
	Number int    `json:"number"`
	URL    string `json:"url"`
}

func (s *Server) submitAgentOperation(_ context.Context, client string, request agentv1.SubmitRequest) (agentv1.Operation, bool, error) {
	if request.Operation != string(policy.OperationPullRequestCreate) {
		return agentv1.Operation{}, false, &agentapi.Error{Status: http.StatusBadRequest, Code: "unsupported_operation", Message: "Unsupported agent operation"}
	}
	target, arguments, attrs, err := decodePullRequestOperation(request)
	if err != nil {
		return agentv1.Operation{}, false, &agentapi.Error{Status: http.StatusBadRequest, Code: "invalid_request", Message: err.Error()}
	}
	operation, created, err := s.operations.Submit(agentops.Submit{
		Broker: "gh-broker", ClientID: client, IdempotencyKey: request.IdempotencyKey, Operation: request.Operation,
		Target: request.Target, Arguments: request.Arguments, Reason: request.Reason,
		Presentation: agentv1.Presentation{Title: "Create GitHub pull request", Summary: pullRequestSummary(target, arguments)},
	})
	if err != nil {
		return agentv1.Operation{}, false, err
	}
	if created || operation.State == agentv1.StatePending && operation.ApprovalID == "" {
		operation = s.authorizePullRequest(s.agentLifecycleContext(), operation, target, attrs)
	}
	return operation, created, nil
}

func (s *Server) agentLifecycleContext() context.Context {
	if s.lifecycleContext != nil {
		return s.lifecycleContext
	}
	return context.Background()
}

func (s *Server) authorizePullRequest(ctx context.Context, operation agentv1.Operation, target pullRequestTarget, attrs map[string]string) agentv1.Operation {
	lock := s.operationAuthorizationLock(operation.ID)
	lock.Lock()
	defer lock.Unlock()
	current, err := s.operations.GetByID(operation.ID)
	if err != nil {
		return s.failAgentOperation(operation.ID, agentv1.StateFailed, "operation_store_unavailable", "Could not read operation")
	}
	if current.State != agentv1.StatePending || current.ApprovalID != "" {
		return current
	}
	request := policy.Request{Client: current.ClientID, Operation: policy.OperationPullRequestCreate, Target: target.policyTarget(), Attrs: attrs}
	decision, err := s.evaluateBrokerRequest(request)
	if err != nil {
		return s.failAgentOperation(current.ID, agentv1.StateFailed, "operation_store_unavailable", "Could not inspect approvals")
	}
	return s.applyPullRequestDecision(ctx, current, target, attrs, request, decision)
}

func (s *Server) operationAuthorizationLock(id string) *sync.Mutex {
	var hash uint64 = 14695981039346656037
	for i := 0; i < len(id); i++ {
		hash ^= uint64(id[i])
		hash *= 1099511628211
	}
	return &s.operationAuthLocks[hash%uint64(len(s.operationAuthLocks))]
}

func (s *Server) applyPullRequestDecision(ctx context.Context, operation agentv1.Operation, target pullRequestTarget, attrs map[string]string, request policy.Request, decision policy.Decision) agentv1.Operation {
	if decision.Allowed {
		return s.applyAllowedPullRequest(operation, decision.GrantID)
	}
	if decision.Effect != policy.EffectRequest {
		return s.failAgentOperation(operation.ID, agentv1.StateDenied, "policy_denied", "Policy denied this operation")
	}
	requestDecision := s.policy.EvaluateGrantRequest(request)
	if requestDecision.Effect != policy.EffectRequest || requestDecision.GrantPolicy == nil {
		return s.failAgentOperation(operation.ID, agentv1.StateFailed, "approval_policy_invalid", "Pull request approval policy is invalid")
	}
	return s.requestPullRequestApproval(ctx, operation, target, attrs, requestDecision.GrantPolicy)
}

func (s *Server) applyAllowedPullRequest(operation agentv1.Operation, grantID string) agentv1.Operation {
	if grantID != "" {
		updated, err := s.operations.SetApproval(operation.ID, grantID)
		if err == nil {
			return s.syncAgentApproval(updated)
		}
		return s.failAgentOperation(operation.ID, agentv1.StateFailed, "operation_store_unavailable", "Could not bind approval")
	}
	updated, err := s.operations.Transition(operation.ID, agentv1.StateApproved)
	if err != nil {
		return s.failAgentOperation(operation.ID, agentv1.StateFailed, "operation_store_unavailable", "Could not approve operation")
	}
	return updated
}

func (s *Server) requestPullRequestApproval(ctx context.Context, operation agentv1.Operation, target pullRequestTarget, attrs map[string]string, bounds *corepolicy.GrantPolicy) agentv1.Operation {
	if s.notifier == nil && !s.operatorConfigured {
		return s.failAgentOperation(operation.ID, agentv1.StateFailed, "approval_channel_not_configured", "Approval channel is not configured")
	}
	duration, pending, maxUses, err := pullRequestGrantBounds(bounds)
	if err != nil {
		return s.failAgentOperation(operation.ID, agentv1.StateFailed, "approval_policy_invalid", "Pull request approval policy is invalid")
	}
	request := grants.Request{
		Client: operation.ClientID, ClientRequestID: operation.ID, Operation: operation.Operation,
		Target: policy.CoreTarget(target.policyTarget()), Attrs: corepolicy.SingletonValues(attrs), Reason: operation.Reason,
		Duration: duration, PendingTimeout: pending, MaxUses: maxUses,
	}
	result, _, err := s.requestGrant(request)
	if err != nil {
		return s.failAgentOperation(operation.ID, agentv1.StateFailed, "approval_request_failed", "Could not create approval request")
	}
	if err := s.notifyAgentApproval(ctx, result.Grant); err != nil {
		return s.failAgentOperation(operation.ID, agentv1.StateFailed, "approval_notification_failed", "Could not notify the operator")
	}
	updated, err := s.operations.SetApproval(operation.ID, result.Grant.ID)
	if err != nil {
		return s.failAgentOperation(operation.ID, agentv1.StateFailed, "operation_store_unavailable", "Could not bind approval")
	}
	return updated
}

func pullRequestGrantBounds(bounds *corepolicy.GrantPolicy) (time.Duration, time.Duration, usebudget.Limit, error) {
	if corepolicy.GrantMode(bounds.Mode) != corepolicy.GrantModeExecution || bounds.DefaultMaxUses != 1 {
		return 0, 0, 0, errors.New("pull request approvals require one execution")
	}
	return grantBounds(bounds, bounds.DefaultMinutes, 1)
}

func (s *Server) notifyAgentApproval(ctx context.Context, grant grants.Grant) error {
	if s.notifier == nil {
		return nil
	}
	claim, claimed, err := s.grants.ClaimNotification(grant.ID, grantNotificationClaimLease)
	if err != nil {
		return err
	}
	if !claimed {
		return s.existingAgentNotification(grant.ID)
	}
	return s.sendAgentNotification(ctx, claim)
}

func (s *Server) existingAgentNotification(grantID string) error {
	current, err := s.grants.Get(grantID)
	if err == nil && current.Notification != nil {
		return nil
	}
	return errors.New("approval notification is already claimed")
}

func (s *Server) sendAgentNotification(ctx context.Context, claim grants.NotificationClaim) error {
	ref, err := s.notifier.SendApproval(ctx, grantApprovalMessage(claim.Grant, claim.DecisionToken))
	if err != nil || ref.MessageID <= 0 {
		if err == nil {
			err = errors.New("approval notifier returned an invalid message")
		}
		return s.settleAgentNotificationFailure(claim, err)
	}
	stored, recorded, err := s.grants.SetNotificationIfClaimed(claim.Grant.ID, claim.Grant.NotificationClaimedAt, ref)
	if err != nil || !recorded && stored.Notification == nil {
		return errors.Join(err, errors.New("approval notification claim changed"))
	}
	return nil
}

func (s *Server) settleAgentNotificationFailure(claim grants.NotificationClaim, cause error) error {
	if s.operatorConfigured {
		_, _, err := s.grants.RetainNotificationClaim(claim.Grant.ID, claim.Grant.NotificationClaimedAt)
		return errors.Join(cause, err)
	}
	_, _, err := s.grants.CancelIfNotificationClaimed(claim.Grant.ID, claim.Grant.NotificationClaimedAt)
	return errors.Join(cause, err)
}

func decodePullRequestOperation(request agentv1.SubmitRequest) (pullRequestTarget, pullRequestArguments, map[string]string, error) {
	var target pullRequestTarget
	if err := decodeAgentObject(request.Target, &target); err != nil || !validPullRequestTarget(target) {
		return pullRequestTarget{}, pullRequestArguments{}, nil, errors.New("pull request target must contain an exact owner and repository")
	}
	var arguments pullRequestArguments
	if err := decodeAgentObject(request.Arguments, &arguments); err != nil {
		return pullRequestTarget{}, pullRequestArguments{}, nil, errors.New("invalid pull request arguments")
	}
	body, _ := json.Marshal(arguments)
	attrs, err := pullRequestAttrs(body)
	if err != nil {
		return pullRequestTarget{}, pullRequestArguments{}, nil, err
	}
	return target, arguments, attrs, nil
}

func validPullRequestTarget(target pullRequestTarget) bool {
	return target.Kind == "repo" && target.Owner != "" && target.Name != "" &&
		validateRouteSegment(target.Owner) == nil && validateRouteSegment(target.Name) == nil
}

func decodeAgentObject(data []byte, destination any) error {
	if len(data) == 0 || len(data) > maxAgentGitHubBody {
		return errors.New("invalid JSON object")
	}
	return strictDecode(data, destination)
}

func strictDecode(data []byte, destination any) error {
	return strictjson.Decode(data, destination, true)
}

func (target pullRequestTarget) policyTarget() policy.Target {
	return policy.Target{Kind: "repo", Owner: target.Owner, Name: target.Name}
}

func pullRequestSummary(target pullRequestTarget, arguments pullRequestArguments) string {
	return fmt.Sprintf("Open %s/%s pull request %q from %s into %s", target.Owner, target.Name, arguments.Title, arguments.Head, arguments.Base)
}

func (s *Server) startOperationWorker(ctx context.Context) {
	s.operationWorkerOnce.Do(func() {
		workerContext, cancel := context.WithCancel(ctx)
		s.lifecycleContext = workerContext
		s.lifecycleCancel = cancel
		s.backgroundWorkers.Add(1)
		go func() {
			defer s.backgroundWorkers.Done()
			ticker := time.NewTicker(500 * time.Millisecond)
			defer ticker.Stop()
			s.recoverAgentOperations(workerContext)
			for {
				select {
				case <-workerContext.Done():
					return
				case <-ticker.C:
					s.advanceAgentOperations(workerContext)
				}
			}
		}()
	})
}

func (s *Server) recoverAgentOperations(ctx context.Context) {
	operations, err := s.operations.ListUnfinished()
	if err != nil {
		return
	}
	for _, operation := range operations {
		if operation.State == agentv1.StateExecuting {
			_, _ = s.operations.Fail(operation.ID, agentv1.StateFailed, "execution_interrupted", "Broker restarted during execution; result is unknown")
			continue
		}
		s.advanceAgentOperation(ctx, operation)
	}
}

func (s *Server) advanceAgentOperations(ctx context.Context) {
	operations, err := s.operations.ListUnfinished()
	if err != nil {
		return
	}
	for _, operation := range operations {
		s.advanceAgentOperation(ctx, operation)
	}
}

func (s *Server) advanceAgentOperation(ctx context.Context, operation agentv1.Operation) {
	operation = s.prepareAgentOperation(ctx, operation)
	if operation.State != agentv1.StateApproved {
		return
	}
	claimed, err := s.operations.Transition(operation.ID, agentv1.StateExecuting)
	if err == nil {
		s.executePullRequest(ctx, claimed)
	}
}

func (s *Server) prepareAgentOperation(ctx context.Context, operation agentv1.Operation) agentv1.Operation {
	if operation.State != agentv1.StatePending {
		return operation
	}
	if operation.ApprovalID != "" {
		return s.syncAgentApproval(operation)
	}
	return s.authorizeStoredPullRequest(ctx, operation)
}

func (s *Server) authorizeStoredPullRequest(ctx context.Context, operation agentv1.Operation) agentv1.Operation {
	target, _, attrs, err := decodePullRequestOperation(agentv1.SubmitRequest{Target: operation.Target, Arguments: operation.Arguments})
	if err != nil {
		return s.failAgentOperation(operation.ID, agentv1.StateFailed, "invalid_stored_operation", "Stored operation is invalid")
	}
	return s.authorizePullRequest(ctx, operation, target, attrs)
}

func (s *Server) syncAgentApproval(operation agentv1.Operation) agentv1.Operation {
	grant, err := s.grants.Get(operation.ApprovalID)
	if err != nil {
		return operation
	}
	switch grant.Status {
	case grants.StatusActive:
		updated, _ := s.operations.Transition(operation.ID, agentv1.StateApproved)
		return updated
	case grants.StatusDenied:
		return s.failAgentOperation(operation.ID, agentv1.StateDenied, "approval_denied", "Approval was denied")
	case grants.StatusExpired:
		return s.failAgentOperation(operation.ID, agentv1.StateExpired, "approval_expired", "Approval request expired")
	case grants.StatusCanceled, grants.StatusRevoked:
		return s.failAgentOperation(operation.ID, agentv1.StateCanceled, "approval_canceled", "Approval was canceled")
	default:
		return operation
	}
}

func (s *Server) executePullRequest(ctx context.Context, operation agentv1.Operation) {
	target, arguments, _, err := decodePullRequestOperation(agentv1.SubmitRequest{Target: operation.Target, Arguments: operation.Arguments})
	if err != nil {
		s.failAgentOperation(operation.ID, agentv1.StateFailed, "invalid_stored_operation", "Stored operation is invalid")
		return
	}
	reserved, ok := s.reserveAgentApproval(operation)
	if !ok {
		return
	}
	result, definitive, err := s.createUpstreamPullRequest(ctx, target, arguments)
	if err != nil {
		s.failPullRequestExecution(operation, reserved, definitive)
		return
	}
	if reserved {
		if _, err := s.grants.CommitUse(operation.ApprovalID); err != nil {
			s.failAgentOperation(operation.ID, agentv1.StateFailed, "approval_commit_failed", "Pull request was created but approval accounting failed")
			return
		}
	}
	encoded, _ := json.Marshal(result)
	_, _ = s.operations.Succeed(operation.ID, encoded)
}

func (s *Server) reserveAgentApproval(operation agentv1.Operation) (bool, bool) {
	if operation.ApprovalID == "" {
		return false, true
	}
	grant, err := s.grants.Get(operation.ApprovalID)
	if err != nil || s.planValidator.ValidateExecution(grant) != nil {
		s.failAgentOperation(operation.ID, agentv1.StateFailed, "approval_invalid", "Approval no longer matches the operation")
		return false, false
	}
	if _, err := s.grants.ReserveUse(grant.ID); err != nil {
		s.failAgentOperation(operation.ID, agentv1.StateFailed, "approval_unavailable", "Approval could not be reserved")
		return false, false
	}
	return true, true
}

func (s *Server) failPullRequestExecution(operation agentv1.Operation, reserved, definitive bool) {
	if reserved {
		if definitive {
			_, _ = s.grants.CommitUse(operation.ApprovalID)
		} else {
			_, _ = s.grants.RetainUse(operation.ApprovalID)
		}
	}
	code, message := "upstream_rejected", "GitHub rejected the pull request"
	if !definitive {
		code, message = "upstream_result_unknown", "GitHub pull request result is unknown; it was not retried"
	}
	s.failAgentOperation(operation.ID, agentv1.StateFailed, code, message)
}

func (s *Server) createUpstreamPullRequest(ctx context.Context, target pullRequestTarget, arguments pullRequestArguments) (pullRequestResult, bool, error) {
	token, err := s.githubCredentialForRepoContext(ctx, target.Owner, target.Name)
	if err != nil {
		return pullRequestResult{}, false, err
	}
	body, _ := json.Marshal(arguments)
	requestURL := s.githubAPIBaseURL.JoinPath("repos", target.Owner, target.Name, "pulls")
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, requestURL.String(), bytes.NewReader(body))
	if err != nil {
		return pullRequestResult{}, false, err
	}
	configureInstallationTokenRequest(request, token)
	request.Header.Set("Content-Type", "application/json")
	response, err := s.githubClient.Do(request)
	if err != nil {
		return pullRequestResult{}, false, err
	}
	defer func() { _ = response.Body.Close() }()
	return decodePullRequestResponse(response)
}

func decodePullRequestResponse(response *http.Response) (pullRequestResult, bool, error) {
	data, err := io.ReadAll(io.LimitReader(response.Body, maxAgentGitHubBody+1))
	if err != nil || len(data) > maxAgentGitHubBody {
		return pullRequestResult{}, false, errors.New("GitHub response is invalid")
	}
	if definitive, err := pullRequestResponseStatus(response.StatusCode); err != nil {
		return pullRequestResult{}, definitive, err
	}
	var upstream struct {
		Number  int    `json:"number"`
		HTMLURL string `json:"html_url"`
	}
	if json.Unmarshal(data, &upstream) != nil || upstream.Number <= 0 || upstream.HTMLURL == "" {
		return pullRequestResult{}, false, errors.New("GitHub response is invalid")
	}
	return pullRequestResult{Number: upstream.Number, URL: upstream.HTMLURL}, true, nil
}

func pullRequestResponseStatus(status int) (bool, error) {
	if status >= 200 && status < 300 {
		return true, nil
	}
	return status >= 400 && status < 500, fmt.Errorf("GitHub status %d", status)
}

func (s *Server) failAgentOperation(id string, state agentv1.State, code, message string) agentv1.Operation {
	operation, err := s.operations.Fail(id, state, code, message)
	if err != nil {
		operation, _ = s.operations.GetByID(id)
	}
	return operation
}
