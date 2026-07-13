package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/osolmaz/brokerkit/agentapi"
	"github.com/osolmaz/brokerkit/agentops"
	"github.com/osolmaz/brokerkit/agentv1"
	"github.com/osolmaz/brokerkit/audit"
	bkauthorization "github.com/osolmaz/brokerkit/authorization"
	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/hfgrant"
	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/policy"
	"github.com/osolmaz/brokerkit/grants"
	"github.com/osolmaz/brokerkit/internal/strictjson"
	corepolicy "github.com/osolmaz/brokerkit/policy"
)

const maxUpstreamBody = 64 * 1024

var repoSegmentPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,95}$`)

var errApprovalNotificationClaimed = errors.New("approval notification is already claimed")

type repoCreateTarget struct {
	Kind  string          `json:"kind"`
	Type  policy.RepoType `json:"type"`
	Owner string          `json:"owner"`
	Name  string          `json:"name"`
}

type repoCreateArguments struct {
	Private *bool  `json:"private"`
	SDK     string `json:"sdk,omitempty"`
}

type repoCreateResult struct {
	RepoID string `json:"repo_id"`
	URL    string `json:"url"`
}

func (s *Server) submitAgentOperation(_ context.Context, client string, request agentv1.SubmitRequest) (agentv1.Operation, bool, error) {
	if request.Operation != string(policy.OpRepoCreate) {
		return agentv1.Operation{}, false, &agentapi.Error{
			Status: http.StatusBadRequest, Code: "unsupported_operation", Message: "Unsupported agent operation",
		}
	}
	target, arguments, err := decodeRepoCreate(request)
	if err != nil {
		return agentv1.Operation{}, false, &agentapi.Error{Status: http.StatusBadRequest, Code: "invalid_request", Message: err.Error()}
	}
	presentation := agentv1.Presentation{Title: "Create Hugging Face repository", Summary: repoCreateSummary(target, arguments)}
	operation, created, err := s.operations.Submit(agentops.Submit{
		Broker: "hf-broker", ClientID: client, IdempotencyKey: request.IdempotencyKey, Operation: request.Operation,
		Target: request.Target, Arguments: request.Arguments, Reason: request.Reason, Presentation: presentation,
	})
	if err != nil {
		return agentv1.Operation{}, false, err
	}
	if created || operation.State == agentv1.StatePending && operation.ApprovalID == "" {
		operation = s.authorizeRepoCreate(s.agentLifecycleContext(), operation, target, arguments)
	}
	return operation, created, nil
}

func (s *Server) agentLifecycleContext() context.Context {
	if s.lifecycleContext != nil {
		return s.lifecycleContext
	}
	return context.Background()
}

func (s *Server) authorizeRepoCreate(ctx context.Context, operation agentv1.Operation, target repoCreateTarget, arguments repoCreateArguments) agentv1.Operation {
	lock := s.operationAuthorizationLock(operation.ID)
	lock.Lock()
	defer lock.Unlock()
	current, err := s.operations.GetByID(operation.ID)
	if err != nil {
		return s.failOperation(operation.ID, agentv1.StateFailed, "operation_store_unavailable", "Could not read operation")
	}
	if current.State != agentv1.StatePending || current.ApprovalID != "" {
		return current
	}
	operation = current
	attrs := repoCreateAttrs(arguments)
	providerRequest := policy.Request{Client: operation.ClientID, Operation: policy.OpRepoCreate, Target: target.policyTarget(), Attrs: attrs}
	authorizationRequest := policy.AuthorizationRequest(providerRequest)
	result, err := s.authorization.Authorize(authorizationRequest, func(decision corepolicy.Decision) (bkauthorization.GrantIntent, error) {
		return s.prepareRepoCreateIntent(operation, target, attrs, authorizationRequest, decision.GrantPolicy)
	})
	return s.applyRepoCreateAuthorization(ctx, operation, target, result, err)
}

func (s *Server) applyRepoCreateAuthorization(ctx context.Context, operation agentv1.Operation, target repoCreateTarget, result bkauthorization.Result, err error) agentv1.Operation {
	if err == nil {
		return s.applySuccessfulRepoCreateAuthorization(ctx, operation, result)
	}
	return s.applyFailedRepoCreateAuthorization(operation, target, result, err)
}

func (s *Server) applySuccessfulRepoCreateAuthorization(ctx context.Context, operation agentv1.Operation, result bkauthorization.Result) agentv1.Operation {
	if result.Request.Grant.ID == "" {
		return s.approveStoredOperation(operation)
	}
	return s.bindRepoCreateApproval(ctx, operation, result.Request.Grant)
}

func (s *Server) applyFailedRepoCreateAuthorization(operation agentv1.Operation, target repoCreateTarget, result bkauthorization.Result, err error) agentv1.Operation {
	if refused, ok := s.repoCreateRefusal(operation, target, result, err); ok {
		return refused
	}
	return s.repoCreateApprovalFailure(operation, result)
}

func (s *Server) repoCreateApprovalFailure(operation agentv1.Operation, result bkauthorization.Result) agentv1.Operation {
	if result.Decision.Effect != corepolicy.EffectRequest {
		return s.failOperation(operation.ID, agentv1.StateFailed, "approval_request_failed", "Could not create approval request")
	}
	return s.repoCreateRequestFailure(operation)
}

func (s *Server) repoCreateRequestFailure(operation agentv1.Operation) agentv1.Operation {
	if !s.hasApprovalChannel() {
		return s.failOperation(operation.ID, agentv1.StateFailed, "approval_channel_not_configured", "Approval channel is not configured")
	}
	return s.failOperation(operation.ID, agentv1.StateFailed, "approval_request_failed", "Could not create approval request")
}

func (s *Server) repoCreateRefusal(operation agentv1.Operation, target repoCreateTarget, result bkauthorization.Result, err error) (agentv1.Operation, bool) {
	decision := s.policy.AuthorizationDecision(result.Decision)
	if errors.Is(err, bkauthorization.ErrDenied) {
		s.recordPolicyDecision(operation.ClientID, operation.Operation, target.targetName(), audit.DecisionRefused, "policy_denied", 0, decision)
		return s.failOperation(operation.ID, agentv1.StateDenied, "policy_denied", "Policy denied this operation"), true
	}
	if errors.Is(err, bkauthorization.ErrNoMatch) {
		s.recordPolicyDecision(operation.ClientID, operation.Operation, target.targetName(), audit.DecisionRefused, "not_allowed", 0, decision)
		return s.failOperation(operation.ID, agentv1.StateDenied, "not_allowed", "No policy rule allows this operation"), true
	}
	return agentv1.Operation{}, false
}

func (s *Server) operationAuthorizationLock(id string) *sync.Mutex {
	var hash uint64 = 14695981039346656037
	for i := 0; i < len(id); i++ {
		hash ^= uint64(id[i])
		hash *= 1099511628211
	}
	return &s.operationAuthLocks[hash%uint64(len(s.operationAuthLocks))]
}

func (s *Server) approveStoredOperation(operation agentv1.Operation) agentv1.Operation {
	updated, err := s.operations.Transition(operation.ID, agentv1.StateApproved)
	if err == nil {
		return updated
	}
	current, getErr := s.operations.GetByID(operation.ID)
	if getErr == nil && current.State != agentv1.StatePending {
		return current
	}
	return s.failOperation(operation.ID, agentv1.StateFailed, "operation_store_unavailable", "Could not update operation")
}

func (s *Server) bindRepoCreateApproval(ctx context.Context, operation agentv1.Operation, grant grants.Grant) agentv1.Operation {
	if s.notifier != nil {
		if err := s.notifyRepoCreateApproval(ctx, grant); err != nil {
			if errors.Is(err, errApprovalNotificationClaimed) {
				return operation
			}
			return s.failOperation(operation.ID, agentv1.StateFailed, "approval_notification_failed", "Could not notify the operator")
		}
	}
	updated, err := s.operations.SetApproval(operation.ID, grant.ID)
	if err == nil {
		return updated
	}
	return s.failOperation(operation.ID, agentv1.StateFailed, "operation_store_unavailable", "Could not bind approval request")
}

func (s *Server) notifyRepoCreateApproval(ctx context.Context, grant grants.Grant) error {
	claim, claimed, err := s.grants.ClaimNotification(grant.ID, grantNotificationClaimLease)
	if err != nil {
		return err
	}
	if !claimed {
		return s.existingRepoCreateNotification(grant.ID)
	}
	ref, err := s.notifier.SendApproval(ctx, grantApprovalMessage(claim.Grant, claim.DecisionToken))
	if err != nil {
		return s.settleRepoCreateNotificationFailure(claim, err)
	}
	if ref.MessageID <= 0 {
		return s.settleRepoCreateNotificationFailure(claim, errors.New("approval notifier returned an invalid message"))
	}
	if err := s.recordRepoCreateNotification(claim, ref); err != nil {
		return s.settleRepoCreateNotificationFailure(claim, err)
	}
	return nil
}

func (s *Server) existingRepoCreateNotification(grantID string) error {
	current, err := s.grants.Get(grantID)
	if err == nil && current.Notification != nil {
		return nil
	}
	return errApprovalNotificationClaimed
}

func (s *Server) recordRepoCreateNotification(claim grants.NotificationClaim, ref grants.MessageRef) error {
	current, recorded, err := s.grants.SetNotificationIfClaimed(claim.Grant.ID, claim.Grant.NotificationClaimedAt, ref)
	if err != nil {
		return err
	}
	if recorded || current.Notification != nil {
		return nil
	}
	return errors.New("approval notification claim changed")
}

func (s *Server) settleRepoCreateNotificationFailure(claim grants.NotificationClaim, cause error) error {
	if s.operatorConfigured {
		_, _, retainErr := s.grants.RetainNotificationClaim(claim.Grant.ID, claim.Grant.NotificationClaimedAt)
		return retainErr
	}
	_, _, cancelErr := s.grants.CancelIfNotificationClaimed(claim.Grant.ID, claim.Grant.NotificationClaimedAt)
	if cancelErr != nil {
		return cancelErr
	}
	return cause
}

func (s *Server) prepareRepoCreateIntent(operation agentv1.Operation, target repoCreateTarget, attrs map[string]any, authorizationRequest corepolicy.Request, bounds *corepolicy.GrantPolicy) (bkauthorization.GrantIntent, error) {
	if bounds == nil || corepolicy.GrantMode(bounds.Mode) != corepolicy.GrantModeExecution {
		return bkauthorization.GrantIntent{}, errors.New("repo.create requires execution approval")
	}
	request, plan, err := hfgrant.Prepare(s.grants, s.plans, hfgrant.Input{
		Client: operation.ClientID, ClientRequestID: operation.ID, Operation: operation.Operation, Mode: hfgrant.ModeExecution,
		Target: target.targetName(), Attrs: attrs, Reason: operation.Reason, RequestedDuration: time.Duration(bounds.DefaultMinutes) * time.Minute,
		PendingTimeout: time.Duration(bounds.RequestTTLMinutes) * time.Minute,
		MaxUses:        int(bounds.DefaultMaxUses), MaxUsesSpecified: true,
	})
	if err != nil {
		return bkauthorization.GrantIntent{}, err
	}
	return bkauthorization.GrantIntent{
		Mode: corepolicy.GrantModeExecution, Authorization: authorizationRequest, Request: request, Plan: plan,
	}, nil
}

func decodeRepoCreate(request agentv1.SubmitRequest) (repoCreateTarget, repoCreateArguments, error) {
	target, err := decodeRepoCreateTarget(request.Target)
	if err != nil {
		return repoCreateTarget{}, repoCreateArguments{}, err
	}
	arguments, err := decodeRepoCreateArguments(request.Arguments, target.Type)
	if err != nil {
		return repoCreateTarget{}, repoCreateArguments{}, err
	}
	return target, arguments, nil
}

func decodeRepoCreateTarget(raw []byte) (repoCreateTarget, error) {
	var target repoCreateTarget
	if err := decodeStrictObject(raw, &target); err != nil {
		return repoCreateTarget{}, errors.New("invalid repository target")
	}
	if target.Kind != "repo" || !validCreateRepoType(target.Type) || !repoSegmentPattern.MatchString(target.Owner) || !repoSegmentPattern.MatchString(target.Name) {
		return repoCreateTarget{}, errors.New("repository target must contain an exact type, owner, and name")
	}
	return target, nil
}

func decodeRepoCreateArguments(raw []byte, repoType policy.RepoType) (repoCreateArguments, error) {
	var arguments repoCreateArguments
	if err := decodeStrictObject(raw, &arguments); err != nil {
		return repoCreateArguments{}, errors.New("invalid repository arguments")
	}
	if arguments.Private == nil {
		return repoCreateArguments{}, errors.New("repository privacy is required")
	}
	if repoType == policy.TypeSpace && arguments.SDK != "docker" && arguments.SDK != "gradio" && arguments.SDK != "static" {
		return repoCreateArguments{}, errors.New("space SDK must be docker, gradio, or static")
	}
	if repoType != policy.TypeSpace && arguments.SDK != "" {
		return repoCreateArguments{}, errors.New("SDK is supported only for Spaces")
	}
	return arguments, nil
}

func decodeStrictObject(data []byte, out any) error {
	if len(data) == 0 || len(data) > 4096 {
		return errors.New("invalid JSON object")
	}
	return strictjson.Decode(data, out, true)
}

func validCreateRepoType(repoType policy.RepoType) bool {
	return repoType == policy.TypeModel || repoType == policy.TypeDataset || repoType == policy.TypeSpace
}

func (target repoCreateTarget) policyTarget() policy.Target {
	return policy.Target{Kind: policy.KindRepo, Type: target.Type, Owner: target.Owner, Name: target.Name}
}

func (target repoCreateTarget) targetName() string {
	return targetName(route{repoType: target.Type, owner: target.Owner, name: target.Name})
}

func repoCreateAttrs(arguments repoCreateArguments) map[string]any {
	attrs := map[string]any{"private": strconv.FormatBool(*arguments.Private)}
	if arguments.SDK != "" {
		attrs["sdk"] = arguments.SDK
	}
	return attrs
}

func repoCreateSummary(target repoCreateTarget, arguments repoCreateArguments) string {
	visibility := "public"
	if arguments.Private != nil && *arguments.Private {
		visibility = "private"
	}
	return fmt.Sprintf("Create %s %s %s/%s", visibility, target.Type, target.Owner, target.Name)
}

func (s *Server) failOperation(id string, state agentv1.State, code, message string) agentv1.Operation {
	operation, err := s.operations.Fail(id, state, code, message)
	if err != nil {
		operation, _ = s.operations.GetByID(id)
	}
	return operation
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
	operations, err := s.operations.ListUnfinished()
	if err != nil {
		return
	}
	for _, operation := range operations {
		if operation.State == agentv1.StateExecuting {
			_, _ = s.operations.Fail(operation.ID, agentv1.StateFailed, "execution_interrupted", "Broker restarted during execution; result is unknown")
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
		target, arguments, err := decodeRepoCreate(agentv1.SubmitRequest{Target: operation.Target, Arguments: operation.Arguments})
		if err != nil {
			_, _ = s.operations.Fail(operation.ID, agentv1.StateFailed, "invalid_stored_operation", "Stored operation is invalid")
			return
		}
		operation = s.authorizeRepoCreate(ctx, operation, target, arguments)
	}
	if operation.State == agentv1.StatePending && operation.ApprovalID != "" {
		operation = s.syncOperationApproval(operation)
	}
	if operation.State != agentv1.StateApproved {
		return
	}
	claimed, err := s.operations.Transition(operation.ID, agentv1.StateExecuting)
	if err != nil {
		return
	}
	s.executeRepoCreate(ctx, claimed)
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
		updated, _ := s.operations.Fail(operation.ID, agentv1.StateDenied, "approval_denied", "Approval was denied")
		return updated
	case grants.StatusExpired:
		updated, _ := s.operations.Fail(operation.ID, agentv1.StateExpired, "approval_expired", "Approval request expired")
		return updated
	case grants.StatusCanceled, grants.StatusRevoked:
		updated, _ := s.operations.Fail(operation.ID, agentv1.StateCanceled, "approval_canceled", "Approval was canceled")
		return updated
	default:
		return operation
	}
}

func (s *Server) executeRepoCreate(ctx context.Context, operation agentv1.Operation) {
	target, arguments, err := decodeRepoCreate(agentv1.SubmitRequest{Target: operation.Target, Arguments: operation.Arguments})
	if err != nil {
		_, _ = s.operations.Fail(operation.ID, agentv1.StateFailed, "invalid_stored_operation", "Stored operation is invalid")
		return
	}
	reserved, ok := s.reserveOperationApproval(operation)
	if !ok {
		return
	}
	result, definitive, err := s.createUpstreamRepo(ctx, target, arguments)
	if err != nil {
		s.failRepoExecution(operation, target, reserved, definitive)
		return
	}
	if reserved {
		if _, err := s.grants.CommitUse(operation.ApprovalID); err != nil {
			_, _ = s.operations.Fail(operation.ID, agentv1.StateFailed, "approval_commit_failed", "Repository was created but approval accounting failed")
			return
		}
	}
	encoded, _ := json.Marshal(result)
	_, _ = s.operations.Succeed(operation.ID, encoded)
	s.record(operation.ClientID, operation.Operation, target.targetName(), audit.DecisionAllowed, "", http.StatusOK)
}

func (s *Server) reserveOperationApproval(operation agentv1.Operation) (bool, bool) {
	if operation.ApprovalID == "" {
		return false, true
	}
	grant, err := s.grants.Get(operation.ApprovalID)
	if err != nil || s.planValidator.ValidateExecution(grant) != nil {
		_, _ = s.operations.Fail(operation.ID, agentv1.StateFailed, "approval_invalid", "Approval no longer matches the operation")
		return false, false
	}
	if _, err := s.grants.ReserveUse(grant.ID); err != nil {
		_, _ = s.operations.Fail(operation.ID, agentv1.StateFailed, "approval_unavailable", "Approval could not be reserved")
		return false, false
	}
	return true, true
}

func (s *Server) failRepoExecution(operation agentv1.Operation, target repoCreateTarget, reserved, definitive bool) {
	if reserved {
		if definitive {
			_, _ = s.grants.CommitUse(operation.ApprovalID)
		} else {
			_, _ = s.grants.RetainUse(operation.ApprovalID)
		}
	}
	code := "upstream_rejected"
	message := "Hugging Face rejected the repository creation"
	if !definitive {
		code = "upstream_result_unknown"
		message = "Hugging Face repository creation result is unknown; it was not retried"
	}
	_, _ = s.operations.Fail(operation.ID, agentv1.StateFailed, code, message)
	s.record(operation.ClientID, operation.Operation, target.targetName(), audit.DecisionRefused, code, 0)
}

func (s *Server) createUpstreamRepo(ctx context.Context, target repoCreateTarget, arguments repoCreateArguments) (repoCreateResult, bool, error) {
	identity, definitive, err := s.upstreamIdentity(ctx)
	if err != nil {
		return repoCreateResult{}, definitive, err
	}
	payload := map[string]any{"name": target.Name, "type": string(target.Type), "private": *arguments.Private}
	if target.Owner == identity {
		payload["organization"] = nil
	} else {
		payload["organization"] = target.Owner
	}
	if arguments.SDK != "" {
		payload["sdk"] = arguments.SDK
	}
	body, _ := json.Marshal(payload)
	requestURL := strings.TrimRight(s.upstream.String(), "/") + "/api/repos/create"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, requestURL, bytes.NewReader(body))
	if err != nil {
		return repoCreateResult{}, false, err
	}
	req.Header.Set("Authorization", "Bearer "+s.hfToken)
	req.Header.Set("Content-Type", "application/json")
	response, err := s.agentUpstreamClient().Do(req)
	if err != nil {
		return repoCreateResult{}, false, err
	}
	defer func() { _ = response.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, maxUpstreamBody))
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return repoCreateResult{}, response.StatusCode >= 400 && response.StatusCode < 500, fmt.Errorf("upstream status %d", response.StatusCode)
	}
	repoID := target.Owner + "/" + target.Name
	return repoCreateResult{RepoID: repoID, URL: strings.TrimRight(s.upstream.String(), "/") + "/" + repoURLPrefix(target.Type) + repoID}, true, nil
}

func (s *Server) upstreamIdentity(ctx context.Context) (string, bool, error) {
	requestURL := strings.TrimRight(s.upstream.String(), "/") + "/api/whoami-v2"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL, nil)
	if err != nil {
		return "", false, err
	}
	req.Header.Set("Authorization", "Bearer "+s.hfToken)
	response, err := s.agentUpstreamClient().Do(req)
	if err != nil {
		return "", false, err
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, maxUpstreamBody))
		return "", response.StatusCode >= 400 && response.StatusCode < 500, errors.New("could not identify upstream account")
	}
	var value struct {
		Name string `json:"name"`
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, maxUpstreamBody))
	if err := decoder.Decode(&value); err != nil || !repoSegmentPattern.MatchString(value.Name) {
		return "", false, errors.New("upstream identity response is invalid")
	}
	return value.Name, true, nil
}

func (s *Server) agentUpstreamClient() *http.Client {
	return &http.Client{Timeout: s.httpClient.Timeout, CheckRedirect: func(*http.Request, []*http.Request) error {
		return errors.New("upstream redirect refused")
	}}
}

func repoURLPrefix(repoType policy.RepoType) string {
	switch repoType {
	case policy.TypeDataset:
		return "datasets/"
	case policy.TypeSpace:
		return "spaces/"
	default:
		return ""
	}
}
