package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/osolmaz/brokerkit/agentops"
	"github.com/osolmaz/brokerkit/agentv1"
	"github.com/osolmaz/brokerkit/agentv1wire"
	bkauth "github.com/osolmaz/brokerkit/auth"
	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/audit"
	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/hfgrant"
	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/policy"
	"github.com/osolmaz/brokerkit/grants"
	"github.com/osolmaz/brokerkit/httpx"
	"github.com/osolmaz/brokerkit/internal/strictjson"
	"github.com/osolmaz/brokerkit/protocol/agentwire"
)

const (
	agentDiscoveryPath  = "/.well-known/brokerkit-agent"
	agentOperationsPath = "/api/agent/v1/operations"
	maxAgentRequestBody = 16 * 1024
	maxUpstreamBody     = 64 * 1024
)

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

var _ agentwire.ServerInterface = (*Server)(nil)

func (s *Server) DiscoverAgent(c echo.Context) error {
	_, ok := s.authenticateAgent(c.Response(), c.Request())
	if !ok {
		return nil
	}
	return c.JSON(http.StatusOK, agentwire.Descriptor{ApiVersion: agentwire.DescriptorApiVersionBrokerkitIoagentv1})
}

func (s *Server) SubmitAgentOperation(c echo.Context) error {
	return s.withAuthenticatedAgent(c, s.handleAgentOperationSubmit)
}

func (s *Server) GetAgentOperation(c echo.Context, _ agentwire.OperationID) error {
	return s.withAuthenticatedAgent(c, s.handleAgentOperationGet)
}

func (s *Server) WaitForAgentOperation(c echo.Context, _ agentwire.OperationID, _ agentwire.WaitForAgentOperationParams) error {
	return s.withAuthenticatedAgent(c, s.handleAgentOperationGet)
}

func (s *Server) withAuthenticatedAgent(c echo.Context, handler func(http.ResponseWriter, *http.Request, string)) error {
	client, ok := s.authenticateAgent(c.Response(), c.Request())
	if ok {
		handler(c.Response(), c.Request(), client)
	}
	return nil
}

func (s *Server) authenticateAgent(w http.ResponseWriter, r *http.Request) (string, bool) {
	client, err := s.control.Clients.AuthenticateHeader(r.Header.Get("Authorization"))
	if err == nil {
		return client, true
	}
	status := http.StatusForbidden
	if errors.Is(err, bkauth.ErrMissing) {
		status = http.StatusUnauthorized
	}
	if r.Header.Get("Authorization") == "" {
		status = http.StatusUnauthorized
		w.Header().Set("WWW-Authenticate", `Bearer realm="hf-broker"`)
	}
	writeAgentError(w, status, "authentication_failed", "Authentication failed")
	s.record("system", "agent.authenticate", "", audit.DecisionRefused, "authentication failed", 0)
	return "", false
}

func (s *Server) handleAgentOperationSubmit(w http.ResponseWriter, r *http.Request, client string) {
	request, err := readAgentSubmit(r)
	if err != nil {
		writeAgentError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if request.Operation != string(policy.OpRepoCreate) {
		writeAgentError(w, http.StatusBadRequest, "unsupported_operation", "Unsupported agent operation")
		return
	}
	target, arguments, err := decodeRepoCreate(request)
	if err != nil {
		writeAgentError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	presentation := agentv1.Presentation{Title: "Create Hugging Face repository", Summary: repoCreateSummary(target, arguments)}
	operation, created, err := s.operations.Submit(agentops.Submit{
		Broker: "hf-broker", ClientID: client, IdempotencyKey: request.IdempotencyKey, Operation: request.Operation,
		Target: request.Target, Arguments: request.Arguments, Reason: request.Reason, Presentation: presentation,
	})
	if errors.Is(err, agentops.ErrIdempotencyConflict) {
		writeAgentError(w, http.StatusConflict, "idempotency_conflict", "Idempotency key was reused with a different operation")
		return
	}
	if err != nil {
		writeAgentError(w, http.StatusInternalServerError, "operation_store_unavailable", "Could not store operation")
		return
	}
	if created || operation.State == agentv1.StatePending && operation.ApprovalID == "" {
		operation = s.authorizeRepoCreate(s.agentLifecycleContext(), operation, target, arguments)
	}
	writeAgentOperation(w, operation, created)
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
	decision := s.repoCreateDecision(operation.ClientID, target, attrs)
	switch decision.Effect {
	case policy.EffectAllow:
		return s.approveStoredOperation(operation)
	case policy.EffectRequest:
		return s.bindRepoCreateApproval(ctx, operation, target, attrs, decision.GrantPolicy)
	case policy.EffectDeny:
		s.recordPolicyDecision(operation.ClientID, operation.Operation, target.targetName(), audit.DecisionRefused, "policy_denied", 0, decision)
		return s.failOperation(operation.ID, agentv1.StateDenied, "policy_denied", "Policy denied this operation")
	default:
		s.recordPolicyDecision(operation.ClientID, operation.Operation, target.targetName(), audit.DecisionRefused, "not_allowed", 0, decision)
		return s.failOperation(operation.ID, agentv1.StateDenied, "not_allowed", "No policy rule allows this operation")
	}
}

func (s *Server) operationAuthorizationLock(id string) *sync.Mutex {
	var hash uint64 = 14695981039346656037
	for i := 0; i < len(id); i++ {
		hash ^= uint64(id[i])
		hash *= 1099511628211
	}
	return &s.operationAuthLocks[hash%uint64(len(s.operationAuthLocks))]
}

func (s *Server) repoCreateDecision(client string, target repoCreateTarget, attrs map[string]any) policy.Decision {
	request := policy.Request{Client: client, Operation: policy.OpRepoCreate, Target: target.policyTarget(), Attrs: attrs}
	now := s.utcNow()
	decision := s.policy.Decide(request, nil, now, false)
	if decision.Effect == policy.EffectDeny && decision.Reason == "approval_required" {
		return s.policy.Decide(request, nil, now, true)
	}
	return decision
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

func (s *Server) bindRepoCreateApproval(ctx context.Context, operation agentv1.Operation, target repoCreateTarget, attrs map[string]any, bounds *policy.GrantPolicy) agentv1.Operation {
	if !s.operatorConfigured && s.notifier == nil {
		return s.failOperation(operation.ID, agentv1.StateFailed, "approval_channel_not_configured", "Approval channel is not configured")
	}
	grant, err := s.createRepoApproval(operation, target, attrs, bounds)
	if err != nil {
		return s.failOperation(operation.ID, agentv1.StateFailed, "approval_request_failed", "Could not create approval request")
	}
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

func (s *Server) createRepoApproval(operation agentv1.Operation, target repoCreateTarget, attrs map[string]any, bounds *policy.GrantPolicy) (grants.Grant, error) {
	if bounds == nil || bounds.Mode != policy.GrantModeExecution {
		return grants.Grant{}, errors.New("repo.create requires execution approval")
	}
	minutes := bounds.DefaultMinutes
	maxUses := bounds.DefaultMaxUses
	result, _, err := hfgrant.Request(s.grants, s.plans, hfgrant.Input{
		Client: operation.ClientID, ClientRequestID: operation.ID, Operation: operation.Operation, Mode: hfgrant.ModeExecution,
		Target: target.targetName(), Attrs: attrs, Reason: operation.Reason, RequestedDuration: time.Duration(minutes) * time.Minute,
		PendingTimeout: time.Duration(bounds.RequestTTLMinutes) * time.Minute, MaxUses: maxUses,
	})
	return result.Grant, err
}

func (s *Server) handleAgentOperationGet(w http.ResponseWriter, r *http.Request, client string) {
	id := operationPathID(r.URL.Path)
	if id == "" {
		writeAgentError(w, http.StatusNotFound, "not_found", "Operation not found")
		return
	}
	operation, err := s.operations.Get(client, id)
	if errors.Is(err, agentops.ErrNotFound) {
		writeAgentError(w, http.StatusNotFound, "not_found", "Operation not found")
		return
	}
	if err != nil {
		writeAgentError(w, http.StatusInternalServerError, "operation_store_unavailable", "Could not read operation")
		return
	}
	if strings.HasSuffix(r.URL.Path, "/events") {
		after, wait, ok := agentWaitQuery(r)
		if !ok {
			writeAgentError(w, http.StatusBadRequest, "invalid_request", "Invalid operation wait query")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), wait)
		defer cancel()
		operation, err = s.operations.Wait(ctx, client, id, after)
		if err != nil {
			writeAgentError(w, http.StatusInternalServerError, "operation_store_unavailable", "Could not wait for operation")
			return
		}
	}
	writeAgentOperation(w, operation, false)
}

func operationPathID(path string) string {
	if !strings.HasPrefix(path, agentOperationsPath+"/") {
		return ""
	}
	tail := strings.TrimPrefix(path, agentOperationsPath+"/")
	tail = strings.TrimSuffix(tail, "/events")
	if tail == "" || strings.Contains(tail, "/") || len(tail) > 128 {
		return ""
	}
	return tail
}

func agentWaitQuery(r *http.Request) (int64, time.Duration, bool) {
	after, ok := agentAfterRevision(r.URL.Query().Get("after_revision"))
	if !ok {
		return 0, 0, false
	}
	wait, ok := agentWaitDuration(r.URL.Query().Get("wait_seconds"))
	if !ok {
		return 0, 0, false
	}
	return after, wait, true
}

func agentAfterRevision(value string) (int64, bool) {
	if value == "" {
		return 0, true
	}
	after, err := strconv.ParseInt(value, 10, 64)
	return after, err == nil && after >= 0
}

func agentWaitDuration(value string) (time.Duration, bool) {
	if value == "" {
		return 30 * time.Second, true
	}
	seconds, err := strconv.Atoi(value)
	return time.Duration(seconds) * time.Second, err == nil && seconds >= 0 && seconds <= 30
}

func readAgentSubmit(r *http.Request) (agentv1.SubmitRequest, error) {
	var wire agentwire.SubmitRequest
	if err := httpx.DecodeJSON(r.Body, maxAgentRequestBody, &wire, true); err != nil {
		return agentv1.SubmitRequest{}, fmt.Errorf("agent operation request is invalid: %w", err)
	}
	request, err := agentv1wire.SubmitFromWire(wire)
	if err != nil {
		return agentv1.SubmitRequest{}, fmt.Errorf("agent operation request is invalid: %w", err)
	}
	if strings.TrimSpace(request.IdempotencyKey) == "" || len(request.IdempotencyKey) > 128 || strings.TrimSpace(request.Reason) == "" || len(request.Reason) > 512 {
		return agentv1.SubmitRequest{}, errors.New("idempotency key and reason are required")
	}
	return request, nil
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

func writeAgentOperation(w http.ResponseWriter, operation agentv1.Operation, created bool) {
	wire, err := agentv1wire.OperationToWire(operation)
	if err != nil {
		writeAgentError(w, http.StatusInternalServerError, "operation_store_unavailable", "Stored operation is invalid")
		return
	}
	status := http.StatusOK
	if created && !operation.State.Terminal() {
		status = http.StatusAccepted
	}
	if !operation.State.Terminal() {
		w.Header().Set("Location", agentOperationsPath+"/"+url.PathEscape(operation.ID))
		w.Header().Set("Retry-After", "2")
	}
	writeJSON(w, status, wire)
}

func writeAgentError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, agentwire.ErrorEnvelope{Error: agentwire.OperationError{Code: code, Message: message}})
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
