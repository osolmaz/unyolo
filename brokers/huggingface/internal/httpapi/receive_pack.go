// Package httpapi exposes the broker HTTP surface.
package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	bkauthorization "github.com/osolmaz/brokerkit/authorization"
	"github.com/osolmaz/brokerkit/authorization/grants"
	corepolicy "github.com/osolmaz/brokerkit/authorization/policy"
	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/gitproxy"
	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/hfgrant"
	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/mirror"
	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/policy"
	"github.com/osolmaz/brokerkit/internal/slicex"
	"github.com/osolmaz/brokerkit/operation/digest"
	"github.com/osolmaz/brokerkit/telemetry/audit"
)

func (s *Server) handleReceivePack(w http.ResponseWriter, r *http.Request, client string, rt route, target string) {
	if status, operation, reason, ok := s.receivePackMayRead(client, rt); !ok {
		writePlain(w, status, "hf-broker: "+reason+"\n")
		s.record(client, operation, target, audit.DecisionRefused, reason, 0)
		return
	}
	req, body, ok := s.readReceivePack(w, r, client, target)
	if !ok {
		return
	}
	operation, reason, ok, inspectErr := s.receivePackMayInspect(client, rt, target, req)
	if inspectErr != nil {
		s.writeGrantStoreError(w, client, operation, target)
		return
	}
	if !ok {
		writePlain(w, http.StatusForbidden, "hf-broker: "+reason+"\n")
		s.record(client, operation, target, audit.DecisionRefused, reason, 0)
		return
	}
	repo := mirror.Repo{Kind: string(rt.repoType), Owner: rt.owner, Name: rt.name, UpstreamURL: s.upstreamRepoURL(rt)}
	upstreamStatus, lockErr := s.withLockedPush(w, r, rt, repo, req, body, client, target)
	if lockErr != nil {
		s.handleReceivePackError(w, client, target, upstreamStatus, lockErr)
	}
}

func (s *Server) handleReceivePackError(w http.ResponseWriter, client, target string, upstreamStatus int, err error) {
	if upstreamStatus == 0 {
		status, message := receivePackErrorResponse(err)
		writePlain(w, status, message)
	}
	s.record(client, string(policy.OpGitPushAppend), target, audit.DecisionRefused, "push enforcement failed: "+err.Error(), upstreamStatus)
}

func receivePackErrorResponse(err error) (int, string) {
	if errors.Is(err, errGrantStoreUnavailable) {
		return http.StatusInternalServerError, "hf-broker: could not inspect grants\n"
	}
	return http.StatusForbidden, "hf-broker: push refused\n"
}

func (s *Server) receivePackMayRead(client string, rt route) (int, string, string, bool) {
	decision, err := s.decideReceivePackDiscovery(client, rt)
	if err != nil {
		return http.StatusInternalServerError, "git.push", "could not inspect grants", false
	}
	if receivePackDiscoveryPermitted(decision) {
		return 0, "", "", true
	}
	return http.StatusForbidden, "git.push", pushFailureReason(decision), false
}

func (s *Server) receivePackMayInspect(client string, rt route, target string, req gitproxy.ReceivePackRequest) (string, string, bool, error) {
	packSize := int64(len(req.Pack))
	for _, command := range req.Commands {
		operation, reason, ok, err := s.commandMayInspect(client, rt, target, command, packSize)
		if err != nil || !ok {
			return operation, reason, false, err
		}
	}
	return "", "", true, nil
}

func (s *Server) commandMayInspect(client string, rt route, target string, command gitproxy.Command, packSize int64) (string, string, bool, error) {
	candidates := preflightPushCandidates(command)
	if len(candidates) == 0 {
		return "", "", true, nil
	}
	operation := preflightAuditOperation(candidates)
	reason := "no matching policy rule"
	for _, candidate := range candidates {
		ok, candidateReason, err := s.pushCandidateMayInspect(client, rt, target, command.Ref, candidate, packSize)
		if err != nil {
			return operation, "could not inspect grants", false, err
		}
		if ok {
			return "", "", true, nil
		}
		if candidateReason != "" {
			reason = candidateReason
		}
	}
	return operation, reason, false, nil
}

func (s *Server) pushCandidateMayInspect(client string, rt route, target, ref string, candidate pushPolicyCandidate, packSize int64) (bool, string, error) {
	attrs := pushAttrsForChange(candidate.refChange, packSize)
	decision, err := s.decideRepo(client, candidate.operation, rt, []string{ref}, attrs, false)
	if err != nil {
		return false, "could not inspect grants", err
	}
	if policyDenyRefusesGrant(decision) {
		return false, pushFailureReason(decision), nil
	}
	if decision.Effect == policy.EffectAllow || decision.Reason == "approval_required" {
		return true, "", nil
	}
	return false, pushFailureReason(decision), nil
}

func preflightPushCandidates(command gitproxy.Command) []pushPolicyCandidate {
	if isReplaceRef(command.Ref) {
		return nil
	}
	if gitproxy.IsZeroSHA(command.New) {
		return deletePushCandidates(command.Ref)
	}
	if updatesExistingTag(command) {
		return []pushPolicyCandidate{{operation: policy.OpGitTagUpdate, refChange: "tag_update"}}
	}
	if createsRef(command) {
		return []pushPolicyCandidate{{operation: policy.OpGitPushAppend, refChange: "create"}}
	}
	return branchUpdatePushCandidates()
}

func updatesExistingTag(command gitproxy.Command) bool {
	return isTagRef(command.Ref) && !gitproxy.IsZeroSHA(command.Old)
}

func createsRef(command gitproxy.Command) bool {
	return gitproxy.IsZeroSHA(command.Old) || isTagRef(command.Ref)
}

func branchUpdatePushCandidates() []pushPolicyCandidate {
	return []pushPolicyCandidate{
		{operation: policy.OpGitPushAppend, refChange: "fast_forward"},
		{operation: policy.OpGitPushForce, refChange: "non_fast_forward"},
	}
}

func deletePushCandidates(ref string) []pushPolicyCandidate {
	if isTagRef(ref) {
		return []pushPolicyCandidate{{operation: policy.OpGitTagUpdate, refChange: "tag_update"}}
	}
	return []pushPolicyCandidate{{operation: policy.OpGitRefDelete, refChange: "delete"}}
}

func preflightAuditOperation(candidates []pushPolicyCandidate) string {
	if len(candidates) == 0 {
		return string(policy.OpGitPushAppend)
	}
	operation := candidates[0].operation
	for _, candidate := range candidates[1:] {
		if candidate.operation != operation {
			return "git.push"
		}
	}
	return string(operation)
}

func (s *Server) readReceivePack(w http.ResponseWriter, r *http.Request, client, target string) (gitproxy.ReceivePackRequest, []byte, bool) {
	body, tooLarge, err := readLimited(r.Body, s.maxBody)
	if err != nil {
		writePlain(w, http.StatusBadRequest, "hf-broker: could not read push\n")
		s.record(client, string(policy.OpGitPushAppend), target, audit.DecisionRefused, "could not read push", 0)
		return gitproxy.ReceivePackRequest{}, nil, false
	}
	if tooLarge {
		writePlain(w, http.StatusRequestEntityTooLarge, "hf-broker: push pack exceeds configured limit\n")
		s.record(client, string(policy.OpGitPushAppend), target, audit.DecisionRefused, "push pack exceeds configured limit", 0)
		return gitproxy.ReceivePackRequest{}, nil, false
	}
	req, err := gitproxy.ParseReceivePack(body)
	if err != nil {
		writePlain(w, http.StatusBadRequest, "hf-broker: could not parse push\n")
		s.record(client, string(policy.OpGitPushAppend), target, audit.DecisionRefused, "could not parse push", 0)
		return gitproxy.ReceivePackRequest{}, nil, false
	}
	if len(req.Commands) == 0 {
		writePlain(w, http.StatusBadRequest, "hf-broker: empty push\n")
		s.record(client, string(policy.OpGitPushAppend), target, audit.DecisionRefused, "empty receive-pack command list", 0)
		return gitproxy.ReceivePackRequest{}, nil, false
	}
	return req, body, true
}

func (s *Server) withLockedPush(w http.ResponseWriter, r *http.Request, rt route, repo mirror.Repo, req gitproxy.ReceivePackRequest, body []byte, client, target string) (int, error) {
	var result lockedPushResult
	lockErr := s.mirrors.WithLock(repo, func(mir *mirror.Repository) error {
		var err error
		result, err = s.processLockedPush(w, r, rt, req, body, mir, client, target)
		return err
	})
	s.updateGrantMessages(result.retainedGrantsToNotify, s.updateRetainedGrantReservationMessage)
	s.updateGrantMessages(result.grantsToNotify, s.updateGrantUseMessage)
	return result.upstreamStatus, lockErr
}

func (s *Server) processLockedPush(w http.ResponseWriter, r *http.Request, rt route, req gitproxy.ReceivePackRequest, body []byte, mir *mirror.Repository, client, target string) (lockedPushResult, error) {
	refused, usedGrants, classes, err := s.refuseInvalidPush(w, r, req, mir, client, target)
	if err != nil || refused {
		return lockedPushResult{}, err
	}
	reservedGrants, err := s.reserveGrantUses(usedGrants)
	if err != nil {
		return lockedPushResult{}, err
	}
	return s.forwardReservedPush(w, r, rt, req, body, mir, client, target, usedGrants, reservedGrants, classes)
}

func (s *Server) forwardReservedPush(w http.ResponseWriter, r *http.Request, rt route, req gitproxy.ReceivePackRequest, body []byte, mir *mirror.Repository, client, target string, usedGrants []grantUse, reservedGrants []grants.Grant, classes []gitproxy.ClassifiedCommand) (lockedPushResult, error) {
	statusCode, accepted, reason, definitiveReject, err := s.forwardReceivePack(w, r, rt, req, body)
	result := lockedPushResult{upstreamStatus: statusCode}
	if err != nil {
		retainedGrants, retainErr := s.retainGrantUseReservations(reservedGrants)
		result.retainedGrantsToNotify = retainedGrants
		if retainErr != nil {
			return result, fmt.Errorf("%w; %w", err, retainErr)
		}
		return result, err
	}
	if !accepted {
		retainedGrants, err := s.handleRejectedReservedPush(client, target, pushAuditOperation(classes), reason, statusCode, definitiveReject, reservedGrants)
		result.retainedGrantsToNotify = retainedGrants
		return result, err
	}
	s.acceptReservedPush(req, mir, client, target, statusCode, usedGrants, reservedGrants, classes, &result)
	return result, nil
}

func (s *Server) handleRejectedReservedPush(client, target, operation, reason string, statusCode int, definitiveReject bool, reservedGrants []grants.Grant) ([]grants.Grant, error) {
	var retainedGrants []grants.Grant
	var err error
	if definitiveReject {
		s.releaseGrantUses(reservedGrants)
	} else {
		retainedGrants, err = s.retainGrantUseReservations(reservedGrants)
	}
	s.record(client, operation, target, audit.DecisionRefused, reason, statusCode)
	return retainedGrants, err
}

func (s *Server) acceptReservedPush(req gitproxy.ReceivePackRequest, mir *mirror.Repository, client, target string, statusCode int, usedGrants []grantUse, reservedGrants []grants.Grant, classes []gitproxy.ClassifiedCommand, result *lockedPushResult) {
	_ = gitproxy.AdvanceAccepted(context.Background(), req, mir)
	result.grantsToNotify = s.commitGrantUses(reservedGrants)
	operation := pushAuditOperation(classes)
	if len(usedGrants) > 0 {
		s.recordGrantUsed(client, grantAuditOperation(usedGrants), target, statusCode, grantUseIDs(usedGrants))
		return
	}
	s.record(client, operation, target, audit.DecisionAllowed, "", statusCode)
}

func (s *Server) refuseInvalidPush(w http.ResponseWriter, r *http.Request, req gitproxy.ReceivePackRequest, mir *mirror.Repository, client, target string) (bool, []grantUse, []gitproxy.ClassifiedCommand, error) {
	used := map[string]grantUse{}
	classes, failures, err := gitproxy.ClassifyPush(r.Context(), req, mir)
	if err == nil && len(failures) == 0 {
		failures, err = s.refusePolicyDeniedPush(classes, client, target, int64(len(req.Pack)), used)
	}
	if len(failures) > 0 {
		report, reportErr := gitproxy.BuildRefusalReport(req, failures)
		if reportErr != nil {
			return false, nil, nil, reportErr
		}
		w.Header().Set("Content-Type", "application/x-git-receive-pack-result")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(report)
		s.record(client, pushAuditOperation(classes), target, audit.DecisionRefused, failures[0].Reason, 0)
		return true, nil, nil, nil
	}
	if err != nil {
		return false, nil, nil, err
	}
	return false, slicex.Values(used), classes, nil
}

func (s *Server) refusePolicyDeniedPush(classes []gitproxy.ClassifiedCommand, client, target string, packSize int64, used map[string]grantUse) ([]gitproxy.RefFailure, error) {
	rt, ok := parseGrantTarget(target)
	if !ok {
		return refFailuresForClasses(classes, "invalid target"), nil
	}
	var failures []gitproxy.RefFailure
	for _, class := range classes {
		failure, refused, err := s.refusalForClassifiedPush(class, client, rt, target, packSize, used)
		if err != nil {
			return nil, err
		}
		if refused {
			failures = append(failures, failure)
		}
	}
	return failures, nil
}

func (s *Server) refusalForClassifiedPush(class gitproxy.ClassifiedCommand, client string, rt route, target string, packSize int64, used map[string]grantUse) (gitproxy.RefFailure, bool, error) {
	operation := operationForRefUpdate(class.Kind)
	attrs := pushAttrs(class, packSize)
	providerRequest := policy.Request{Client: client, Operation: operation, Target: routeTarget(rt, []string{class.Command.Ref}), Attrs: attrs}
	authorizationRequest := policy.AuthorizationRequest(providerRequest)
	result, err := s.authorization.Authorize(authorizationRequest, func(decision corepolicy.Decision) (bkauthorization.GrantIntent, error) {
		return s.preparePushIntent(client, operation, target, class.Command.Ref, attrs, authorizationRequest, decision)
	})
	return s.pushAuthorizationRefusal(class.Command.Ref, client, operation, target, attrs, used, result, err)
}

func (s *Server) pushAuthorizationRefusal(ref, client string, operation policy.Operation, target string, attrs map[string]any, used map[string]grantUse, result bkauthorization.Result, err error) (gitproxy.RefFailure, bool, error) {
	decision := s.policy.AuthorizationDecision(result.Decision)
	if err != nil {
		return s.failedPushAuthorization(ref, result, decision, err)
	}
	if result.Request.Grant.ID != "" {
		return gitproxy.RefFailure{Ref: ref, Reason: approvalRetryReason(result.Request.Grant.ID)}, true, nil
	}
	if decision.Reason != "grant_allowed" {
		return gitproxy.RefFailure{}, false, nil
	}
	matched, err := s.useGrantAllowedDecision(decision, client, operation, target, ref, attrs, used)
	if err != nil {
		return gitproxy.RefFailure{}, false, err
	}
	if !matched {
		return gitproxy.RefFailure{}, false, errors.New("authorized grant is unavailable")
	}
	return gitproxy.RefFailure{}, false, nil
}

func (s *Server) failedPushAuthorization(ref string, result bkauthorization.Result, decision policy.Decision, err error) (gitproxy.RefFailure, bool, error) {
	if errors.Is(err, bkauthorization.ErrDenied) {
		return refFailureForDecision(ref, decision), true, nil
	}
	return s.failedPushAuthorizationWithoutDeny(ref, result, decision, err)
}

func (s *Server) failedPushAuthorizationWithoutDeny(ref string, result bkauthorization.Result, decision policy.Decision, err error) (gitproxy.RefFailure, bool, error) {
	if errors.Is(err, bkauthorization.ErrNoMatch) {
		return refFailureForDecision(ref, decision), true, nil
	}
	if result.Decision.Effect != corepolicy.EffectRequest {
		return gitproxy.RefFailure{}, false, err
	}
	return s.failedPushRequest(ref, decision, err)
}

func (s *Server) failedPushRequest(ref string, decision policy.Decision, err error) (gitproxy.RefFailure, bool, error) {
	if !s.hasApprovalChannel() {
		return refFailureForDecision(ref, decision), true, nil
	}
	return gitproxy.RefFailure{}, false, err
}

func (s *Server) preparePushIntent(client string, operation policy.Operation, target, ref string, attrs map[string]any, authorizationRequest corepolicy.Request, decision corepolicy.Decision) (bkauthorization.GrantIntent, error) {
	if !s.hasApprovalChannel() {
		return bkauthorization.GrantIntent{}, errors.New("approval channel is not configured")
	}
	bounds := decision.GrantPolicy
	if bounds == nil || corepolicy.GrantMode(bounds.Mode) != corepolicy.GrantModeWindow {
		return bkauthorization.GrantIntent{}, errors.New("Git push requires a window approval") //nolint:staticcheck // User-facing provider name starts the sentence.
	}
	id, err := approvalRequestID("git", authorizationRequest, decision.MatchedRequestRuleIDs)
	if err != nil {
		return bkauthorization.GrantIntent{}, err
	}
	request, plan, err := hfgrant.Prepare(s.grants, s.plans, hfgrant.Input{
		Client: client, ClientRequestID: id, Operation: string(operation), Mode: hfgrant.ModeWindow,
		Target: target, Ref: ref, Attrs: attrs, Reason: "Git push requires approval",
		RequestedDuration: time.Duration(bounds.DefaultMinutes) * time.Minute,
		PendingTimeout:    time.Duration(bounds.RequestTTLMinutes) * time.Minute,
		MaxUses:           int(bounds.DefaultMaxUses), MaxUsesSpecified: true,
	})
	if err != nil {
		return bkauthorization.GrantIntent{}, err
	}
	return bkauthorization.GrantIntent{
		Mode: corepolicy.GrantModeWindow, Authorization: authorizationRequest, Request: request, Plan: plan,
	}, nil
}

func approvalRequestID(prefix string, request corepolicy.Request, ruleIDs []string) (string, error) {
	encoded, err := json.Marshal(struct {
		Request corepolicy.Request `json:"request"`
		Rules   []string           `json:"rules"`
	}{Request: request, Rules: ruleIDs})
	if err != nil {
		return "", err
	}
	return prefix + "-" + plandigest.Digest(encoded)[:48], nil
}

func approvalRetryReason(id string) string {
	return "approval required (" + id + "); approve and retry"
}

func (s *Server) useGrantAllowedDecision(decision policy.Decision, client string, operation policy.Operation, target, ref string, attrs map[string]any, used map[string]grantUse) (bool, error) {
	if decision.Reason != "grant_allowed" {
		return false, nil
	}
	return s.useActiveGrant(client, operation, target, ref, attrs, used)
}

func pushAttrs(class gitproxy.ClassifiedCommand, packSize int64) map[string]any {
	return pushAttrsForChange(refChangeForClass(class), packSize)
}

func pushAttrsForChange(refChange string, packSize int64) map[string]any {
	attrs := refChangeAttrs(refChange)
	addMaxBytesAttr(attrs, packSize)
	return attrs
}

func refChangeAttrs(refChange string) map[string]any {
	return map[string]any{"ref_change": refChange}
}

func maxBytesAttrsForRequest(r *http.Request, body []byte, bodyRead bool) map[string]any {
	if bodyRead {
		return maxBytesAttrs(int64(len(body)))
	}
	if requestMayHaveBody(r.Method) && r.ContentLength >= 0 {
		return maxBytesAttrs(r.ContentLength)
	}
	return nil
}

func requestMayHaveBody(method string) bool {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch:
		return true
	default:
		return false
	}
}

func maxBytesAttrs(size int64) map[string]any {
	attrs := map[string]any{}
	addMaxBytesAttr(attrs, size)
	return attrs
}

func addMaxBytesAttr(attrs map[string]any, size int64) {
	if size >= 0 {
		attrs["max_bytes"] = size
	}
}

func refChangeForClass(class gitproxy.ClassifiedCommand) string {
	switch class.Kind {
	case gitproxy.RefUpdateAppend:
		if gitproxy.IsZeroSHA(class.Command.Old) {
			return "create"
		}
		return "fast_forward"
	case gitproxy.RefUpdateHistoryRewrite:
		return "non_fast_forward"
	case gitproxy.RefUpdateRefDelete:
		return "delete"
	case gitproxy.RefUpdateTagUpdate:
		return "tag_update"
	default:
		return string(class.Kind)
	}
}

func policyDenyRefusesGrant(decision policy.Decision) bool {
	return decision.Effect == policy.EffectDeny && decision.Reason == "policy_denied"
}

func (s *Server) useActiveGrant(client string, operation policy.Operation, target, ref string, attrs map[string]any, used map[string]grantUse) (bool, error) {
	grant, matched, err := s.matchActiveGrant(client, operation, target, ref, attrs)
	if err != nil {
		return false, fmt.Errorf("%w: %w", errGrantStoreUnavailable, err)
	}
	if !matched {
		return false, nil
	}
	used[grant.ID] = grantUse{grant: grant, ref: ref}
	return true, nil
}

func (s *Server) matchActiveGrant(client string, operation policy.Operation, target, ref string, attrs map[string]any) (grants.Grant, bool, error) {
	return hfgrant.MatchActiveFunc(s.grants, client, string(operation), target, ref, func(grant grants.Grant) bool {
		values, err := hfgrant.Attrs(grant)
		return err == nil && s.planValidator.ValidateExecution(grant) == nil && runtimeWindowGrant(grant) && policy.AttrValuesMatch(values, attrs)
	})
}

func runtimeWindowGrant(grant grants.Grant) bool {
	return hfgrant.Mode(grant) == hfgrant.ModeWindow
}

func refFailureForDecision(ref string, decision policy.Decision) gitproxy.RefFailure {
	return gitproxy.RefFailure{Ref: ref, Reason: pushFailureReason(decision)}
}

func refFailuresForClasses(classes []gitproxy.ClassifiedCommand, reason string) []gitproxy.RefFailure {
	failures := make([]gitproxy.RefFailure, 0, len(classes))
	for _, class := range classes {
		failures = append(failures, gitproxy.RefFailure{Ref: class.Command.Ref, Reason: reason})
	}
	return failures
}

func operationForRefUpdate(kind gitproxy.RefUpdateKind) policy.Operation {
	switch kind {
	case gitproxy.RefUpdateHistoryRewrite:
		return policy.OpGitPushForce
	case gitproxy.RefUpdateRefDelete:
		return policy.OpGitRefDelete
	case gitproxy.RefUpdateTagUpdate:
		return policy.OpGitTagUpdate
	default:
		return policy.OpGitPushAppend
	}
}

func pushFailureReason(decision policy.Decision) string {
	switch decision.Reason {
	case "approval_required":
		return "approval required"
	case "policy_denied":
		return "policy denied"
	case "no_matching_rule":
		return "no matching policy rule"
	default:
		return decision.Reason
	}
}

func isTagRef(ref string) bool {
	return strings.HasPrefix(ref, "refs/tags/")
}

func isReplaceRef(ref string) bool {
	return strings.HasPrefix(ref, "refs/replace/")
}

func pushAuditOperation(classes []gitproxy.ClassifiedCommand) string {
	if len(classes) == 0 {
		return string(policy.OpGitPushAppend)
	}
	operation := operationForRefUpdate(classes[0].Kind)
	for _, class := range classes[1:] {
		if operationForRefUpdate(class.Kind) != operation {
			return "git.push"
		}
	}
	return string(operation)
}

func grantAuditOperation(used []grantUse) string {
	operation := used[0].grant.Operation
	for _, use := range used[1:] {
		if use.grant.Operation != operation {
			return "git.push"
		}
	}
	return operation
}

func grantUseIDs(used []grantUse) []string {
	ids := make([]string, 0, len(used))
	for _, use := range used {
		ids = append(ids, use.grant.ID)
	}
	sort.Strings(ids)
	return ids
}

func (s *Server) reserveGrantUses(uses []grantUse) ([]grants.Grant, error) {
	reserved := make([]grants.Grant, 0, len(uses))
	for _, use := range uses {
		if err := s.planValidator.ValidateExecution(use.grant); err != nil {
			s.releaseGrantUses(reserved)
			return nil, err
		}
		grant, err := s.grants.ReserveUse(use.grant.ID)
		if err != nil {
			s.releaseGrantUses(reserved)
			return nil, err
		}
		reserved = append(reserved, grant)
	}
	return reserved, nil
}

func (s *Server) commitGrantUses(reserved []grants.Grant) []grants.Grant {
	updated := make([]grants.Grant, 0, len(reserved))
	for _, grant := range reserved {
		committed, err := s.grants.CommitUse(grant.ID)
		if err != nil {
			continue
		}
		updated = append(updated, committed)
	}
	return updated
}

func (s *Server) releaseGrantUses(reserved []grants.Grant) {
	for _, grant := range reserved {
		_, _ = s.grants.ReleaseUse(grant.ID)
	}
}

func (s *Server) retainGrantUseReservations(reserved []grants.Grant) ([]grants.Grant, error) {
	retained := make([]grants.Grant, 0, len(reserved))
	for _, grant := range reserved {
		current, err := s.grants.RetainUse(grant.ID)
		if err != nil {
			return retained, fmt.Errorf("retain grant reservation: %w", err)
		}
		retained = append(retained, current)
	}
	return retained, nil
}

func (s *Server) updateGrantMessages(updated []grants.Grant, update func(grants.Grant)) {
	for _, grant := range updated {
		update(grant)
	}
}
