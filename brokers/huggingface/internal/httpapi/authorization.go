// Package httpapi exposes the broker HTTP surface.
package httpapi

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/osolmaz/brokerkit/audit"
	bkauthorization "github.com/osolmaz/brokerkit/authorization"
	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/hfgrant"
	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/policy"
	"github.com/osolmaz/brokerkit/grants"
	corepolicy "github.com/osolmaz/brokerkit/policy"
)

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if s.router != nil {
		s.router.ServeHTTP(w, r)
		return
	}
	s.serveHTTP(w, r)
}

// serveHTTP routes one broker request after Echo dispatch.
func (s *Server) serveHTTP(w http.ResponseWriter, r *http.Request) {
	if writeHealth(w, r) {
		return
	}
	if isAPIPath(r.URL.Path) {
		s.serveAPI(w, r)
		return
	}
	client, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	if isInferencePath(r.URL.Path) {
		s.serveInference(w, r, client)
		return
	}
	if strings.HasPrefix(r.URL.Path, "/v1/") {
		writeInferenceError(w, http.StatusNotFound, "unsupported_inference_route")
		s.record(client, "inference.unknown", "", audit.DecisionRefused, "unsupported_inference_route", 0)
		return
	}
	s.serveAuthenticated(w, r, client)
}

func (s *Server) serveAuthenticated(w http.ResponseWriter, r *http.Request, client string) {
	classified, status, reason := s.classify(r)
	if reason != "" {
		writePlain(w, status, "hf-broker: "+reason+"\n")
		s.record(client, "unknown", "", audit.DecisionRefused, reason, 0)
		return
	}
	target := targetName(classified.route)
	if classified.operation == policy.OpGitPushAppend && r.Method == http.MethodPost && classified.route.tail == "git-receive-pack" {
		s.handleReceivePack(w, r, client, classified.route, target)
		return
	}
	if receivePackDiscoveryRequest(r, classified) {
		s.handleReceivePackDiscovery(w, r, client, classified, target)
		return
	}
	result, decision, err := s.authorizeForwardRepo(client, r, classified, target)
	if s.writeForwardAuthorizationResponse(w, client, classified.operation, target, result, decision, err) {
		return
	}
	if s.forwardAllowedDecision(w, r, client, classified, target, decision) {
		return
	}
	writePlain(w, http.StatusForbidden, "hf-broker: "+decision.Reason+"\n")
	s.recordPolicyDecision(client, string(classified.operation), target, audit.DecisionRefused, decision.Reason, 0, decision)
}

func (s *Server) writeForwardAuthorizationResponse(w http.ResponseWriter, client string, operation policy.Operation, target string, result bkauthorization.Result, decision policy.Decision, err error) bool {
	if err != nil {
		return s.writeForwardAuthorizationError(w, client, operation, target, result, decision)
	}
	if result.Request.Grant.ID == "" {
		return false
	}
	reason := approvalRetryReason(result.Request.Grant.ID)
	writePlain(w, http.StatusForbidden, "hf-broker: "+reason+"\n")
	s.recordPolicyDecision(client, string(operation), target, audit.DecisionRefused, "approval_required", 0, decision)
	return true
}

func (s *Server) writeForwardAuthorizationError(w http.ResponseWriter, client string, operation policy.Operation, target string, result bkauthorization.Result, decision policy.Decision) bool {
	if result.Decision.Effect == "" {
		s.writeGrantStoreError(w, client, string(operation), target)
		return true
	}
	writePlain(w, http.StatusForbidden, "hf-broker: "+decision.Reason+"\n")
	s.recordPolicyDecision(client, string(operation), target, audit.DecisionRefused, decision.Reason, 0, decision)
	return true
}

func (s *Server) forwardAllowedDecision(w http.ResponseWriter, r *http.Request, client string, classified classifiedRequest, target string, decision policy.Decision) bool {
	if decision.Effect != policy.EffectAllow {
		return false
	}
	if decision.Reason == "grant_allowed" {
		return s.handleForwardWithActiveGrant(w, r, client, classified, target, decision, consumeForwardGrantUse(r, classified))
	}
	s.handleForward(w, r, client, classified, target, decision)
	return true
}

func receivePackDiscoveryRequest(r *http.Request, classified classifiedRequest) bool {
	return gitServiceDiscoveryRequest(r, classified, policy.OpGitPushAppend, "git-receive-pack")
}

func uploadPackDiscoveryRequest(r *http.Request, classified classifiedRequest) bool {
	return gitServiceDiscoveryRequest(r, classified, policy.OpGitFetch, "git-upload-pack")
}

func consumeForwardGrantUse(r *http.Request, classified classifiedRequest) bool {
	return !uploadPackDiscoveryRequest(r, classified) &&
		!lfsBatchRequest(r, classified) &&
		!lfsUploadRequest(r, classified)
}

func lfsBatchRequest(r *http.Request, classified classifiedRequest) bool {
	return r.Method == http.MethodPost && classified.route.tail == "info/lfs/objects/batch"
}

func lfsUploadRequest(r *http.Request, classified classifiedRequest) bool {
	if classified.operation != policy.OpGitPushAppend {
		return false
	}
	if r.Method == http.MethodPost && classified.route.tail == "info/lfs/objects/batch" {
		return true
	}
	return isLFSObjectUpload(r.Method, classified.route.tail)
}

func gitServiceDiscoveryRequest(r *http.Request, classified classifiedRequest, operation policy.Operation, service string) bool {
	return r.Method == http.MethodGet &&
		classified.operation == operation &&
		classified.route.tail == "info/refs" &&
		r.URL.Query().Get("service") == service
}

func (s *Server) handleReceivePackDiscovery(w http.ResponseWriter, r *http.Request, client string, classified classifiedRequest, target string) {
	decision, err := s.decideReceivePackDiscovery(client, classified.route)
	if err != nil {
		s.writeGrantStoreError(w, client, string(classified.operation), target)
		return
	}
	if receivePackDiscoveryPermitted(decision) {
		s.handleForward(w, r, client, classified, target, decision)
		return
	}
	writePlain(w, http.StatusForbidden, "hf-broker: "+decision.Reason+"\n")
	s.recordPolicyDecision(client, string(classified.operation), target, audit.DecisionRefused, decision.Reason, 0, decision)
}

func receivePackDiscoveryPermitted(decision policy.Decision) bool {
	return decision.Effect == policy.EffectAllow
}

func (s *Server) decideReceivePackDiscovery(client string, rt route) (policy.Decision, error) {
	target := routeTarget(rt, nil)
	now := s.utcNow()
	activeGrants, err := s.activeGrantRules(client)
	if err != nil {
		return policy.Decision{}, err
	}
	var fallback policy.Decision
	for _, operation := range receivePackDiscoveryOperations() {
		decision := s.policy.DecideReceivePackDiscovery(policy.Request{
			Client:    client,
			Operation: operation,
			Target:    target,
		}, activeGrants, now)
		if receivePackDiscoveryPermitted(decision) {
			return decision, nil
		}
		fallback = receivePackDiscoveryFallback(fallback, decision)
	}
	if fallback.Reason == "" {
		return policy.Decision{Effect: policy.EffectNoMatch, Reason: "no_matching_rule"}, nil
	}
	return fallback, nil
}

func receivePackDiscoveryFallback(current, next policy.Decision) policy.Decision {
	if current.Reason == "" {
		return next
	}
	if next.Reason == "approval_required" {
		return next
	}
	if current.Reason == "approval_required" {
		return current
	}
	if current.Reason == "no_matching_rule" {
		return next
	}
	return current
}

func receivePackDiscoveryOperations() []policy.Operation {
	return []policy.Operation{
		policy.OpGitPushAppend,
		policy.OpGitPushForce,
		policy.OpGitRefDelete,
		policy.OpGitTagUpdate,
	}
}

func (s *Server) decideRepo(client string, operation policy.Operation, rt route, refs []string, attrs map[string]any, grantRequest bool) (policy.Decision, error) {
	return s.decideRepoWithOptions(client, operation, rt, refs, attrs, grantRequest, false)
}

func (s *Server) authorizeForwardRepo(client string, r *http.Request, classified classifiedRequest, target string) (bkauthorization.Result, policy.Decision, error) {
	if lfsUploadRequest(r, classified) {
		decision, err := s.decideRepoWithOptions(client, classified.operation, classified.route, nil, classified.attrs, false, true)
		return bkauthorization.Result{}, decision, err
	}
	providerRequest := policy.Request{
		Client: client, Operation: classified.operation, Target: routeTarget(classified.route, nil), Attrs: classified.attrs,
	}
	authorizationRequest := policy.AuthorizationRequest(providerRequest)
	result, err := s.authorization.Authorize(authorizationRequest, func(decision corepolicy.Decision) (bkauthorization.GrantIntent, error) {
		return s.prepareForwardIntent(client, classified.operation, target, classified.attrs, authorizationRequest, decision)
	})
	return result, s.policy.AuthorizationDecision(result.Decision), err
}

func (s *Server) prepareForwardIntent(client string, operation policy.Operation, target string, attrs map[string]any, authorizationRequest corepolicy.Request, decision corepolicy.Decision) (bkauthorization.GrantIntent, error) {
	bounds, err := s.forwardApprovalBounds(operation, decision.GrantPolicy)
	if err != nil {
		return bkauthorization.GrantIntent{}, err
	}
	id, err := approvalRequestID("http", authorizationRequest, decision.MatchedRequestRuleIDs)
	if err != nil {
		return bkauthorization.GrantIntent{}, err
	}
	request, plan, err := hfgrant.Prepare(s.grants, s.plans, hfgrant.Input{
		Client: client, ClientRequestID: id, Operation: string(operation), Mode: hfgrant.ModeWindow,
		Target: target, Attrs: attrs, Reason: string(operation) + " requires approval",
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

func (s *Server) forwardApprovalBounds(operation policy.Operation, bounds *corepolicy.GrantPolicy) (*corepolicy.GrantPolicy, error) {
	if !s.hasApprovalChannel() {
		return nil, errors.New("approval channel is not configured")
	}
	if bounds == nil || corepolicy.GrantMode(bounds.Mode) != corepolicy.GrantModeWindow || operationNeedsRef(operation) {
		return nil, errors.New("operation requires an exact window approval")
	}
	return bounds, nil
}

func (s *Server) decideRepoWithOptions(client string, operation policy.Operation, rt route, refs []string, attrs map[string]any, grantRequest bool, ignoreRefs bool) (policy.Decision, error) {
	activeGrants, err := s.activeGrantRules(client)
	if err != nil {
		return policy.Decision{}, err
	}
	return s.policy.Decide(policy.Request{
		Client:         client,
		Operation:      operation,
		Target:         routeTarget(rt, refs),
		Attrs:          attrs,
		IgnoreRepoRefs: ignoreRefs,
	}, activeGrants, s.utcNow(), grantRequest), nil
}

func (s *Server) activeGrantRules(client string) ([]policy.Rule, error) {
	values, err := s.grants.ListForClient(client)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errGrantStoreUnavailable, err)
	}
	out := make([]policy.Rule, 0, len(values))
	for _, grant := range values {
		rule, ok := activeGrantRule(grant)
		if ok {
			out = append(out, rule)
		}
	}
	return out, nil
}

func (s *Server) writeGrantStoreError(w http.ResponseWriter, client, operation, target string) {
	writePlain(w, http.StatusInternalServerError, "hf-broker: could not inspect grants\n")
	s.record(client, operation, target, audit.DecisionRefused, "could not inspect grants", 0)
}

func activeGrantRule(grant grants.Grant) (policy.Rule, bool) {
	if !grantEligibleForRule(grant) {
		return policy.Rule{}, false
	}
	target := targetFromGrant(grant)
	if target.Kind == "" {
		return policy.Rule{}, false
	}
	constraints, err := grantAttrConstraints(grant)
	if err != nil {
		return policy.Rule{}, false
	}
	rule := policy.GeneratedGrantRule(
		grant.ID, grant.Client, policy.Operation(grant.Operation), target, grant.ExpiresAt, grantUsesRemaining(grant),
	)
	rule.Unlimited = grant.MaxUses.IsUnlimited()
	rule.Attrs = constraints
	return rule, true
}

func grantEligibleForRule(grant grants.Grant) bool {
	return grant.Status == grants.StatusActive && !grant.ReservationRetained && runtimeWindowGrant(grant) && hasGrantUses(grant)
}

func grantAttrConstraints(grant grants.Grant) (map[string]policy.AttrConstraint, error) {
	attrs, err := hfgrant.Attrs(grant)
	if err != nil {
		return nil, err
	}
	return policy.AttrConstraintsFromValues(attrs)
}

func routeTarget(rt route, refs []string) policy.Target {
	return policy.Target{
		Kind:  policy.KindRepo,
		Type:  rt.repoType,
		Owner: rt.owner,
		Name:  rt.name,
		Refs:  refs,
	}
}

func (s *Server) handleForward(w http.ResponseWriter, r *http.Request, client string, classified classifiedRequest, target string, decision policy.Decision) {
	s.forwardAndRecord(w, r, client, classified, target, audit.DecisionAllowed, "", decision)
}

func (s *Server) handleForwardWithActiveGrant(w http.ResponseWriter, r *http.Request, client string, classified classifiedRequest, target string, decision policy.Decision, consumeUse bool) bool {
	if policyDenyRefusesGrant(decision) {
		return false
	}
	grant, matched, err := s.matchForwardActiveGrant(r, client, classified, target)
	if err != nil {
		writePlain(w, http.StatusInternalServerError, "hf-broker: could not inspect grants\n")
		s.record(client, string(classified.operation), target, audit.DecisionRefused, "could not inspect grants", 0)
		return true
	}
	if !matched {
		return false
	}
	if !consumeUse {
		s.forwardWithMatchedGrant(w, r, client, classified, target)
		return true
	}
	s.forwardWithReservedGrant(w, r, client, classified, target, grant)
	return true
}

func (s *Server) matchForwardActiveGrant(r *http.Request, client string, classified classifiedRequest, target string) (grants.Grant, bool, error) {
	if lfsUploadRequest(r, classified) {
		return s.matchActiveGrantIgnoringRef(client, classified.operation, target, classified.attrs)
	}
	return s.matchActiveGrant(client, classified.operation, target, "", classified.attrs)
}

func (s *Server) matchActiveGrantIgnoringRef(client string, operation policy.Operation, target string, attrs map[string]any) (grants.Grant, bool, error) {
	clientGrants, err := s.grants.ListForClient(client)
	if err != nil {
		return grants.Grant{}, false, err
	}
	for _, grant := range clientGrants {
		if activeGrantMatchesIgnoringRef(grant, client, operation, target, attrs) {
			return grant, true, nil
		}
	}
	return grants.Grant{}, false, nil
}

func activeGrantMatchesIgnoringRef(grant grants.Grant, client string, operation policy.Operation, target string, attrs map[string]any) bool {
	return grant.Status == grants.StatusActive &&
		!grant.ReservationRetained &&
		runtimeWindowGrant(grant) &&
		grant.Client == client &&
		grant.Operation == string(operation) &&
		hfgrant.Target(grant) == target &&
		hasGrantUses(grant) &&
		grantAttrsMatchIgnoringRef(grant, attrs)
}

func grantAttrsMatchIgnoringRef(grant grants.Grant, attrs map[string]any) bool {
	values, err := hfgrant.Attrs(grant)
	return err == nil && policy.AttrValuesMatch(refLessSupportGrantAttrs(values), attrs)
}

func refLessSupportGrantAttrs(attrs map[string]any) map[string]any {
	if _, ok := attrs["ref_change"]; !ok {
		return attrs
	}
	out := make(map[string]any, len(attrs)-1)
	for key, value := range attrs {
		if key != "ref_change" {
			out[key] = value
		}
	}
	return out
}

func (s *Server) forwardWithMatchedGrant(w http.ResponseWriter, r *http.Request, client string, classified classifiedRequest, target string) {
	s.forwardAndRecord(w, r, client, classified, target, audit.DecisionAllowed, "operator grant discovery", policy.Decision{})
}

func (s *Server) forwardAndRecord(w http.ResponseWriter, r *http.Request, client string, classified classifiedRequest, target, decision, reason string, policyDecision policy.Decision) {
	statusCode, err := s.forward(w, r, classified.route, classified.body, classified.bodyRead)
	if s.recordForwardError(w, client, classified, target, statusCode, err, policyDecision) {
		return
	}
	s.recordPolicyDecision(client, string(classified.operation), target, decision, reason, statusCode, policyDecision)
}

func (s *Server) forwardWithReservedGrant(w http.ResponseWriter, r *http.Request, client string, classified classifiedRequest, target string, grant grants.Grant) {
	if err := s.planValidator.ValidateExecution(grant); err != nil {
		writePlain(w, http.StatusForbidden, "hf-broker: grant plan is invalid\n")
		s.record(client, string(classified.operation), target, audit.DecisionRefused, "grant plan is invalid", 0)
		return
	}
	reserved, err := s.grants.ReserveUse(grant.ID)
	if err != nil {
		writePlain(w, http.StatusForbidden, "hf-broker: grant is not active\n")
		s.record(client, string(classified.operation), target, audit.DecisionRefused, "grant is not active", 0)
		return
	}
	statusCode, err := s.forward(w, r, classified.route, classified.body, classified.bodyRead)
	if errors.Is(err, errInvalidLFSAction) {
		_, _ = s.grants.ReleaseUse(reserved.ID)
	} else if err != nil {
		s.closeForwardGrantReservation(reserved, err)
	}
	if s.recordForwardError(w, client, classified, target, statusCode, err, policy.Decision{}) {
		return
	}
	s.updateGrantMessages(s.commitGrantUses([]grants.Grant{reserved}), s.updateGrantUseMessage)
	s.recordGrantUsed(client, string(classified.operation), target, statusCode, []string{reserved.ID})
}

func (s *Server) recordForwardError(w http.ResponseWriter, client string, classified classifiedRequest, target string, statusCode int, err error, decision policy.Decision) bool {
	if errors.Is(err, errInvalidLFSAction) {
		s.recordPolicyDecision(client, string(classified.operation), target, audit.DecisionRefused, errInvalidLFSAction.Error(), statusCode, decision)
		return true
	}
	if err != nil {
		writePlain(w, http.StatusBadGateway, "hf-broker: upstream request failed\n")
		s.recordPolicyDecision(client, string(classified.operation), target, audit.DecisionRefused, "upstream request failed", statusCode, decision)
		return true
	}
	return false
}

func (s *Server) closeForwardGrantReservation(reserved grants.Grant, err error) {
	if forwardErrorBeforeUpstream(err) {
		_, _ = s.grants.ReleaseUse(reserved.ID)
		return
	}
	s.updateRetainedGrantReservationMessage(reserved)
}

func forwardErrorBeforeUpstream(err error) bool {
	return errors.Is(err, errInvalidLFSAction)
}
