// Package httpapi exposes the broker HTTP surface.
package httpapi

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	bkauthorization "github.com/osolmaz/brokerkit/authorization"
	"github.com/osolmaz/brokerkit/authorization/budget"
	"github.com/osolmaz/brokerkit/authorization/grants"
	corepolicy "github.com/osolmaz/brokerkit/authorization/policy"
	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/gitproxy"
	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/hfgrant"
	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/policy"
	"github.com/osolmaz/brokerkit/telemetry/audit"
	"github.com/osolmaz/brokerkit/transport/http"
)

type apiGrantRequestBody struct {
	Operation       policy.Operation   `json:"operation"`
	Target          policy.Target      `json:"target"`
	Attrs           map[string]any     `json:"attrs"`
	Minutes         int                `json:"minutes"`
	MaxUses         usebudget.Optional `json:"max_uses,omitempty"`
	Reason          string             `json:"reason"`
	ClientRequestID string             `json:"client_request_id"`
}

type apiGrantBody struct {
	ID              string           `json:"id"`
	Status          string           `json:"status"`
	Operation       string           `json:"operation"`
	Target          policy.Target    `json:"target"`
	Attrs           map[string]any   `json:"attrs"`
	Mode            policy.GrantMode `json:"mode"`
	Minutes         int              `json:"minutes"`
	MaxUses         usebudget.Limit  `json:"max_uses"`
	UsesRemaining   int              `json:"uses_remaining"`
	UsedCount       int              `json:"used_count"`
	PendingUntil    *string          `json:"pending_until"`
	ExpiresAt       *string          `json:"expires_at"`
	ClientRequestID string           `json:"client_request_id,omitempty"`
}

type apiRepoBody struct {
	Type  string `json:"type"`
	Owner string `json:"owner"`
	Name  string `json:"name"`
}

type apiRouteHandler func(*Server, http.ResponseWriter, *http.Request, string)

type apiRoute struct {
	method string
	path   string
	prefix string
	handle apiRouteHandler
}

type repoListQuery struct {
	limit       int
	filterType  policy.RepoType
	filterOwner string
}

type pushPolicyCandidate struct {
	operation policy.Operation
	refChange string
}

var apiRoutes = []apiRoute{
	{method: http.MethodPost, path: "/api/grants", handle: (*Server).handleAPIGrantCreate},
	{method: http.MethodPost, prefix: "/api/grants/", handle: (*Server).handleAPIGrantAction},
	{method: http.MethodGet, path: "/api/grants", handle: (*Server).handleAPIGrantList},
	{method: http.MethodGet, prefix: "/api/grants/", handle: (*Server).handleAPIGrantGet},
	{method: http.MethodGet, path: "/api/repos", handle: (*Server).handleAPIRepos},
}

func (s *Server) serveAPI(w http.ResponseWriter, r *http.Request) {
	client, ok := s.authenticateAPI(w, r)
	if !ok {
		return
	}
	if handler := matchingAPIHandler(r); handler != nil {
		handler(s, w, r, client)
		return
	}
	reason := writeAPIUnknownRoute(w, r.URL.Path)
	s.record(client, "api", r.URL.Path, audit.DecisionRefused, reason, 0)
}

func matchingAPIHandler(r *http.Request) apiRouteHandler {
	for _, route := range apiRoutes {
		if route.matches(r) {
			return route.handle
		}
	}
	return nil
}

func (route apiRoute) matches(r *http.Request) bool {
	return route.method == r.Method && route.pathMatches(r.URL.Path)
}

func (route apiRoute) pathMatches(path string) bool {
	if route.path != "" {
		return path == route.path
	}
	return route.prefix != "" && strings.HasPrefix(path, route.prefix)
}

func writeAPIUnknownRoute(w http.ResponseWriter, path string) string {
	if apiKnownPath(path) {
		writeJSendFail(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed")
		return "method_not_allowed"
	}
	writeJSendFail(w, http.StatusNotFound, "not_found", "API route not found")
	return "not_found"
}

func apiKnownPath(path string) bool {
	return path == "/api/grants" || path == "/api/repos" || strings.HasPrefix(path, "/api/grants/")
}

func (s *Server) handleAPIGrantCreate(w http.ResponseWriter, r *http.Request, client string) {
	if !s.requireApprovalChannel(w, client) {
		return
	}
	req, ok := readAPIGrantRequest(w, r)
	if !ok {
		s.record(client, "grant_request", "", audit.DecisionRefused, "could not parse grant request", 0)
		return
	}
	if status, reason, message := validateAPIGrantRequestShape(req); reason != "" {
		writeJSendFail(w, status, reason, message)
		s.record(client, "grant_request", targetNameFromPolicy(req.Target), audit.DecisionRefused, reason, 0)
		return
	}
	grant, _, err := s.requestAPIGrant(client, req)
	if err != nil {
		status, reason, message := grantRequestError(err)
		writeJSendFail(w, status, reason, message)
		s.record(client, "grant_request", targetNameFromPolicy(req.Target), audit.DecisionRefused, reason, 0)
		return
	}
	if s.notifier != nil && grantNeedsNotification(grant) {
		var notified bool
		grant, notified = s.notifyAPIGrantIfClaimed(w, r, client, grant)
		if !notified {
			return
		}
	}
	writeJSendSuccess(w, http.StatusAccepted, map[string]any{"grant": apiGrantFromStore(grant, req.Target)})
	s.record(client, "grant_request", hfgrant.Target(grant), audit.DecisionAllowed, "pending", 0)
}

func (s *Server) requireApprovalChannel(w http.ResponseWriter, client string) bool {
	if s.hasApprovalChannel() {
		return true
	}
	writeJSendError(w, http.StatusServiceUnavailable, "approval channel is not configured", "approval_channel_not_configured")
	s.record(client, "grant_request", "", audit.DecisionRefused, "approval channel is not configured", 0)
	return false
}

func (s *Server) hasApprovalChannel() bool {
	return s.notifier != nil || s.operatorConfigured
}

func readAPIGrantRequest(w http.ResponseWriter, r *http.Request) (apiGrantRequestBody, bool) {
	var req apiGrantRequestBody
	err := httpx.DecodeJSON(r.Body, 4096, &req, true)
	if errors.Is(err, httpx.ErrBodyTooLarge) {
		writeJSendFail(w, http.StatusRequestEntityTooLarge, "request_too_large", "Grant request is too large")
		return apiGrantRequestBody{}, false
	}
	if err != nil {
		writeJSendFail(w, http.StatusBadRequest, "malformed_json", "Could not parse grant request")
		return apiGrantRequestBody{}, false
	}
	return req, true
}

func validateGrantTargetForOperation(operation policy.Operation, target policy.Target) error {
	if err := policy.ValidateGrantRequest(policy.Request{Operation: operation, Target: target}); err != nil {
		return err
	}
	return validateGrantTargetRefForOperation(operation, target)
}

func validateGrantTargetRefForOperation(operation policy.Operation, target policy.Target) error {
	ref, err := grantRefFromTarget(target)
	if err != nil {
		return err
	}
	if operationNeedsRef(operation) {
		if ref == "" {
			return errors.New("grant target must include exactly one ref")
		}
		if !gitproxy.ValidRefName(ref) || !grantRefMatchesOperation(operation, ref) {
			return errors.New("grant target ref is invalid for operation")
		}
	} else if ref != "" && !policy.OperationUsesRefs(operation) {
		return errors.New("grant target refs are not supported for operation")
	}
	return nil
}

func operationNeedsRef(operation policy.Operation) bool {
	switch operation {
	case policy.OpGitPushAppend, policy.OpGitPushForce, policy.OpGitRefDelete, policy.OpGitTagUpdate:
		return true
	default:
		return false
	}
}

func grantRefFromTarget(target policy.Target) (string, error) {
	if len(target.Refs) > 1 {
		return "", errors.New("grant target must include at most one ref")
	}
	if len(target.Refs) == 0 {
		return "", nil
	}
	return target.Refs[0], nil
}

func (s *Server) requestAPIGrant(client string, req apiGrantRequestBody) (grants.Grant, bool, error) {
	providerRequest := policy.Request{Client: client, Operation: req.Operation, Target: req.Target, Attrs: req.Attrs}
	authorizationRequest := policy.AuthorizationRequest(providerRequest)
	result, err := s.authorization.RequestApproval(authorizationRequest, func(decision corepolicy.Decision) (bkauthorization.GrantIntent, error) {
		return s.prepareAPIGrantIntent(client, req, authorizationRequest, decision.GrantPolicy)
	})
	return result.Request.Grant, result.Created, err
}

func (s *Server) prepareAPIGrantIntent(client string, req apiGrantRequestBody, authorizationRequest corepolicy.Request, bounds *corepolicy.GrantPolicy) (bkauthorization.GrantIntent, error) {
	if bounds == nil {
		return bkauthorization.GrantIntent{}, errors.New("no policy rule allows requesting this operation")
	}
	minutes, maxUses, err := resolveAPIGrantBounds(req, bounds)
	if err != nil {
		return bkauthorization.GrantIntent{}, err
	}
	request, plan, err := hfgrant.Prepare(s.grants, s.plans, hfgrant.Input{
		Client:            client,
		ClientRequestID:   req.ClientRequestID,
		Operation:         string(req.Operation),
		Mode:              bounds.Mode,
		PolicyTarget:      &req.Target,
		Attrs:             req.Attrs,
		Reason:            req.Reason,
		RequestedDuration: time.Duration(minutes) * time.Minute,
		PendingTimeout:    time.Duration(bounds.RequestTTLMinutes) * time.Minute,
		MaxUses:           int(maxUses),
		MaxUsesSpecified:  req.MaxUses.Specified,
	})
	if err != nil {
		return bkauthorization.GrantIntent{}, err
	}
	return bkauthorization.GrantIntent{
		Mode: corepolicy.GrantMode(bounds.Mode), Authorization: authorizationRequest, Request: request, Plan: plan,
	}, nil
}

func resolveAPIGrantBounds(req apiGrantRequestBody, bounds *corepolicy.GrantPolicy) (int, usebudget.Limit, error) {
	minutes, err := resolveAPIGrantDuration(req.Minutes, bounds)
	if err != nil {
		return 0, 0, err
	}
	maxUses, err := resolveAPIGrantUses(req.MaxUses, bounds)
	return minutes, maxUses, err
}

func resolveAPIGrantDuration(requested int, bounds *corepolicy.GrantPolicy) (int, error) {
	if requested > bounds.MaxMinutes {
		return 0, fmt.Errorf("grant duration exceeds %d minutes", bounds.MaxMinutes)
	}
	if requested == 0 {
		return bounds.DefaultMinutes, nil
	}
	return requested, nil
}

func resolveAPIGrantUses(requested usebudget.Optional, bounds *corepolicy.GrantPolicy) (usebudget.Limit, error) {
	maxUses := requested.Limit
	if !requested.Specified {
		maxUses = bounds.DefaultMaxUses
	}
	return maxUses, validateAPIGrantUses(maxUses, bounds)
}

func validateAPIGrantUses(maxUses usebudget.Limit, bounds *corepolicy.GrantPolicy) error {
	if maxUses < 0 || (bounds.MaxUses.IsFinite() && (maxUses.IsUnlimited() || maxUses > bounds.MaxUses)) {
		return errors.New("grant max uses exceeds policy bounds")
	}
	if corepolicy.GrantMode(bounds.Mode) == corepolicy.GrantModeExecution && maxUses != 1 {
		return errors.New("execution approvals must have exactly one use")
	}
	return nil
}

func grantRequestError(err error) (int, string, string) {
	if errors.Is(err, grants.ErrIdempotencyConflict) {
		return http.StatusConflict, "idempotency_conflict", "Idempotency key was reused with a different request"
	}
	if errors.Is(err, grants.ErrCapacity) {
		return http.StatusTooManyRequests, "pending_approval_limit", "Pending approval limit reached"
	}
	if errors.Is(err, bkauthorization.ErrDenied) || errors.Is(err, bkauthorization.ErrNoMatch) {
		return http.StatusForbidden, "not_requestable", "No policy rule allows requesting this operation"
	}
	return http.StatusBadRequest, "validation_failed", err.Error()
}

func (s *Server) handleAPIGrantList(w http.ResponseWriter, r *http.Request, client string) {
	statusFilter, ok := parseGrantStatusFilter(r)
	if !ok {
		writeJSendFail(w, http.StatusBadRequest, "validation_failed", "Invalid grant status filter")
		s.record(client, "grant_list", "grants", audit.DecisionRefused, "validation_failed", 0)
		return
	}
	grantsForClient, err := s.grants.ListForClient(client)
	if err != nil {
		writeJSendError(w, http.StatusInternalServerError, "could not list grants", "internal_error")
		s.record(client, "grant_list", "grants", audit.DecisionRefused, "could not list grants", 0)
		return
	}
	out := apiGrantListFromStore(grantsForClient, statusFilter)
	writeJSendSuccess(w, http.StatusOK, map[string]any{"grants": out, "next_cursor": nil})
	s.record(client, "grant_list", "grants", audit.DecisionAllowed, "", 0)
}

func parseGrantStatusFilter(r *http.Request) (string, bool) {
	statusFilter := r.URL.Query().Get("status")
	return statusFilter, statusFilter == "" || validGrantStatusFilter(statusFilter)
}

func apiGrantListFromStore(grantsForClient []grants.Grant, statusFilter string) []apiGrantBody {
	out := make([]apiGrantBody, 0, len(grantsForClient))
	for _, grant := range grantsForClient {
		if grantStatusMatchesFilter(grant, statusFilter) {
			out = append(out, apiGrantFromStore(grant, targetFromGrant(grant)))
		}
	}
	return out
}

func (s *Server) notifyAPIGrantIfClaimed(w http.ResponseWriter, r *http.Request, client string, grant grants.Grant) (grants.Grant, bool) {
	claim, claimed, err := s.grants.ClaimNotification(grant.ID, grantNotificationClaimLease)
	if err != nil {
		writeJSendError(w, http.StatusBadGateway, "could not claim operator notification", "internal_error")
		s.record(client, "grant_request", hfgrant.Target(grant), audit.DecisionRefused, "could not claim operator notification", 0)
		return grants.Grant{}, false
	}
	if !claimed {
		return s.waitForAPIGrantNotificationResponse(w, r, client, grant, grant.ID)
	}
	return s.notifyAPICreatedGrant(w, r, client, claim)
}

func (s *Server) cancelAPIGrantNotificationIfClaimed(w http.ResponseWriter, r *http.Request, client string, grant grants.Grant, reason string) (grants.Grant, bool) {
	updated, canceled, err := s.grants.CancelIfNotificationClaimed(grant.ID, grant.NotificationClaimedAt)
	if err != nil {
		writeJSendError(w, http.StatusBadGateway, reason, "internal_error")
		s.record(client, "grant_request", hfgrant.Target(grant), audit.DecisionRefused, reason, 0)
		return grants.Grant{}, false
	}
	if canceled || updated.Status == grants.StatusCanceled {
		writeJSendError(w, http.StatusBadGateway, reason, "upstream_error")
		s.record(client, "grant_request", hfgrant.Target(grant), audit.DecisionRefused, reason, 0)
		return grants.Grant{}, false
	}
	return s.resolveAPIPendingGrantNotification(w, r, client, grant, updated)
}

func (s *Server) retainAPIGrantNotificationIfClaimed(w http.ResponseWriter, r *http.Request, client string, grant grants.Grant, reason string) (grants.Grant, bool) {
	updated, retained, err := s.grants.RetainNotificationClaim(grant.ID, grant.NotificationClaimedAt)
	if err != nil {
		writeJSendError(w, http.StatusBadGateway, reason, "internal_error")
		s.record(client, "grant_request", hfgrant.Target(grant), audit.DecisionRefused, reason, 0)
		return grants.Grant{}, false
	}
	if retained || updated.NotificationDeliveryUnresolved {
		writeJSendError(w, http.StatusBadGateway, reason, "upstream_error")
		s.record(client, "grant_request", hfgrant.Target(grant), audit.DecisionRefused, reason, 0)
		return grants.Grant{}, false
	}
	return s.resolveAPIPendingGrantNotification(w, r, client, grant, updated)
}

func (s *Server) resolveAPIPendingGrantNotification(w http.ResponseWriter, r *http.Request, client string, original, current grants.Grant) (grants.Grant, bool) {
	if !grantNeedsNotification(current) {
		return current, true
	}
	return s.waitForAPIGrantNotificationResponse(w, r, client, original, original.ID)
}

func (s *Server) waitForAPIGrantNotificationResponse(w http.ResponseWriter, r *http.Request, client string, grant grants.Grant, id string) (grants.Grant, bool) {
	current, err := s.waitForGrantNotification(r.Context(), id)
	if err != nil {
		status, message, code := apiGrantNotificationWaitError(err)
		writeJSendError(w, status, message, code)
		s.record(client, "grant_request", hfgrant.Target(grant), audit.DecisionRefused, message, 0)
		return grants.Grant{}, false
	}
	return current, true
}

func apiGrantNotificationWaitError(err error) (int, string, string) {
	if errors.Is(err, errGrantNotificationCanceled) || errors.Is(err, errGrantNotificationUnresolved) {
		return http.StatusBadGateway, "could not notify operator", "upstream_error"
	}
	if errors.Is(err, errGrantNotificationStillQueued) {
		return http.StatusBadGateway, "operator notification is still pending", "internal_error"
	}
	return http.StatusBadGateway, "could not confirm operator notification", "internal_error"
}

func (s *Server) handleAPIGrantGet(w http.ResponseWriter, r *http.Request, client string) {
	id := strings.TrimPrefix(r.URL.Path, "/api/grants/")
	if id == "" || strings.Contains(id, "/") {
		writeJSendFail(w, http.StatusNotFound, "grant_not_found", "Grant not found")
		s.record(client, "grant_read", "grant", audit.DecisionRefused, "grant_not_found", 0)
		return
	}
	grant, err := hfgrant.GetForClient(s.grants, client, id)
	if err != nil {
		writeJSendFail(w, http.StatusNotFound, "grant_not_found", "Grant not found")
		s.record(client, "grant_read", id, audit.DecisionRefused, "grant_not_found", 0)
		return
	}
	writeJSendSuccess(w, http.StatusOK, map[string]any{"grant": apiGrantFromStore(grant, targetFromGrant(grant))})
	s.record(client, "grant_read", id, audit.DecisionAllowed, "", 0)
}

func (s *Server) handleAPIGrantAction(w http.ResponseWriter, r *http.Request, client string) {
	id, action, ok := parseAPIGrantAction(r.URL.Path)
	if !ok {
		writeJSendFail(w, http.StatusNotFound, "grant_not_found", "Grant not found")
		return
	}
	var body struct{}
	if err := httpx.DecodeJSON(r.Body, 1024, &body, true); err != nil {
		writeJSendFail(w, http.StatusBadRequest, "validation_failed", "Invalid grant action")
		return
	}
	updated, err := s.applyAPIGrantAction(id, client, action)
	if err != nil {
		s.writeAPIGrantActionError(w, client, id, action, err)
		return
	}
	writeJSendSuccess(w, http.StatusOK, map[string]any{"grant": apiGrantFromStore(updated, targetFromGrant(updated))})
	s.record(client, "grant_"+action, id, audit.DecisionAllowed, "", 0)
}

func (s *Server) writeAPIGrantActionError(w http.ResponseWriter, client, id, action string, err error) {
	if errors.Is(err, grants.ErrNotFound) {
		writeJSendFail(w, http.StatusNotFound, "grant_not_found", "Grant not found")
		return
	}
	if errors.Is(err, grants.ErrNotPending) || errors.Is(err, grants.ErrNotActive) {
		writeJSendFail(w, http.StatusConflict, "invalid_grant_state", "Grant action is not valid for its current state")
		s.record(client, "grant_"+action, id, audit.DecisionRefused, "invalid_grant_state", 0)
		return
	}
	writeJSendError(w, http.StatusInternalServerError, "could not update grant", "internal_error")
	s.record(client, "grant_"+action, id, audit.DecisionRefused, "internal_error", 0)
}

func parseAPIGrantAction(value string) (string, string, bool) {
	tail := strings.TrimPrefix(value, "/api/grants/")
	id, action, ok := strings.Cut(tail, "/")
	return id, action, ok && id != "" && !strings.Contains(action, "/") && (action == "cancel" || action == "revoke")
}

func (s *Server) applyAPIGrantAction(id, client, action string) (grants.Grant, error) {
	if action == "cancel" {
		return s.grants.CancelForClient(id, client)
	}
	return s.grants.RevokeForClient(id, client)
}
