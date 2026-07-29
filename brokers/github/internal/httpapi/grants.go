package httpapi

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/osolmaz/unyolo/approval/notification"
	"github.com/osolmaz/unyolo/approval/notifier"
	"github.com/osolmaz/unyolo/authorization/budget"
	"github.com/osolmaz/unyolo/authorization/grants"
	corepolicy "github.com/osolmaz/unyolo/authorization/policy"
	ghapproval "github.com/osolmaz/unyolo/brokers/github/internal/approval"
	"github.com/osolmaz/unyolo/brokers/github/internal/ghplan"
	"github.com/osolmaz/unyolo/brokers/github/internal/policy"
	"github.com/osolmaz/unyolo/brokers/github/internal/security"
	"github.com/osolmaz/unyolo/transport/http"
)

const maxGrantRequestBodyBytes int64 = 32 * 1024

const (
	grantNotificationClaimLease = 2 * time.Minute
	grantNotificationWait       = 10 * time.Second
	grantNotificationPoll       = 50 * time.Millisecond
)

type grantCreateRequest struct {
	ClientRequestID string            `json:"client_request_id"`
	Operation       policy.Operation  `json:"operation"`
	Target          policy.Target     `json:"target"`
	Attrs           map[string]string `json:"attrs"`
	Reason          string            `json:"reason"`
	Minutes         int               `json:"minutes"`
	MaxUses         int               `json:"max_uses"`
}

type grantCreatePlan struct {
	payload        grantCreateRequest
	request        policy.Request
	decision       policy.Decision
	duration       time.Duration
	pendingTimeout time.Duration
	maxUses        usebudget.Limit
}

type apiGrant struct {
	ID              string            `json:"id"`
	Status          string            `json:"status"`
	Operation       string            `json:"operation"`
	Target          policy.Target     `json:"target"`
	Attrs           map[string]string `json:"attrs,omitempty"`
	Reason          string            `json:"reason,omitempty"`
	Minutes         int               `json:"minutes"`
	MaxUses         int               `json:"max_uses"`
	UsesRemaining   int               `json:"uses_remaining"`
	UsedCount       int               `json:"used_count"`
	PendingUntil    *time.Time        `json:"pending_until,omitempty"`
	ExpiresAt       *time.Time        `json:"expires_at,omitempty"`
	ClientRequestID string            `json:"client_request_id,omitempty"`
}

func (s *Server) createGrant(c echo.Context) error {
	plan, err := s.planGrantCreate(c)
	if err != nil {
		return err
	}
	result, created, err := s.requestGrant(plan.storeRequest())
	if err != nil {
		return grantStoreHTTPError(err)
	}
	stored, ref, err := s.notifyPendingGrant(c, plan, result.Grant.ID)
	if err != nil {
		return err
	}
	s.audit(c, plan.request, "requires_grant", "operator approval requested", 0, plan.decision.MatchedRuleIDs)
	return c.JSON(grantCreateStatus(created), map[string]any{"grant": apiGrantFromStore(stored), "notification": apiNotification(ref)})
}

func (s *Server) requestGrant(request grants.Request) (grants.RequestResult, bool, error) {
	createdAt, exists, err := existingGitHubPlanCreatedAt(s.grants, s.plans, request.Client, request.ClientRequestID)
	if err != nil {
		return grants.RequestResult{}, false, err
	}
	var plan grants.ImmutablePlan
	if exists {
		plan, err = s.plans.PrepareBindAt(&request, createdAt)
	} else {
		plan, err = s.plans.PrepareBind(&request)
	}
	if err != nil {
		return grants.RequestResult{}, false, fmt.Errorf("store immutable GitHub plan: %w", err)
	}
	return s.grants.RequestWithPlan(request, plan)
}

func existingGitHubPlanCreatedAt(store *grants.Store, plans *ghplan.Store, client string, clientRequestID string) (time.Time, bool, error) {
	items, err := store.ListForClient(client)
	if err != nil {
		return time.Time{}, false, err
	}
	for _, grant := range items {
		if grant.ClientRequestID != clientRequestID || grant.Status == grants.StatusCanceled {
			continue
		}
		plan, err := plans.Get(grant.Metadata[ghplan.MetadataDigest])
		if err != nil {
			return time.Time{}, false, err
		}
		return plan.CreatedAt, true, nil
	}
	return time.Time{}, false, nil
}

func (s *Server) planGrantCreate(c echo.Context) (grantCreatePlan, error) {
	payload, err := decodeGrantCreate(c)
	if err != nil {
		return grantCreatePlan{}, err
	}
	if err := s.validateGrantCreateChannelAndOperation(payload); err != nil {
		return grantCreatePlan{}, err
	}
	request := grantPolicyRequest(c, payload)
	decision, err := s.requestableGrantDecision(c, request)
	if err != nil {
		return grantCreatePlan{}, err
	}
	duration, pendingTimeout, maxUses, err := grantBounds(decision.GrantPolicy, payload.Minutes, payload.MaxUses)
	if err != nil {
		return grantCreatePlan{}, echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}
	return grantCreatePlan{payload: payload, request: request, decision: decision, duration: duration, pendingTimeout: pendingTimeout, maxUses: maxUses}, nil
}

func (s *Server) validateGrantCreateChannelAndOperation(payload grantCreateRequest) error {
	if s.notifier == nil && !s.operatorConfigured {
		return echo.NewHTTPError(http.StatusServiceUnavailable, "approval channel is not configured")
	}
	if !protocolGrantOperation(payload.Operation) {
		return echo.NewHTTPError(http.StatusBadRequest, "Agent V1 is required for non-protocol operations")
	}
	return nil
}

func (s *Server) requestableGrantDecision(c echo.Context, request policy.Request) (policy.Decision, error) {
	decision := s.policy.EvaluateGrantRequest(request)
	if decision.Effect == policy.EffectRequest && decision.GrantPolicy != nil {
		return decision, nil
	}
	s.audit(c, request, outcomeForDecision(decision), decision.Reason, 0, decision.MatchedRuleIDs)
	return policy.Decision{}, echo.NewHTTPError(http.StatusForbidden, "operation is not requestable")
}

func protocolGrantOperation(operation policy.Operation) bool {
	switch operation {
	case policy.OperationGitPushBranchCreate, policy.OperationGitPushFastForward, policy.OperationGitPushForce,
		policy.OperationGitRefDelete, policy.OperationGitTagUpdate:
		return true
	default:
		return false
	}
}

func grantPolicyRequest(c echo.Context, payload grantCreateRequest) policy.Request {
	return policy.Request{
		Client:    security.ClientFromContext(c),
		Operation: payload.Operation,
		Target:    payload.Target,
		Attrs:     payload.Attrs,
	}
}

func (p grantCreatePlan) storeRequest() grants.Request {
	mode := ""
	if p.decision.GrantPolicy != nil {
		mode = p.decision.GrantPolicy.Mode
	}
	return grants.Request{
		Client:          p.request.Client,
		ClientRequestID: p.payload.ClientRequestID,
		Operation:       string(p.request.Operation),
		Target:          policy.CoreTarget(p.request.Target),
		Attrs:           corepolicy.SingletonValues(p.request.Attrs),
		Metadata:        map[string]string{grants.MetadataMode: mode},
		Reason:          strings.TrimSpace(p.payload.Reason),
		Duration:        p.duration,
		PendingTimeout:  p.pendingTimeout,
		MaxUses:         p.maxUses,
	}
}

func (s *Server) notifyPendingGrant(c echo.Context, plan grantCreatePlan, id string) (grants.Grant, notify.MessageRef, error) {
	existing, err := s.grants.Get(id)
	if err != nil {
		return grants.Grant{}, notify.MessageRef{}, echo.NewHTTPError(http.StatusBadGateway, "could not inspect operator notification")
	}
	if existing.Notification != nil {
		return existing, *existing.Notification, nil
	}
	if existing.Status != grants.StatusPending {
		return existing, notify.MessageRef{}, nil
	}
	if s.notifier == nil {
		return existing, notify.MessageRef{}, nil
	}
	return s.claimAndSendGrantNotification(c, plan, id)
}

func (s *Server) claimAndSendGrantNotification(c echo.Context, plan grantCreatePlan, id string) (grants.Grant, notify.MessageRef, error) {
	claim, claimed, err := s.grants.ClaimNotification(id, grantNotificationClaimLease)
	if err != nil {
		return grants.Grant{}, notify.MessageRef{}, echo.NewHTTPError(http.StatusBadGateway, "could not claim operator notification")
	}
	if !claimed {
		return s.waitForGrantNotification(c.Request().Context(), id)
	}
	ref, err := s.notifier.SendApproval(c.Request().Context(), grantApprovalMessage(c.Request().Context(), claim.Grant, claim.DecisionToken))
	if err != nil {
		s.audit(c, plan.request, "error", "could not notify operator", 0, plan.decision.MatchedRuleIDs)
		if s.operatorConfigured {
			return s.keepGrantInOperatorInbox(id, claim.Grant.NotificationClaimedAt, "could not notify operator")
		}
		return failNotificationClaim(s.grants.RetainNotificationClaim, id, claim.Grant.NotificationClaimedAt, "could not notify operator")
	}
	return s.recordGrantNotification(c.Request().Context(), id, claim, ref)
}

func (s *Server) recordGrantNotification(ctx context.Context, id string, claim grants.NotificationClaim, ref notify.MessageRef) (grants.Grant, notify.MessageRef, error) {
	if ref.MessageID <= 0 {
		return s.handleNotificationRecordFailure(id, claim.Grant.NotificationClaimedAt, true)
	}
	stored, recorded, err := s.grants.SetNotificationIfClaimed(id, claim.Grant.NotificationClaimedAt, ref)
	if err != nil {
		return s.handleNotificationRecordFailure(id, claim.Grant.NotificationClaimedAt, false)
	}
	if recorded {
		return stored, ref, nil
	}
	if shouldSupersedeNotification(stored.Notification, ref) {
		_ = s.notifier.UpdateStatus(ctx, ref, notify.Status{Kind: notify.StatusSuperseded})
	}
	return s.waitForGrantNotification(ctx, id)
}

func (s *Server) handleNotificationRecordFailure(id string, claimedAt time.Time, cancel bool) (grants.Grant, notify.MessageRef, error) {
	const message = "could not record operator notification"
	if s.operatorConfigured {
		return s.keepGrantInOperatorInbox(id, claimedAt, message)
	}
	if cancel {
		return failNotificationClaim(s.grants.CancelIfNotificationClaimed, id, claimedAt, message)
	}
	return failNotificationClaim(s.grants.RetainNotificationClaim, id, claimedAt, message)
}

func (s *Server) keepGrantInOperatorInbox(id string, claimedAt time.Time, message string) (grants.Grant, notify.MessageRef, error) {
	stored, _, err := s.grants.RetainNotificationClaim(id, claimedAt)
	if err != nil {
		return grants.Grant{}, notify.MessageRef{}, echo.NewHTTPError(http.StatusBadGateway, message)
	}
	return stored, notify.MessageRef{}, nil
}

func failNotificationClaim(
	action func(string, time.Time) (grants.Grant, bool, error),
	id string,
	claimedAt time.Time,
	message string,
) (grants.Grant, notify.MessageRef, error) {
	_, _, _ = action(id, claimedAt)
	return grants.Grant{}, notify.MessageRef{}, echo.NewHTTPError(http.StatusBadGateway, message)
}

func (s *Server) waitForGrantNotification(ctx context.Context, id string) (grants.Grant, notify.MessageRef, error) {
	return s.waitForGrantNotificationFor(ctx, id, grantNotificationWait, grantNotificationPoll)
}

func (s *Server) waitForGrantNotificationFor(ctx context.Context, id string, wait time.Duration, poll time.Duration) (grants.Grant, notify.MessageRef, error) {
	waitCtx, cancel := context.WithTimeout(ctx, wait)
	defer cancel()
	ticker := time.NewTicker(poll)
	defer ticker.Stop()
	for {
		grant, err := s.grants.Get(id)
		if err != nil {
			return grants.Grant{}, notify.MessageRef{}, echo.NewHTTPError(http.StatusBadGateway, "could not confirm operator notification")
		}
		if grant.Notification != nil {
			return grant, *grant.Notification, nil
		}
		if grant.NotificationDeliveryUnresolved {
			return grants.Grant{}, notify.MessageRef{}, echo.NewHTTPError(http.StatusBadGateway, "operator notification delivery is unresolved")
		}
		if grant.Status != grants.StatusPending {
			return grant, notify.MessageRef{}, nil
		}
		select {
		case <-waitCtx.Done():
			return grants.Grant{}, notify.MessageRef{}, echo.NewHTTPError(http.StatusBadGateway, "operator notification is still pending")
		case <-ticker.C:
		}
	}
}

func grantCreateStatus(created bool) int {
	if created {
		return http.StatusCreated
	}
	return http.StatusOK
}

func (s *Server) listGrants(c echo.Context) error {
	client := security.ClientFromContext(c)
	stored, err := s.grants.ListForClient(client)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "could not list grants")
	}
	api := make([]apiGrant, 0, len(stored))
	for _, grant := range stored {
		api = append(api, apiGrantFromStore(grant))
	}
	return c.JSON(http.StatusOK, map[string]any{"grants": api})
}

func (s *Server) getGrant(c echo.Context) error {
	grant, err := s.grants.Get(c.Param("id"))
	if err != nil || grant.Client != security.ClientFromContext(c) {
		return echo.NewHTTPError(http.StatusNotFound, "grant not found")
	}
	return c.JSON(http.StatusOK, map[string]any{"grant": apiGrantFromStore(grant)})
}

func decodeGrantCreate(c echo.Context) (grantCreateRequest, error) {
	var payload grantCreateRequest
	if err := httpx.DecodeJSON(c.Request().Body, maxGrantRequestBodyBytes, &payload, true); err != nil {
		if errors.Is(err, httpx.ErrBodyTooLarge) {
			return grantCreateRequest{}, echo.NewHTTPError(http.StatusRequestEntityTooLarge, "grant request body is too large")
		}
		return grantCreateRequest{}, echo.NewHTTPError(http.StatusBadRequest, "invalid grant request json")
	}
	if strings.TrimSpace(payload.Reason) == "" {
		return grantCreateRequest{}, echo.NewHTTPError(http.StatusBadRequest, "reason is required")
	}
	if err := validateClientRequestID(payload.ClientRequestID); err != nil {
		return grantCreateRequest{}, echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}
	return payload, nil
}

func grantBounds(grantPolicy *corepolicy.GrantPolicy, requestedMinutes int, requestedUses int) (time.Duration, time.Duration, usebudget.Limit, error) {
	minutes := requestedMinutes
	if minutes <= 0 {
		minutes = grantPolicy.DefaultMinutes
	}
	if minutes > grantPolicy.MaxMinutes {
		return 0, 0, 0, fmt.Errorf("requested minutes %d exceeds policy max %d", minutes, grantPolicy.MaxMinutes)
	}
	maxUses := usebudget.Limit(requestedUses)
	if maxUses <= 0 {
		maxUses = grantPolicy.DefaultMaxUses
	}
	if grantPolicy.MaxUses.IsFinite() && maxUses > grantPolicy.MaxUses {
		return 0, 0, 0, fmt.Errorf("requested max uses %d exceeds policy max %d", maxUses, grantPolicy.MaxUses)
	}
	return time.Duration(minutes) * time.Minute, time.Duration(grantPolicy.RequestTTLMinutes) * time.Minute, maxUses, nil
}

func grantStoreHTTPError(err error) error {
	if errors.Is(err, grants.ErrIdempotencyConflict) {
		return echo.NewHTTPError(http.StatusConflict, "idempotency conflict")
	}
	if errors.Is(err, grants.ErrCapacity) {
		return echo.NewHTTPError(http.StatusTooManyRequests, "pending approval limit reached")
	}
	return echo.NewHTTPError(http.StatusBadRequest, err.Error())
}

func apiGrantFromStore(grant grants.Grant) apiGrant {
	return apiGrant{
		ID:              grant.ID,
		Status:          apiGrantStatus(grant),
		Operation:       grant.Operation,
		Target:          apiTarget(grant.Target),
		Attrs:           flattenCoreValues(grant.Attrs),
		Reason:          grant.Reason,
		Minutes:         int(grant.Duration / time.Minute),
		MaxUses:         int(grant.MaxUses),
		UsesRemaining:   grantUsesRemaining(grant),
		UsedCount:       grant.UsedCount,
		PendingUntil:    timePointer(grant.PendingExpiresAt),
		ExpiresAt:       timePointer(grant.ExpiresAt),
		ClientRequestID: grant.ClientRequestID,
	}
}

func timePointer(value time.Time) *time.Time {
	if value.IsZero() {
		return nil
	}
	utc := value.UTC()
	return &utc
}

func apiTarget(target corepolicy.Target) policy.Target {
	return policy.Target{
		Kind:  target.Kind,
		Owner: corepolicy.FirstValue(target.Fields["owner"]),
		Name:  corepolicy.FirstValue(target.Fields["name"]),
	}
}

func apiNotification(ref notify.MessageRef) map[string]any {
	if ref.Kind == "" {
		return nil
	}
	return map[string]any{"kind": ref.Kind, "chat_id": ref.ChatID, "message_id": ref.MessageID}
}

func grantApprovalMessage(ctx context.Context, grant grants.Grant, decisionToken string) approvalnotify.Approval {
	return approvalnotify.Project(ctx, "GitHub", ghapproval.Presenter{}, grant, decisionToken)
}

func flattenCoreValues(values map[string][]string) map[string]string {
	if len(values) == 0 {
		return nil
	}
	out := make(map[string]string, len(values))
	for key, value := range values {
		out[key] = strings.Join(value, ",")
	}
	return out
}
