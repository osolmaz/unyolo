package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/osolmaz/brokerkit/grants"
	"github.com/osolmaz/brokerkit/httpx"
	"github.com/osolmaz/brokerkit/notify"
	corepolicy "github.com/osolmaz/brokerkit/policy"
	"github.com/osolmaz/gh-broker/internal/policy"
	"github.com/osolmaz/gh-broker/internal/security"
)

const maxGrantRequestBodyBytes int64 = 32 * 1024

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
	maxUses        int
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
	result, created, err := s.grants.Request(plan.storeRequest())
	if err != nil {
		return grantStoreHTTPError(err)
	}
	ref, err := s.notifyPendingGrant(c, plan, result)
	if err != nil {
		return err
	}
	s.audit(c, plan.request, "requires_grant", "operator approval requested", 0, plan.decision.MatchedRuleIDs)
	return c.JSON(grantCreateStatus(created), map[string]any{"grant": apiGrantFromStore(result.Grant), "notification": apiNotification(ref)})
}

func (s *Server) planGrantCreate(c echo.Context) (grantCreatePlan, error) {
	if s.notifier == nil {
		return grantCreatePlan{}, echo.NewHTTPError(http.StatusServiceUnavailable, "approval channel is not configured")
	}
	payload, err := decodeGrantCreate(c)
	if err != nil {
		return grantCreatePlan{}, err
	}
	request := grantPolicyRequest(c, payload)
	decision := s.policy.EvaluateGrantRequest(request)
	if decision.Effect != policy.EffectRequest || decision.GrantPolicy == nil {
		s.audit(c, request, outcomeForDecision(decision), decision.Reason, 0, decision.MatchedRuleIDs)
		return grantCreatePlan{}, echo.NewHTTPError(http.StatusForbidden, "operation is not requestable")
	}
	duration, pendingTimeout, maxUses, err := grantBounds(decision.GrantPolicy, payload.Minutes, payload.MaxUses)
	if err != nil {
		return grantCreatePlan{}, echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}
	return grantCreatePlan{payload: payload, request: request, decision: decision, duration: duration, pendingTimeout: pendingTimeout, maxUses: maxUses}, nil
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
	return grants.Request{
		Client:          p.request.Client,
		ClientRequestID: p.payload.ClientRequestID,
		Operation:       string(p.request.Operation),
		Target:          policy.CoreTarget(p.request.Target),
		Attrs:           p.request.Attrs,
		Reason:          strings.TrimSpace(p.payload.Reason),
		Duration:        p.duration,
		PendingTimeout:  p.pendingTimeout,
		MaxUses:         p.maxUses,
	}
}

func (s *Server) notifyPendingGrant(c echo.Context, plan grantCreatePlan, result grants.RequestResult) (notify.MessageRef, error) {
	if result.DecisionToken == "" {
		return notify.MessageRef{}, nil
	}
	ref, err := s.notifier.SendApproval(c.Request().Context(), grantApprovalMessage(result.Grant, result.DecisionToken))
	if err != nil {
		s.audit(c, plan.request, "error", "could not notify operator", 0, plan.decision.MatchedRuleIDs)
		return notify.MessageRef{}, echo.NewHTTPError(http.StatusBadGateway, "could not notify operator")
	}
	return ref, nil
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

func (s *Server) handleTelegramDecision(_ context.Context, decision notify.Decision) notify.DecisionResult {
	actor := telegramActor(decision)
	switch decision.Action {
	case notify.ActionApprove:
		return s.approveTelegramGrant(decision, actor)
	case notify.ActionDeny:
		return s.denyTelegramGrant(decision, actor)
	default:
		return notify.DecisionResult{Answer: "Grant decision ignored"}
	}
}

func (s *Server) approveTelegramGrant(decision notify.Decision, actor string) notify.DecisionResult {
	grant, err := s.grants.Approve(decision.GrantID, decision.DecisionToken, actor)
	if err != nil {
		return notify.DecisionResult{Answer: grantDecisionAnswer(err)}
	}
	return notify.DecisionResult{
		Answer:          "Grant approved",
		Status:          "Approved. Access is active.",
		ActiveExpiresAt: grant.ExpiresAt,
	}
}

func (s *Server) denyTelegramGrant(decision notify.Decision, actor string) notify.DecisionResult {
	if _, err := s.grants.Deny(decision.GrantID, decision.DecisionToken, actor); err != nil {
		return notify.DecisionResult{Answer: grantDecisionAnswer(err)}
	}
	return notify.DecisionResult{Answer: "Grant denied", Status: "Denied. Access was not granted."}
}

func telegramActor(decision notify.Decision) string {
	if decision.OperatorTag != "" {
		return "telegram:@" + decision.OperatorTag
	}
	if decision.OperatorID != 0 {
		return fmt.Sprintf("telegram:%d", decision.OperatorID)
	}
	if decision.Approver != "" {
		return decision.Approver
	}
	return "telegram"
}

func grantDecisionAnswer(err error) string {
	switch {
	case errors.Is(err, grants.ErrNotFound):
		return "Grant not found"
	case errors.Is(err, grants.ErrInvalidDecisionToken):
		return "Grant decision token did not match"
	case errors.Is(err, grants.ErrNotPending):
		return "Grant is no longer pending"
	default:
		return "Grant decision failed"
	}
}

func decodeGrantCreate(c echo.Context) (grantCreateRequest, error) {
	body, err := httpx.ReadLimited(c.Request().Body, maxGrantRequestBodyBytes)
	if err != nil {
		return grantCreateRequest{}, echo.NewHTTPError(http.StatusRequestEntityTooLarge, "grant request body is too large")
	}
	var payload grantCreateRequest
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&payload); err != nil {
		return grantCreateRequest{}, echo.NewHTTPError(http.StatusBadRequest, "invalid grant request json")
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); err == nil {
		return grantCreateRequest{}, echo.NewHTTPError(http.StatusBadRequest, "invalid grant request json")
	} else if !errors.Is(err, io.EOF) {
		return grantCreateRequest{}, echo.NewHTTPError(http.StatusBadRequest, "invalid grant request json")
	}
	if strings.TrimSpace(payload.Reason) == "" {
		return grantCreateRequest{}, echo.NewHTTPError(http.StatusBadRequest, "reason is required")
	}
	return payload, nil
}

func grantBounds(grantPolicy *corepolicy.GrantPolicy, requestedMinutes int, requestedUses int) (time.Duration, time.Duration, int, error) {
	minutes := requestedMinutes
	if minutes <= 0 {
		minutes = grantPolicy.DefaultMinutes
	}
	if minutes > grantPolicy.MaxMinutes {
		return 0, 0, 0, fmt.Errorf("requested minutes %d exceeds policy max %d", minutes, grantPolicy.MaxMinutes)
	}
	maxUses := requestedUses
	if maxUses <= 0 {
		maxUses = grantPolicy.DefaultMaxUses
	}
	if maxUses > grantPolicy.MaxUses {
		return 0, 0, 0, fmt.Errorf("requested max uses %d exceeds policy max %d", maxUses, grantPolicy.MaxUses)
	}
	return time.Duration(minutes) * time.Minute, time.Duration(grantPolicy.RequestTTLMinutes) * time.Minute, maxUses, nil
}

func grantStoreHTTPError(err error) error {
	switch {
	case errors.Is(err, grants.ErrIdempotencyConflict):
		return echo.NewHTTPError(http.StatusConflict, "idempotency conflict")
	default:
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}
}

func apiGrantFromStore(grant grants.Grant) apiGrant {
	return apiGrant{
		ID:              grant.ID,
		Status:          string(grant.Status),
		Operation:       grant.Operation,
		Target:          apiTarget(grant.Target),
		Attrs:           cloneStringMap(grant.Attrs),
		Reason:          grant.Reason,
		Minutes:         int(grant.Duration / time.Minute),
		MaxUses:         grant.MaxUses,
		UsesRemaining:   usesRemaining(grant),
		UsedCount:       grant.UsedCount,
		PendingUntil:    timePointer(grant.PendingExpiresAt),
		ExpiresAt:       timePointer(grant.ExpiresAt),
		ClientRequestID: grant.ClientRequestID,
	}
}

func usesRemaining(grant grants.Grant) int {
	if grant.Status != grants.StatusActive {
		return 0
	}
	remaining := grant.MaxUses - grant.UsedCount - grant.ReservedCount
	if remaining < 0 {
		return 0
	}
	return remaining
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
		Owner: target.Fields["owner"],
		Name:  target.Fields["name"],
	}
}

func apiNotification(ref notify.MessageRef) map[string]any {
	if ref.Kind == "" {
		return nil
	}
	return map[string]any{"kind": ref.Kind, "chat_id": ref.ChatID, "message_id": ref.MessageID}
}

func grantApprovalMessage(grant grants.Grant, decisionToken string) notify.ApprovalMessage {
	return notify.ApprovalMessage{
		GrantID:          grant.ID,
		DecisionToken:    decisionToken,
		Text:             grantApprovalText(grant),
		Client:           grant.Client,
		Operation:        grant.Operation,
		Target:           targetSummary(grant.Target),
		Reason:           grant.Reason,
		RequestedMinutes: int(grant.Duration / time.Minute),
		MaxUses:          grant.MaxUses,
		PendingExpiresAt: grant.PendingExpiresAt,
		Fields:           approvalFields(grant),
	}
}

func grantApprovalText(grant grants.Grant) string {
	return fmt.Sprintf(
		"Approval needed for gh-broker\n\n%s is asking to run %s on %s.\n\nReason: %s\n\nApprove only if this looks right.",
		grant.Client,
		grant.Operation,
		targetSummary(grant.Target),
		grant.Reason,
	)
}

func targetSummary(target corepolicy.Target) string {
	if target.Kind == "repo" {
		return target.Fields["owner"] + "/" + target.Fields["name"]
	}
	return target.Kind
}

func approvalFields(grant grants.Grant) []notify.Field {
	fields := []notify.Field{
		{Name: "operation", Value: grant.Operation},
		{Name: "target", Value: targetSummary(grant.Target)},
	}
	for _, key := range []string{"ref", "base_ref", "head_ref", "path"} {
		if value := grant.Attrs[key]; value != "" {
			fields = append(fields, notify.Field{Name: key, Value: value})
		}
	}
	if grant.MaxUses > 0 {
		fields = append(fields, notify.Field{Name: "max_uses", Value: fmt.Sprintf("%d", grant.MaxUses)})
	}
	return fields
}

func cloneStringMap(values map[string]string) map[string]string {
	if len(values) == 0 {
		return nil
	}
	out := make(map[string]string, len(values))
	for key, value := range values {
		out[key] = value
	}
	return out
}
