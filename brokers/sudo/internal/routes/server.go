// Package routes assembles sudo-broker's unprivileged HTTP frontend.
package routes

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/osolmaz/brokerkit/audit"
	"github.com/osolmaz/brokerkit/brokers/sudo/internal/catalog"
	"github.com/osolmaz/brokerkit/brokers/sudo/internal/executorclient"
	"github.com/osolmaz/brokerkit/brokers/sudo/internal/executorprotocol"
	"github.com/osolmaz/brokerkit/brokers/sudo/internal/plan"
	"github.com/osolmaz/brokerkit/brokers/sudo/internal/presenter"
	"github.com/osolmaz/brokerkit/brokers/sudo/internal/sudopolicy"
	"github.com/osolmaz/brokerkit/controlplane"
	"github.com/osolmaz/brokerkit/grants"
	"github.com/osolmaz/brokerkit/httpx"
	"github.com/osolmaz/brokerkit/internal/strictjson"
	"github.com/osolmaz/brokerkit/notify"
	corepolicy "github.com/osolmaz/brokerkit/policy"
)

const maxBodyBytes int64 = 32 * 1024

const sudoPlanOrphanGrace = 24 * time.Hour

type DecisionPoller interface {
	Poll(context.Context, func(context.Context, notify.Decision) notify.DecisionResult)
}

type Options struct {
	Policy             *corepolicy.Policy
	Catalog            *catalog.Snapshot
	GrantStore         *grants.Store
	PlanStore          *plan.Store
	Identities         plan.IdentityResolver
	Helper             *executorclient.Client
	ClientSecrets      map[string]string
	OperatorSecrets    map[string]string
	Notifier           notify.Notifier
	Poller             DecisionPoller
	Audit              *audit.Writer
	Now                func() time.Time
	OperatorConfigured bool
}

type Server struct {
	echo               *echo.Echo
	control            *controlplane.Runtime
	policy             *corepolicy.Policy
	catalog            *catalog.Snapshot
	grants             *grants.Store
	plans              *plan.Store
	identities         plan.IdentityResolver
	helper             *executorclient.Client
	validator          plan.Validator
	notifier           notify.Notifier
	poller             DecisionPoller
	audit              *audit.Writer
	now                func() time.Time
	operatorConfigured bool
	requestMu          sync.Mutex
}

func New(opts Options) (*Server, error) {
	if opts.Policy == nil || opts.Catalog == nil || opts.GrantStore == nil || opts.PlanStore == nil || opts.Identities == nil || opts.Helper == nil {
		return nil, errors.New("sudo broker dependencies are required")
	}
	validator := plan.Validator{Store: opts.PlanStore, Catalog: opts.Catalog, Identities: opts.Identities, Helper: opts.Helper}
	control, err := controlplane.New(controlplane.Options{
		Broker: "sudo-broker", Store: opts.GrantStore, ClientSecrets: opts.ClientSecrets, OperatorSecrets: opts.OperatorSecrets,
		Presenter: presenter.Presenter{Catalog: opts.Catalog}, ActivationValidator: validator, Audit: opts.Audit,
	})
	if err != nil {
		return nil, err
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	auditWriter := opts.Audit
	if auditWriter == nil {
		auditWriter = audit.New(io.Discard)
	}
	e := echo.New()
	e.HideBanner = true
	e.HidePort = true
	e.Use(middleware.Recover(), noStore)
	server := &Server{echo: e, control: control, policy: opts.Policy, catalog: opts.Catalog, grants: opts.GrantStore, plans: opts.PlanStore,
		identities: opts.Identities, helper: opts.Helper, validator: validator, notifier: opts.Notifier, poller: opts.Poller,
		audit: auditWriter, now: now, operatorConfigured: opts.OperatorConfigured || len(opts.OperatorSecrets) > 0}
	if err := collectPlanOrphans(opts.GrantStore, opts.PlanStore, now().UTC()); err != nil {
		slog.Default().Warn("collect orphan sudo plans", "error", err)
	}
	server.registerRoutes()
	return server, nil
}

func (s *Server) Handler() http.Handler { return s.echo }

func (s *Server) OperatorHandler() http.Handler { return s.control.OperatorHandler }

func (s *Server) Start(ctx context.Context) {
	if s.poller != nil {
		go s.poller.Poll(ctx, s.control.HandleDecision)
	}
}

func (s *Server) registerRoutes() {
	s.echo.GET("/healthz", func(c echo.Context) error { return c.JSON(http.StatusOK, map[string]bool{"ok": true}) })
	s.echo.GET("/readyz", s.readiness)
	protected := s.echo.Group("")
	protected.Use(s.authenticate)
	protected.POST("/api/v1/requests", s.createRequest)
	protected.GET("/api/v1/requests/:id", s.getRequest)
	protected.POST("/api/v1/executions", s.execute)
}

func (s *Server) authenticate(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		client, err := s.control.Clients.AuthenticateRequest(c.Request())
		if err != nil {
			return echo.NewHTTPError(http.StatusUnauthorized, "authentication required")
		}
		c.Set("sudo_client", client)
		return next(c)
	}
}

func noStore(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		httpx.NoStore(c.Response().Header())
		return next(c)
	}
}

func (s *Server) readiness(c echo.Context) error {
	if err := s.helper.Ready(c.Request().Context()); err != nil {
		return c.JSON(http.StatusServiceUnavailable, map[string]bool{"ok": false})
	}
	return c.JSON(http.StatusOK, map[string]bool{"ok": true})
}

type commandInput struct {
	CommandID  string                     `json:"command_id"`
	TargetUser string                     `json:"target_user"`
	Arguments  map[string]json.RawMessage `json:"arguments"`
}

type requestInput struct {
	commandInput
	ClientRequestID string `json:"client_request_id"`
	Reason          string `json:"reason"`
	Minutes         int    `json:"minutes,omitempty"`
}

type executionInput struct {
	commandInput
	ExecutionID string `json:"execution_id"`
}

type requestView struct {
	ID              string        `json:"id"`
	Status          grants.Status `json:"status"`
	Revision        int64         `json:"revision"`
	CommandID       string        `json:"command_id"`
	TargetUser      string        `json:"target_user"`
	RequestedAt     time.Time     `json:"requested_at"`
	PendingUntil    time.Time     `json:"pending_until"`
	ActiveUntil     *time.Time    `json:"active_until,omitempty"`
	UsesRemaining   int           `json:"uses_remaining"`
	ClientRequestID string        `json:"client_request_id"`
}

func (s *Server) createRequest(c echo.Context) error {
	if s.notifier == nil && !s.operatorConfigured {
		return echo.NewHTTPError(http.StatusServiceUnavailable, "approval channel is not configured")
	}
	var input requestInput
	if err := decodeBody(c, &input); err != nil {
		return err
	}
	if err := validateRequestInput(input); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}
	client := clientFromContext(c)
	resolved, policyRequest, err := s.classify(client, input.commandInput)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}
	decision := s.policy.Decide(policyRequest, corepolicy.DecisionOptions{ForGrantRequest: true, Now: s.now().UTC()})
	if decision.Effect != corepolicy.EffectRequest || decision.GrantPolicy == nil {
		s.record(policyRequest, "denied", decision.Reason, "", decision.MatchedDenyRuleIDs)
		return echo.NewHTTPError(http.StatusForbidden, "command is not requestable")
	}
	duration, pending, err := grantBounds(decision.GrantPolicy, input.Minutes)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}
	request := grants.Request{Client: client, ClientRequestID: input.ClientRequestID, Operation: policyRequest.Operation,
		Target: policyRequest.Target, Attrs: policyRequest.Attrs, Reason: strings.TrimSpace(input.Reason), Duration: duration, PendingTimeout: pending, MaxUses: 1}
	identity, err := s.identities.Lookup(resolved.TargetUser)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "target user cannot be resolved")
	}
	s.requestMu.Lock()
	createdAt, exists, err := existingPlanCreatedAt(s.grants, s.plans, request.Client, request.ClientRequestID)
	if err != nil {
		s.requestMu.Unlock()
		return echo.NewHTTPError(http.StatusServiceUnavailable, "grant state is unavailable")
	}
	if !exists {
		createdAt = s.now().UTC()
	}
	value, err := plan.Build(request, resolved, identity, createdAt)
	if err != nil {
		s.requestMu.Unlock()
		return echo.NewHTTPError(http.StatusBadRequest, "command plan is invalid")
	}
	if err := s.plans.Bind(&request, value); err != nil {
		s.requestMu.Unlock()
		return echo.NewHTTPError(http.StatusInternalServerError, "command plan could not be stored")
	}
	result, created, err := s.grants.Request(request)
	s.requestMu.Unlock()
	if err != nil {
		return grantError(err)
	}
	stored, err := s.notifyRequest(c.Request().Context(), result)
	if err != nil {
		return err
	}
	s.record(policyRequest, "requires_approval", "requestable", stored.ID, decision.MatchedRequestRuleIDs)
	status := http.StatusOK
	if created {
		status = http.StatusCreated
	}
	return c.JSON(status, map[string]any{"request": view(stored)})
}

func existingPlanCreatedAt(store *grants.Store, plans *plan.Store, client string, clientRequestID string) (time.Time, bool, error) {
	items, err := store.ListForClient(client)
	if err != nil {
		return time.Time{}, false, err
	}
	for _, grant := range items {
		if grant.ClientRequestID != clientRequestID || grant.Status == grants.StatusCanceled {
			continue
		}
		value, err := plans.Get(grant.Metadata[plan.MetadataDigest])
		if err != nil {
			return time.Time{}, false, err
		}
		return value.CreatedAt, true, nil
	}
	return time.Time{}, false, nil
}

func collectPlanOrphans(store *grants.Store, plans *plan.Store, now time.Time) error {
	items, err := store.List()
	if err != nil {
		return err
	}
	referenced := make(map[string]bool, len(items))
	for _, grant := range items {
		if grant.Metadata[plan.MetadataSchema] == plan.SchemaV1 {
			referenced[grant.Metadata[plan.MetadataDigest]] = true
		}
	}
	_, err = plans.CollectOrphans(referenced, now.Add(-sudoPlanOrphanGrace))
	return err
}

func (s *Server) getRequest(c echo.Context) error {
	grant, err := s.grants.Get(c.Param("id"))
	if err != nil || grant.Client != clientFromContext(c) {
		return echo.NewHTTPError(http.StatusNotFound, "request not found")
	}
	return c.JSON(http.StatusOK, map[string]any{"request": view(grant)})
}

func (s *Server) execute(c echo.Context) error {
	var input executionInput
	if err := decodeBody(c, &input); err != nil {
		return err
	}
	if err := validateExecutionInput(input); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}
	client := clientFromContext(c)
	_, policyRequest, err := s.classify(client, input.commandInput)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}
	active, err := s.grants.ActivePolicyGrants()
	if err != nil {
		return echo.NewHTTPError(http.StatusServiceUnavailable, "grant state is unavailable")
	}
	decision := s.policy.Decide(policyRequest, corepolicy.DecisionOptions{ActiveGrants: active, Now: s.now().UTC()})
	if !decision.Allowed || decision.GrantID == "" {
		s.record(policyRequest, "denied", decision.Reason, "", append(decision.MatchedDenyRuleIDs, decision.MatchedRequestRuleIDs...))
		return echo.NewHTTPError(http.StatusForbidden, "an active one-shot approval is required")
	}
	reserved, err := s.grants.ReserveUse(decision.GrantID)
	if err != nil {
		return echo.NewHTTPError(http.StatusConflict, "approval is no longer usable")
	}
	value, err := s.validator.ValidateExecution(c.Request().Context(), reserved)
	if err != nil {
		_, _ = s.grants.ReleaseUse(reserved.ID)
		return echo.NewHTTPError(http.StatusForbidden, "approved command plan is invalid")
	}
	reservationID := fmt.Sprintf("%s:r%d", reserved.ID, reserved.Revision)
	response, callErr := s.helper.Execute(c.Request().Context(), input.ExecutionID, value, reserved.ID, reservationID, reserved.ExpiresAt)
	return s.settleExecution(c, policyRequest, reserved, response, callErr)
}

func (s *Server) settleExecution(c echo.Context, request corepolicy.Request, reserved grants.Grant, response executorprotocol.Response, callErr error) error {
	if callErr != nil {
		if !executorclient.WasDispatched(callErr) {
			_, _ = s.grants.ReleaseUse(reserved.ID)
			s.record(request, "rejected", "helper unavailable before dispatch", reserved.ID, nil)
			return echo.NewHTTPError(http.StatusServiceUnavailable, "privileged helper is unavailable")
		}
		_, _ = s.grants.RetainUse(reserved.ID)
		s.record(request, "ambiguous", "helper response unavailable", reserved.ID, nil)
		return echo.NewHTTPError(http.StatusServiceUnavailable, "execution result is ambiguous; approval is closed")
	}
	switch response.Status {
	case executorprotocol.StatusRejected:
		_, _ = s.grants.ReleaseUse(reserved.ID)
		s.record(request, "rejected", response.ErrorCode, reserved.ID, nil)
		return echo.NewHTTPError(http.StatusConflict, "helper rejected execution before start")
	case executorprotocol.StatusAmbiguous:
		_, _ = s.grants.RetainUse(reserved.ID)
		s.record(request, "ambiguous", response.ErrorCode, reserved.ID, nil)
		return echo.NewHTTPError(http.StatusServiceUnavailable, "execution result is ambiguous; approval is closed")
	case executorprotocol.StatusCompleted:
		if response.Outcome == nil {
			_, _ = s.grants.RetainUse(reserved.ID)
			return echo.NewHTTPError(http.StatusServiceUnavailable, "execution result is ambiguous; approval is closed")
		}
		if !response.Outcome.Started {
			_, _ = s.grants.ReleaseUse(reserved.ID)
			return echo.NewHTTPError(http.StatusConflict, "command did not start")
		}
		if _, err := s.grants.CommitUse(reserved.ID); err != nil {
			_, _ = s.grants.RetainUse(reserved.ID)
			return echo.NewHTTPError(http.StatusInternalServerError, "execution use could not be settled")
		}
		s.record(request, "executed", "", reserved.ID, nil)
		return c.JSON(http.StatusOK, map[string]any{"execution": executionView(response)})
	default:
		_, _ = s.grants.RetainUse(reserved.ID)
		return echo.NewHTTPError(http.StatusServiceUnavailable, "execution result is ambiguous; approval is closed")
	}
}

func (s *Server) classify(client string, input commandInput) (catalog.Resolved, corepolicy.Request, error) {
	resolved, err := s.catalog.Resolve(strings.TrimSpace(input.CommandID), strings.TrimSpace(input.TargetUser), input.Arguments)
	if err != nil {
		return catalog.Resolved{}, corepolicy.Request{}, err
	}
	return resolved, sudopolicy.Request(client, resolved), nil
}

func (s *Server) notifyRequest(ctx context.Context, result grants.RequestResult) (grants.Grant, error) {
	grant := result.Grant
	if grant.Notification != nil || grant.Status != grants.StatusPending || s.notifier == nil {
		return grant, nil
	}
	claim, claimed, err := s.grants.ClaimNotification(grant.ID, 2*time.Minute)
	if err != nil {
		return grants.Grant{}, echo.NewHTTPError(http.StatusServiceUnavailable, "approval notification could not be claimed")
	}
	if !claimed {
		return s.grants.Get(grant.ID)
	}
	commandID := corepolicy.FirstValue(grant.Attrs[sudopolicy.AttrCommandID])
	target := corepolicy.FirstValue(grant.Target.Fields[sudopolicy.TargetName])
	ref, err := s.notifier.SendApproval(ctx, notify.ApprovalMessage{
		GrantID: claim.Grant.ID, DecisionToken: claim.DecisionToken,
		Text:   fmt.Sprintf("Approval needed for sudo-broker\n\n%s requests %s once as %s.", grant.Client, commandID, target),
		Client: grant.Client, Operation: grant.Operation, Target: target, Reason: grant.Reason,
		RequestedMinutes: int(grant.Duration / time.Minute), MaxUses: 1,
		Fields: []notify.Field{{Name: "command", Value: commandID}, {Name: "target user", Value: target}},
	})
	if err != nil {
		if s.operatorConfigured {
			stored, _, retainErr := s.grants.RetainNotificationClaim(grant.ID, claim.Grant.NotificationClaimedAt)
			if retainErr == nil {
				return stored, nil
			}
		}
		_, _, _ = s.grants.CancelIfNotificationClaimed(grant.ID, claim.Grant.NotificationClaimedAt)
		return grants.Grant{}, echo.NewHTTPError(http.StatusServiceUnavailable, "operator could not be notified")
	}
	stored, recorded, err := s.grants.SetNotificationIfClaimed(grant.ID, claim.Grant.NotificationClaimedAt, ref)
	if err != nil || !recorded {
		return grants.Grant{}, echo.NewHTTPError(http.StatusServiceUnavailable, "approval notification could not be recorded")
	}
	return stored, nil
}

func decodeBody(c echo.Context, out any) error {
	body, err := httpx.ReadLimited(c.Request().Body, maxBodyBytes)
	if err != nil {
		return echo.NewHTTPError(http.StatusRequestEntityTooLarge, "request body is too large")
	}
	if err := strictjson.RejectDuplicateKeys(body); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid request JSON")
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(out); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid request JSON")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid request JSON")
	}
	return nil
}

func validateRequestInput(input requestInput) error {
	if err := validateCommandInput(input.commandInput); err != nil {
		return err
	}
	if !boundedID(input.ClientRequestID) {
		return errors.New("client_request_id is required and must be a bounded identifier")
	}
	reason := strings.TrimSpace(input.Reason)
	if reason == "" || len(reason) > 1000 || strings.IndexFunc(reason, unicode.IsControl) >= 0 {
		return errors.New("reason is required and must be bounded plain text")
	}
	if input.Minutes < 0 {
		return errors.New("minutes must not be negative")
	}
	return nil
}

func validateExecutionInput(input executionInput) error {
	if err := validateCommandInput(input.commandInput); err != nil {
		return err
	}
	if !boundedID(input.ExecutionID) {
		return errors.New("execution_id is required and must be a bounded identifier")
	}
	return nil
}

func validateCommandInput(input commandInput) error {
	if strings.TrimSpace(input.CommandID) == "" || strings.TrimSpace(input.TargetUser) == "" {
		return errors.New("command_id and target_user are required")
	}
	return nil
}

func boundedID(value string) bool {
	return len(value) >= 1 && len(value) <= 128 && strings.TrimSpace(value) == value && !strings.ContainsAny(value, " \t\r\n")
}

func grantBounds(policy *corepolicy.GrantPolicy, minutes int) (time.Duration, time.Duration, error) {
	if policy.Mode != string(corepolicy.GrantModeExecution) || policy.DefaultMaxUses != 1 || policy.MaxUses != 1 {
		return 0, 0, errors.New("sudo command policy must use one-shot execution grants")
	}
	if minutes == 0 {
		minutes = policy.DefaultMinutes
	}
	if minutes < 1 || minutes > policy.MaxMinutes {
		return 0, 0, errors.New("requested duration exceeds policy bounds")
	}
	return time.Duration(minutes) * time.Minute, time.Duration(policy.RequestTTLMinutes) * time.Minute, nil
}

func grantError(err error) error {
	if errors.Is(err, grants.ErrIdempotencyConflict) {
		return echo.NewHTTPError(http.StatusConflict, "client_request_id conflicts with another request")
	}
	return echo.NewHTTPError(http.StatusBadRequest, "grant request is invalid")
}

func view(grant grants.Grant) requestView {
	var activeUntil *time.Time
	if !grant.ExpiresAt.IsZero() {
		value := grant.ExpiresAt.UTC()
		activeUntil = &value
	}
	remaining := grant.MaxUses - grant.UsedCount - grant.ReservedCount
	if remaining < 0 || grant.ReservationRetained {
		remaining = 0
	}
	return requestView{ID: grant.ID, Status: grant.Status, Revision: grant.Revision,
		CommandID: corepolicy.FirstValue(grant.Attrs[sudopolicy.AttrCommandID]), TargetUser: corepolicy.FirstValue(grant.Target.Fields[sudopolicy.TargetName]),
		RequestedAt: grant.CreatedAt, PendingUntil: grant.PendingExpiresAt, ActiveUntil: activeUntil,
		UsesRemaining: remaining, ClientRequestID: grant.ClientRequestID}
}

func executionView(response executorprotocol.Response) map[string]any {
	outcome := response.Outcome
	return map[string]any{
		"id": response.ExecutionID, "started": outcome.Started, "exit_code": outcome.ExitCode, "signal": outcome.Signal,
		"timed_out": outcome.TimedOut, "truncated": outcome.Truncated, "duration_ns": outcome.Duration.Nanoseconds(),
		"stdout_base64": base64.StdEncoding.EncodeToString(outcome.Stdout), "stderr_base64": base64.StdEncoding.EncodeToString(outcome.Stderr),
	}
}

func clientFromContext(c echo.Context) string {
	client, _ := c.Get("sudo_client").(string)
	return client
}

func (s *Server) record(request corepolicy.Request, decision string, reason string, grantID string, rules []string) {
	_ = s.audit.Record(audit.Event{Broker: "sudo-broker", Client: request.Client, Operation: request.Operation,
		Target: corepolicy.FirstValue(request.Target.Fields[sudopolicy.TargetName]), Decision: decision, Reason: reason,
		MatchedRuleIDs: rules, GrantID: grantID, Attrs: map[string]string{"command_id": corepolicy.FirstValue(request.Attrs[sudopolicy.AttrCommandID])}})
}
