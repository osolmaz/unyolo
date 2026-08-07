// Package operatorapi exposes unYOLO Operator V1 over protected HTTP.
package operatorapi

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/osolmaz/unyolo/authorization/activation"
	"github.com/osolmaz/unyolo/authorization/budget"
	"github.com/osolmaz/unyolo/authorization/decision"
	"github.com/osolmaz/unyolo/authorization/grants"
	"github.com/osolmaz/unyolo/authorization/policy"
	"github.com/osolmaz/unyolo/internal/buildinfo"
	"github.com/osolmaz/unyolo/internal/optional"
	"github.com/osolmaz/unyolo/operator/inbox"
	"github.com/osolmaz/unyolo/operator/v1"
	"github.com/osolmaz/unyolo/operator/wire"
	"github.com/osolmaz/unyolo/protocol/contract"
	"github.com/osolmaz/unyolo/protocol/operatorwire"
	"github.com/osolmaz/unyolo/telemetry/audit"
	"github.com/osolmaz/unyolo/transport/http"
)

const (
	maxDecisionBodyBytes = 96 * 1024
	eventHeartbeat       = 15 * time.Second
)

type Authorizer func(*http.Request) (string, error)

type AuditRecorder interface {
	Record(audit.Event) error
}

type Options struct {
	Inbox            *operatorinbox.Service
	Decisions        *decision.Service
	Authorize        Authorizer
	Broker           string
	Audit            AuditRecorder
	Metrics          http.Handler
	NewCorrelationID func() (string, error)
}

type handler struct {
	inbox     *operatorinbox.Service
	decisions *decision.Service
	authorize Authorizer
	broker    string
	audit     AuditRecorder
	newID     func() (string, error)
}

func New(options Options) (http.Handler, error) {
	if err := validateOptions(options); err != nil {
		return nil, err
	}
	if options.NewCorrelationID == nil {
		options.NewCorrelationID = secureCorrelationID
	}
	h := &handler{options.Inbox, options.Decisions, options.Authorize, options.Broker, options.Audit, options.NewCorrelationID}
	router := echo.New()
	router.HideBanner = true
	router.HidePort = true
	router.Use(h.requestMetadata)
	router.HTTPErrorHandler = h.echoError
	if options.Metrics != nil {
		router.GET("/metrics", h.metrics(options.Metrics))
	}
	operatorwire.RegisterHandlers(router, h)
	return router, nil
}

func (h *handler) metrics(handler http.Handler) echo.HandlerFunc {
	return func(c echo.Context) error {
		return h.authorized(c, func(string) { handler.ServeHTTP(c.Response(), c.Request()) })
	}
}

func validateOptions(options Options) error {
	if options.Inbox == nil || options.Decisions == nil {
		return errors.New("operator inbox and decision service are required")
	}
	if !validOperatorDependencies(options) {
		return errors.New("operator authorizer, broker, and audit recorder are required")
	}
	return nil
}

func validOperatorDependencies(options Options) bool {
	return options.Authorize != nil && strings.TrimSpace(options.Broker) != "" && options.Audit != nil
}

var _ operatorwire.ServerInterface = (*handler)(nil)

func (h *handler) requestMetadata(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		writer := c.Response()
		writer.Header().Set("Cache-Control", "no-store")
		writer.Header().Set("X-Content-Type-Options", "nosniff")
		correlationID, err := h.newID()
		if err != nil {
			writer.Header().Set("X-Correlation-ID", "unavailable")
			h.writeError(writer, http.StatusServiceUnavailable, "temporarily_unavailable", "secure request identifier unavailable", nil)
			return nil //nolint:nilerr // The middleware already emitted the terminal response.
		}
		writer.Header().Set("X-Correlation-ID", correlationID)
		return next(c)
	}
}

func (h *handler) echoError(err error, c echo.Context) {
	if c.Response().Committed {
		return
	}
	status, code, message := http.StatusInternalServerError, "internal_error", "operator request failed"
	var httpError *echo.HTTPError
	if errors.As(err, &httpError) {
		status = httpError.Code
	}
	switch status {
	case http.StatusBadRequest:
		code, message = "invalid_request", "request is invalid"
	case http.StatusMethodNotAllowed:
		code, message = "method_not_allowed", "method not allowed"
	case http.StatusNotFound:
		code, message = "not_found", "route not found"
	}
	h.writeError(c.Response(), status, code, message, nil)
}

func (h *handler) actor(c echo.Context) (string, bool) {
	return h.authenticate(c.Response(), c.Request())
}

func (h *handler) DiscoverOperator(c echo.Context) error {
	if _, ok := h.actor(c); !ok {
		return nil
	}
	return c.JSON(http.StatusOK, operatorwire.Descriptor{ApiVersion: operatorwire.UnyoloIooperatorv1,
		ContractDigest: contract.OperatorV1Digest, BuildId: buildinfo.ID()})
}

func (h *handler) StreamOperatorEvents(c echo.Context, _ operatorwire.StreamOperatorEventsParams) error {
	return h.authorizedRequest(c, h.events)
}

func (h *handler) ListOperatorRequests(c echo.Context, _ operatorwire.ListOperatorRequestsParams) error {
	return h.authorizedRequest(c, h.list)
}

func (h *handler) GetOperatorRequest(c echo.Context, id operatorwire.RequestID) error {
	return h.authorized(c, func(string) {
		h.detail(c.Response(), c.Request(), id)
	})
}

func (h *handler) DecideOperatorRequest(c echo.Context, id operatorwire.RequestID, action operatorwire.Action) error {
	return h.authorized(c, func(actor string) {
		h.decide(c.Response(), c.Request(), id, operatorv1.Action(action), actor)
	})
}

func (h *handler) authorized(c echo.Context, handle func(string)) error {
	if actor, ok := h.actor(c); ok {
		handle(actor)
	}
	return nil
}

func (h *handler) authorizedRequest(c echo.Context, handle func(http.ResponseWriter, *http.Request)) error {
	return h.authorized(c, func(string) { handle(c.Response(), c.Request()) })
}

func (h *handler) OperatorHealth(c echo.Context) error {
	return h.operatorStatus(c)
}

func (h *handler) OperatorReady(c echo.Context) error {
	return h.operatorStatus(c)
}

func (h *handler) operatorStatus(c echo.Context) error {
	h.status(c.Response(), c.Request())
	return nil
}

func (h *handler) authenticate(writer http.ResponseWriter, request *http.Request) (string, bool) {
	actor, err := h.authorize(request)
	if err != nil || strings.TrimSpace(actor) == "" {
		_ = h.audit.Record(audit.Event{Broker: h.broker, Decision: "operator_auth", ErrorCode: "unauthorized"})
		writer.Header().Set("WWW-Authenticate", `Bearer realm="broker-operator"`)
		h.writeError(writer, http.StatusUnauthorized, "unauthorized", "operator authentication required", nil)
		return "", false
	}
	return actor, true
}

func (h *handler) status(writer http.ResponseWriter, request *http.Request) {
	if strings.TrimSuffix(request.URL.Path, "/") == "/readyz" {
		if _, err := h.inbox.Store().QueryGrants(grants.Query{Limit: 1}); err != nil {
			h.writeError(writer, http.StatusServiceUnavailable, "temporarily_unavailable", "operator source is not ready", nil)
			return
		}
	}
	h.writeJSON(writer, http.StatusOK, operatorwire.Health{Status: "ok", ContractDigest: contract.OperatorV1Digest, BuildId: buildinfo.ID()})
}

func (h *handler) list(writer http.ResponseWriter, request *http.Request) {
	query, err := parseQuery(request)
	if err != nil {
		h.writeMappedError(writer, request, err)
		return
	}
	page, err := h.inbox.List(request.Context(), query)
	if err != nil {
		h.writeMappedError(writer, request, err)
		return
	}
	out := operatorwire.RequestPage{Requests: make([]operatorwire.BrokerRequest, 0, len(page.Items)), NextCursor: optional.NonZero(page.NextCursor), EventCursor: optional.NonZero(page.EventCursor)}
	for _, item := range page.Items {
		out.Requests = append(out.Requests, project(item))
	}
	h.writeJSON(writer, http.StatusOK, out)
}

func (h *handler) detail(writer http.ResponseWriter, request *http.Request, id string) {
	item, err := h.inbox.Get(request.Context(), id)
	if err != nil {
		h.writeMappedError(writer, request, err)
		return
	}
	h.writeJSON(writer, http.StatusOK, project(item))
}

func (h *handler) decide(writer http.ResponseWriter, request *http.Request, id string, action operatorv1.Action, actor string) {
	if !validAction(action) {
		h.writeError(writer, http.StatusNotFound, "not_found", "route not found", nil)
		return
	}
	var command operatorv1.Decision
	if !h.decodeDecision(writer, request, &command) {
		return
	}
	command.CorrelationID = writer.Header().Get("X-Correlation-ID")
	result, err := h.decisions.Decide(request.Context(), id, action, actor, command)
	if err != nil {
		h.writeDecisionError(writer, request, err, result.Grant)
		return
	}
	item := project(h.inbox.Project(request.Context(), result.Grant))
	if result.AuditExportFailed {
		writer.Header().Set("X-Broker-Audit-Export", "failed")
	}
	if result.Replay {
		writer.Header().Set("Idempotency-Replayed", "true")
	}
	h.writeJSON(writer, http.StatusOK, item)
}

func (h *handler) decodeDecision(writer http.ResponseWriter, request *http.Request, command *operatorv1.Decision) bool {
	mediaType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		h.writeError(writer, http.StatusUnsupportedMediaType, "invalid_request", "content type must be application/json", nil)
		return false
	}
	var input operatorwire.Decision
	if err := decodeStrictJSON(request, &input); err != nil || !validDecisionConstraints(input.Constraints) ||
		!validNotificationDecision(input.Notification, input.Constraints) {
		h.writeError(writer, http.StatusBadRequest, "invalid_request", "decision body is invalid", nil)
		return false
	}
	*command = wireDecision(input)
	return true
}

func validNotificationDecision(value *operatorwire.NotificationDecision, constraints *operatorwire.Constraints) bool {
	if value == nil {
		return true
	}
	return constraints == nil && validNotificationFields(value)
}

func validNotificationFields(value *operatorwire.NotificationDecision) bool {
	return validNotificationIdentity(value) && validNotificationPayload(value)
}

func validNotificationIdentity(value *operatorwire.NotificationDecision) bool {
	return value.Kind == operatorwire.NotificationDecisionKind("telegram") && value.ChatId != 0 && value.MessageId > 0 &&
		value.DecisionToken != "" && len(value.DecisionToken) <= 200
}

func validNotificationPayload(value *operatorwire.NotificationDecision) bool {
	return value.Renderer != "" && len(value.Renderer) <= 64 && value.Text != "" && len(value.Text) <= 32*1024 &&
		value.PresentationJson != "" && len(value.PresentationJson) <= 64*1024 &&
		validNotificationDigest(value.PresentationDigest) && validNotificationDigest(value.RenderedDigest)
}

func validNotificationDigest(value string) bool {
	if len(value) != len("sha256:")+sha256.Size*2 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil
}

func validDecisionConstraints(value *operatorwire.Constraints) bool {
	return value == nil ||
		((value.DurationSeconds == nil || *value.DurationSeconds > 0) &&
			(!value.MaxUses.IsSpecified() || value.MaxUses.IsNull() || value.MaxUses.MustGet() > 0))
}

func wireDecision(input operatorwire.Decision) operatorv1.Decision {
	result := operatorv1.Decision{
		ExpectedRevision: int64(input.ExpectedRevision), IdempotencyKey: input.IdempotencyKey,
	}
	if input.OnBehalfOf != nil {
		result.OnBehalfOf = *input.OnBehalfOf
	}
	if input.Notification != nil {
		result.Notification = &operatorv1.NotificationDecision{Kind: string(input.Notification.Kind),
			Renderer: input.Notification.Renderer, DecisionToken: input.Notification.DecisionToken,
			ChatID: int64(input.Notification.ChatId), MessageID: input.Notification.MessageId, Text: input.Notification.Text,
			PresentationJSON: input.Notification.PresentationJson, PresentationDigest: input.Notification.PresentationDigest,
			RenderedDigest: input.Notification.RenderedDigest}
	}
	if input.Constraints == nil {
		return result
	}
	result.Constraints = &operatorv1.Constraints{}
	if input.Constraints.DurationSeconds != nil {
		result.Constraints.DurationSeconds = int64(*input.Constraints.DurationSeconds)
	}
	if input.Constraints.MaxUses.IsSpecified() {
		result.Constraints.MaxUses = usebudget.Optional{Limit: operatorv1wire.UseLimitFromWire(input.Constraints.MaxUses), Specified: true}
	}
	return result
}

func project(item operatorinbox.Item) operatorwire.BrokerRequest {
	facts := make([]operatorwire.Fact, 0, len(item.Presentation.Facts))
	for _, fact := range item.Presentation.Facts {
		facts = append(facts, operatorwire.Fact{Label: fact.Label, Value: fact.Value})
	}
	warnings := make([]operatorwire.Warning, 0, len(item.Presentation.Warnings))
	for _, warning := range item.Presentation.Warnings {
		warnings = append(warnings, operatorwire.Warning{Severity: operatorwire.PresentationRisk(warning.Severity), Text: warning.Text})
	}
	request := operatorwire.BrokerRequest{
		Id: item.ID, Revision: int(item.Revision), Requester: item.Client, Operation: item.Operation,
		Mode: operatorwire.GrantMode(item.Mode), Status: operatorwire.Status(item.Status),
		RequestedAt: item.RequestedAt, RequestedDurationSeconds: int(item.RequestedDurationSeconds),
		RequestedMaxUses: operatorv1wire.UseLimitToWire(item.RequestedMaxUses), GrantedMaxUses: operatorv1wire.UseLimitToWire(item.MaxUses),
		UsedCount: item.UsedCount, RequestReason: optional.NonZero(item.Reason),
		DecidedAt: item.DecidedAt, DecidedBy: optional.NonZero(item.DecidedBy), DecidedOnBehalfOf: optional.NonZero(item.DecidedOnBehalfOf),
		FailedAt: item.FailedAt, FailureReference: optional.NonZero(item.FailureReference),
		PresentationUnavailable: optional.NonZero(item.PresentationUnavailable),
		Presentation: operatorwire.Presentation{Risk: operatorwire.PresentationRisk(item.Presentation.Risk), Title: item.Presentation.Title,
			Summary: optional.NonZero(item.Presentation.Summary), Target: item.Presentation.Target, Facts: &facts,
			Warnings: &warnings, PlanHash: optional.NonZero(item.Presentation.PlanHash)},
		AllowedActions: allowedActions(item),
	}
	if item.FailureCode != "" {
		code := operatorwire.BrokerRequestFailureCode(item.FailureCode)
		request.FailureCode = &code
	}
	if item.Status == grants.StatusPending {
		expires := item.PendingExpiresAt
		request.PendingExpiresAt = &expires
		request.ApprovalBounds = &operatorwire.ApprovalBounds{MaxDurationSeconds: int(item.RequestedDurationSeconds), MaxUses: operatorv1wire.UseLimitToWire(item.RequestedMaxUses)}
	}
	if item.ActiveExpiresAt != nil {
		request.ActiveExpiresAt = item.ActiveExpiresAt
	}
	return request
}

func allowedActions(item operatorinbox.Item) []operatorwire.Action {
	switch item.Status {
	case grants.StatusPending:
		return []operatorwire.Action{operatorwire.Approve, operatorwire.Deny}
	case grants.StatusActive:
		return []operatorwire.Action{operatorwire.Revoke}
	default:
		return []operatorwire.Action{}
	}
}

func (h *handler) events(writer http.ResponseWriter, request *http.Request) {
	flusher, ok := writer.(http.Flusher)
	if !ok {
		h.writeError(writer, http.StatusInternalServerError, "internal_error", "event streaming unavailable", nil)
		return
	}
	cursor := request.URL.Query().Get("cursor")
	if cursor == "" {
		cursor = request.Header.Get("Last-Event-ID")
	}
	page, err := h.inbox.Store().EventsAfter(cursor, 100)
	if err != nil {
		h.writeMappedError(writer, request, err)
		return
	}
	writer.Header().Set("Content-Type", "text/event-stream")
	writer.Header().Set("Connection", "keep-alive")
	writer.WriteHeader(http.StatusOK)
	for {
		cursor, err = writeEventPage(writer, page, cursor)
		if err != nil {
			return
		}
		flusher.Flush()
		page, err = h.nextEventPage(writer, flusher, request, page, cursor)
		if err != nil {
			return
		}
	}
}

func (h *handler) nextEventPage(writer io.Writer, flusher http.Flusher, request *http.Request, current grants.EventPage, cursor string) (grants.EventPage, error) {
	if current.HasMore {
		return h.inbox.Store().EventsAfter(cursor, 100)
	}
	ctx, cancel := context.WithTimeout(request.Context(), eventHeartbeat)
	defer cancel()
	page, err := h.inbox.Store().WaitForEvents(ctx, cursor)
	if !errors.Is(err, context.DeadlineExceeded) {
		return page, err
	}
	_, _ = io.WriteString(writer, ": heartbeat\n\n")
	flusher.Flush()
	return grants.EventPage{}, nil
}

func writeEventPage(writer io.Writer, page grants.EventPage, cursor string) (string, error) {
	for _, internal := range page.Events {
		cursor = internal.Cursor
		event, ok := publicEvent(internal)
		if !ok {
			continue
		}
		data, err := json.Marshal(event)
		if err != nil {
			return cursor, err
		}
		if _, err := fmt.Fprintf(writer, "id: %s\ndata: %s\n\n", event.Cursor, data); err != nil {
			return cursor, err
		}
	}
	return cursor, nil
}

func publicEvent(event grants.Event) (operatorwire.BrokerEvent, bool) {
	kind, visible := publicEventKind(event)
	if !visible {
		return operatorwire.BrokerEvent{}, false
	}
	return operatorwire.BrokerEvent{Cursor: event.Cursor, Kind: operatorwire.BrokerEventKind(kind), RequestId: event.GrantID,
		Revision: int(event.Revision), Status: operatorwire.Status(event.Status), OccurredAt: event.Time, UsedCount: event.UsedCount}, true
}

func publicEventKind(event grants.Event) (string, bool) {
	hidden := map[grants.EventKind]bool{
		grants.EventGrantReserved: true, grants.EventGrantReleased: true, grants.EventExecutionSucceeded: true,
		grants.EventExecutionFailed: true, grants.EventExecutionAmbiguous: true,
	}
	if hidden[event.Kind] {
		return "", false
	}
	if event.Kind == grants.EventGrantRevoked {
		return "request.revoked", true
	}
	if event.Kind == grants.EventGrantConsumed {
		return consumedEventKind(event.Status), true
	}
	return string(event.Kind), true
}

func consumedEventKind(status grants.Status) string {
	if status == grants.StatusConsumed {
		return "request.consumed"
	}
	return "request.updated"
}

func parseQuery(request *http.Request) (grants.Query, error) {
	values := request.URL.Query()
	if !validQueryKeys(values) || !singleValueQueryKeys(values) {
		return grants.Query{}, grants.ErrInvalidQuery
	}
	limit, err := parseLimit(values.Get("limit"))
	if err != nil {
		return grants.Query{}, err
	}
	query := grants.Query{StatusGroup: grants.StatusGroup(values.Get("status")), Client: values.Get("requester"), Operation: values.Get("operation"), Cursor: values.Get("cursor"), Limit: limit}
	query.Target, err = parseTargetFilter(values)
	return query, err
}

func validQueryKeys(values map[string][]string) bool {
	allowed := map[string]bool{"status": true, "requester": true, "operation": true, "target_kind": true, "cursor": true, "limit": true}
	for key := range values {
		if !allowed[key] && !strings.HasPrefix(key, "target.") {
			return false
		}
	}
	_, emptyTarget := values["target."]
	return !emptyTarget
}

func singleValueQueryKeys(values map[string][]string) bool {
	for _, key := range []string{"status", "requester", "operation", "target_kind", "cursor", "limit"} {
		if len(values[key]) > 1 {
			return false
		}
	}
	return true
}

func parseLimit(value string) (int, error) {
	if value == "" {
		return 0, nil
	}
	limit, err := strconv.Atoi(value)
	if err != nil {
		return 0, grants.ErrInvalidQuery
	}
	return limit, nil
}

func parseTargetFilter(values map[string][]string) (*policy.Target, error) {
	kind := policy.FirstValue(values["target_kind"])
	fields := targetFilterFields(values)
	if kind == "" {
		if len(fields) == 0 {
			return nil, nil
		}
		return nil, grants.ErrInvalidQuery
	}
	return &policy.Target{Kind: kind, Fields: fields}, nil
}

func targetFilterFields(values map[string][]string) map[string][]string {
	fields := make(map[string][]string)
	for key, list := range values {
		if strings.HasPrefix(key, "target.") && len(key) > len("target.") {
			fields[strings.TrimPrefix(key, "target.")] = append([]string(nil), list...)
		}
	}
	return fields
}

func validAction(action operatorv1.Action) bool {
	return action == operatorv1.ActionApprove || action == operatorv1.ActionDeny || action == operatorv1.ActionRevoke
}

func decodeStrictJSON(request *http.Request, target any) error {
	return httpx.DecodeJSON(request.Body, maxDecisionBodyBytes, target, true)
}

func (h *handler) writeMappedError(writer http.ResponseWriter, request *http.Request, err error) {
	h.writeMappedErrorWithCurrent(writer, request, err, grants.Grant{})
}

func (h *handler) writeDecisionError(writer http.ResponseWriter, request *http.Request, err error, currentGrant grants.Grant) {
	h.writeMappedErrorWithCurrent(writer, request, err, currentGrant)
}

func (h *handler) writeMappedErrorWithCurrent(writer http.ResponseWriter, request *http.Request, err error, currentGrant grants.Grant) {
	if h.writeRevisionConflict(writer, request, err) {
		return
	}
	status, code, message, retry := mappedErrorResponse(err)
	if retry {
		writer.Header().Set("Retry-After", "1")
	}
	h.writeError(writer, status, code, message, h.terminalFailureCurrent(request, err, currentGrant))
}

func (h *handler) writeRevisionConflict(writer http.ResponseWriter, request *http.Request, err error) bool {
	var conflict *grants.RevisionConflictError
	if !errors.As(err, &conflict) {
		return false
	}
	item, getErr := h.inbox.Get(request.Context(), conflict.Current.ID)
	var current *operatorwire.BrokerRequest
	if getErr == nil {
		projected := project(item)
		current = &projected
	}
	h.writeError(writer, http.StatusConflict, "revision_conflict", "request changed; refresh before deciding", current)
	return true
}

func (h *handler) terminalFailureCurrent(request *http.Request, err error, currentGrant grants.Grant) *operatorwire.BrokerRequest {
	failure, ok := activation.As(err)
	if !ok || failure.Retryable || currentGrant.ID == "" {
		return nil
	}
	projected := project(h.inbox.Project(request.Context(), currentGrant))
	return &projected
}

func mappedErrorResponse(err error) (int, string, string, bool) {
	code := errorCode(err)
	switch code {
	case "not_found":
		return http.StatusNotFound, code, "request not found", false
	case "invalid_request":
		return http.StatusBadRequest, code, "request is invalid", false
	case "cursor_expired":
		return http.StatusGone, code, "cursor is no longer retained", false
	case "idempotency_conflict", "invalid_transition", "invalid_decision_token", "constraint_exceeded",
		"invalid_notification", "plan_unavailable", "plan_mismatch", "credential_changed", "credential_insufficient":
		return http.StatusConflict, code, strings.ReplaceAll(code, "_", " "), false
	case "storage_unavailable", "temporarily_unavailable":
		return http.StatusServiceUnavailable, code, "operator request temporarily unavailable", true
	default:
		return http.StatusInternalServerError, code, "operator request failed", false
	}
}

func errorCode(err error) string {
	if failure, ok := activation.As(err); ok {
		return string(failure.Code)
	}
	classifications := []struct {
		code   string
		errors []error
	}{
		{"not_found", []error{grants.ErrNotFound}},
		{"invalid_request", []error{grants.ErrInvalidCursor, grants.ErrInvalidGrantCursor, grants.ErrInvalidQuery, grants.ErrInvalidCommand}},
		{"cursor_expired", []error{grants.ErrCursorExpired}},
		{"idempotency_conflict", []error{grants.ErrIdempotencyConflict}},
		{"invalid_decision_token", []error{grants.ErrInvalidDecisionToken}},
		{"constraint_exceeded", []error{grants.ErrConstraintExceeded}},
		{"invalid_transition", []error{grants.ErrInvalidTransition, grants.ErrNotPending, grants.ErrNotActive}},
	}
	for _, classification := range classifications {
		for _, candidate := range classification.errors {
			if errors.Is(err, candidate) {
				return classification.code
			}
		}
	}
	return "internal_error"
}

func (h *handler) writeError(writer http.ResponseWriter, status int, code, message string, current *operatorwire.BrokerRequest) {
	h.writeJSON(writer, status, operatorwire.ErrorEnvelope{Error: operatorwire.Error{Code: operatorwire.ErrorCode(code), Message: message,
		CorrelationId: writer.Header().Get("X-Correlation-ID"), Current: current}})
}

func (h *handler) writeJSON(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(value)
}

func secureCorrelationID() (string, error) {
	data := make([]byte, 16)
	if _, err := rand.Read(data); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(data), nil
}
