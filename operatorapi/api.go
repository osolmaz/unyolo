// Package operatorapi exposes BrokerKit Operator V1 over protected HTTP.
package operatorapi

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/osolmaz/brokerkit/audit"
	"github.com/osolmaz/brokerkit/decision"
	"github.com/osolmaz/brokerkit/grants"
	"github.com/osolmaz/brokerkit/operatorinbox"
	"github.com/osolmaz/brokerkit/operatorv1"
	"github.com/osolmaz/brokerkit/policy"
)

const (
	maxDecisionBodyBytes = 16 * 1024
	eventHeartbeat       = 15 * time.Second
	requestPrefix        = "/api/operator/v1/requests/"
)

type Authorizer func(*http.Request) (string, error)

type AuditRecorder interface {
	Record(audit.Event) error
}

type Options struct {
	Inbox     *operatorinbox.Service
	Decisions *decision.Service
	Authorize Authorizer
	Broker    string
	Audit     AuditRecorder
}

type handler struct {
	inbox     *operatorinbox.Service
	decisions *decision.Service
	authorize Authorizer
	broker    string
	audit     AuditRecorder
}

func New(options Options) (http.Handler, error) {
	if err := validateOptions(options); err != nil {
		return nil, err
	}
	return &handler{options.Inbox, options.Decisions, options.Authorize, options.Broker, options.Audit}, nil
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

func (h *handler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	writer.Header().Set("X-Correlation-ID", correlationID())
	path := strings.TrimSuffix(request.URL.Path, "/")
	if path == "/healthz" || path == "/readyz" {
		h.status(writer, request)
		return
	}
	actor, ok := h.authenticate(writer, request)
	if !ok {
		return
	}
	h.serveAuthorized(writer, request, path, actor)
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

func (h *handler) serveAuthorized(writer http.ResponseWriter, request *http.Request, path string, actor string) {
	switch path {
	case "/.well-known/brokerkit-operator":
		if h.requireMethod(writer, request, http.MethodGet) {
			h.writeJSON(writer, http.StatusOK, operatorv1.Descriptor{APIVersion: operatorv1.APIVersion})
		}
	case "/api/operator/v1/requests":
		if h.requireMethod(writer, request, http.MethodGet) {
			h.list(writer, request)
		}
	case "/api/operator/v1/events":
		if h.requireMethod(writer, request, http.MethodGet) {
			h.events(writer, request)
		}
	default:
		h.requestPath(writer, request, path, actor)
	}
}

func (h *handler) requireMethod(writer http.ResponseWriter, request *http.Request, method string) bool {
	if request.Method == method {
		return true
	}
	h.methodNotAllowed(writer, method)
	return false
}

func (h *handler) status(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		h.methodNotAllowed(writer, http.MethodGet)
		return
	}
	if strings.TrimSuffix(request.URL.Path, "/") == "/readyz" {
		if _, err := h.inbox.Store().QueryGrants(grants.Query{Limit: 1}); err != nil {
			h.writeError(writer, http.StatusServiceUnavailable, "temporarily_unavailable", "operator source is not ready", nil)
			return
		}
	}
	h.writeJSON(writer, http.StatusOK, map[string]string{"status": "ok"})
}

func (h *handler) requestPath(writer http.ResponseWriter, request *http.Request, path, actor string) {
	id, action, ok := parseRequestPath(path)
	if !ok {
		h.writeError(writer, http.StatusNotFound, "not_found", "route not found", nil)
		return
	}
	if action == "" {
		if request.Method != http.MethodGet {
			h.methodNotAllowed(writer, http.MethodGet)
			return
		}
		h.detail(writer, request, id)
		return
	}
	if request.Method != http.MethodPost {
		h.methodNotAllowed(writer, http.MethodPost)
		return
	}
	h.decide(writer, request, id, operatorv1.Action(action), actor)
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
	out := operatorv1.Page{Requests: make([]operatorv1.Request, 0, len(page.Items)), NextCursor: page.NextCursor, EventCursor: page.EventCursor}
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
	result, err := h.decisions.Decide(request.Context(), id, action, actor, command)
	if err != nil {
		h.writeMappedError(writer, request, err)
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
	if err := decodeStrictJSON(writer, request, command); err != nil {
		h.writeError(writer, http.StatusBadRequest, "invalid_request", "decision body is invalid", nil)
		return false
	}
	return true
}

func project(item operatorinbox.Item) operatorv1.Request {
	facts := make([]operatorv1.Fact, 0, len(item.Presentation.Fields))
	for _, fact := range item.Presentation.Fields {
		facts = append(facts, operatorv1.Fact{Label: fact.Label, Value: fact.Value})
	}
	request := operatorv1.Request{
		ID: item.ID, Revision: item.Revision, Requester: item.Client, Operation: item.Operation, Status: item.Status,
		RequestedAt: item.RequestedAt, RequestedDurationSeconds: item.RequestedDurationSeconds,
		RequestedMaxUses: item.RequestedMaxUses, UsedCount: item.UsedCount, RequestReason: item.Reason,
		DecidedAt: item.DecidedAt, DecidedBy: item.DecidedBy, DecidedOnBehalfOf: item.DecidedOnBehalfOf,
		DecisionReason: item.DecisionReason, PresentationUnavailable: item.PresentationUnavailable,
		Presentation:   operatorv1.Presentation{Risk: string(item.Presentation.Risk), Title: item.Presentation.Title, Summary: item.Presentation.Summary, Facts: facts},
		AllowedActions: allowedActions(item),
	}
	if item.Status == grants.StatusPending {
		expires := item.PendingExpiresAt
		request.PendingExpiresAt = &expires
		request.ApprovalBounds = &operatorv1.ApprovalBounds{MaxDurationSeconds: item.RequestedDurationSeconds, MaxUses: item.RequestedMaxUses}
	}
	if item.ActiveExpiresAt != nil {
		request.ActiveExpiresAt = item.ActiveExpiresAt
		granted := item.MaxUses
		request.GrantedMaxUses = &granted
	}
	return request
}

func allowedActions(item operatorinbox.Item) []operatorv1.Action {
	switch item.Status {
	case grants.StatusPending:
		return []operatorv1.Action{operatorv1.ActionApprove, operatorv1.ActionDeny, operatorv1.ActionCancel}
	case grants.StatusActive:
		return []operatorv1.Action{operatorv1.ActionRevoke}
	default:
		return []operatorv1.Action{}
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

func publicEvent(event grants.Event) (operatorv1.Event, bool) {
	kind, visible := publicEventKind(event)
	if !visible {
		return operatorv1.Event{}, false
	}
	return operatorv1.Event{Cursor: event.Cursor, Kind: kind, RequestID: event.GrantID,
		Revision: event.Revision, Status: event.Status, OccurredAt: event.Time, UsedCount: event.UsedCount}, true
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

func parseRequestPath(path string) (string, string, bool) {
	remainder, ok := strings.CutPrefix(path, requestPrefix)
	if !ok || remainder == "" {
		return "", "", false
	}
	parts := strings.Split(remainder, "/")
	switch len(parts) {
	case 1:
		return parts[0], "", validPathPart(parts[0])
	case 2:
		return parts[0], parts[1], validPathPart(parts[0]) && validPathPart(parts[1])
	default:
		return "", "", false
	}
}

func validPathPart(value string) bool { return value != "" }

func validAction(action operatorv1.Action) bool {
	return action == operatorv1.ActionApprove || action == operatorv1.ActionDeny || action == operatorv1.ActionCancel || action == operatorv1.ActionRevoke
}

func decodeStrictJSON(writer http.ResponseWriter, request *http.Request, target any) error {
	request.Body = http.MaxBytesReader(writer, request.Body, maxDecisionBodyBytes)
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("trailing request data")
	}
	return nil
}

func (h *handler) writeMappedError(writer http.ResponseWriter, request *http.Request, err error) {
	var conflict *grants.RevisionConflictError
	if errors.As(err, &conflict) {
		item, getErr := h.inbox.Get(request.Context(), conflict.Current.ID)
		var current *operatorv1.Request
		if getErr == nil {
			projected := project(item)
			current = &projected
		}
		h.writeError(writer, http.StatusConflict, "revision_conflict", "request changed; refresh before deciding", current)
		return
	}
	status, code, message := http.StatusInternalServerError, errorCode(err), "operator request failed"
	switch code {
	case "not_found":
		status, message = http.StatusNotFound, "request not found"
	case "invalid_request":
		status, message = http.StatusBadRequest, "request is invalid"
	case "cursor_expired":
		status, message = http.StatusGone, "cursor is no longer retained"
	case "idempotency_conflict", "invalid_transition", "constraint_exceeded":
		status, message = http.StatusConflict, strings.ReplaceAll(code, "_", " ")
	}
	h.writeError(writer, status, code, message, nil)
}

func errorCode(err error) string {
	classifications := []struct {
		code   string
		errors []error
	}{
		{"not_found", []error{grants.ErrNotFound}},
		{"invalid_request", []error{grants.ErrInvalidCursor, grants.ErrInvalidGrantCursor, grants.ErrInvalidQuery, grants.ErrInvalidCommand}},
		{"cursor_expired", []error{grants.ErrCursorExpired}},
		{"idempotency_conflict", []error{grants.ErrIdempotencyConflict}},
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

func (h *handler) methodNotAllowed(writer http.ResponseWriter, allowed string) {
	writer.Header().Set("Allow", allowed)
	h.writeError(writer, http.StatusMethodNotAllowed, "invalid_request", "method not allowed", nil)
}

func (h *handler) writeError(writer http.ResponseWriter, status int, code, message string, current *operatorv1.Request) {
	h.writeJSON(writer, status, operatorv1.ErrorEnvelope{Error: operatorv1.Error{Code: code, Message: message, CorrelationID: writer.Header().Get("X-Correlation-ID"), Current: current}})
}

func (h *handler) writeJSON(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(value)
}

func correlationID() string {
	data := make([]byte, 16)
	if _, err := rand.Read(data); err != nil {
		return strconv.FormatInt(time.Now().UnixNano(), 36)
	}
	return base64.RawURLEncoding.EncodeToString(data)
}
