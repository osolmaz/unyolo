// Package operatorapi exposes the Brokerkit operator inbox over protected HTTP.
package operatorapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/osolmaz/brokerkit/audit"
	"github.com/osolmaz/brokerkit/grants"
	"github.com/osolmaz/brokerkit/operatorinbox"
	"github.com/osolmaz/brokerkit/policy"
)

const maxDecisionBodyBytes = 16 * 1024

// Authorizer authenticates one operator and returns the audit identity.
type Authorizer func(*http.Request) (string, error)

// Options configures the shared operator-only handler.
type Options struct {
	Inbox     *operatorinbox.Service
	Authorize Authorizer
	Broker    string
	Audit     AuditRecorder
}

// AuditRecorder receives secret-safe shared audit events.
type AuditRecorder interface {
	Record(audit.Event) error
}

type handler struct {
	inbox     *operatorinbox.Service
	authorize Authorizer
	broker    string
	audit     AuditRecorder
}

type decisionBody struct {
	ExpectedRevision int64         `json:"expected_revision"`
	ExpectedStatus   grants.Status `json:"expected_status,omitempty"`
	Reason           string        `json:"reason,omitempty"`
	DurationSeconds  int64         `json:"duration_seconds,omitempty"`
	MaxUses          int           `json:"max_uses,omitempty"`
}

type errorEnvelope struct {
	Error apiError `json:"error"`
}

type apiError struct {
	Code    string              `json:"code"`
	Message string              `json:"message"`
	Current *operatorinbox.Item `json:"current,omitempty"`
}

// New constructs a fail-closed operator handler.
func New(options Options) (http.Handler, error) {
	if options.Inbox == nil {
		return nil, errors.New("operator inbox is required")
	}
	if options.Authorize == nil {
		return nil, errors.New("operator authorizer is required")
	}
	if strings.TrimSpace(options.Broker) == "" {
		return nil, errors.New("broker name is required")
	}
	if options.Audit == nil {
		return nil, errors.New("operator audit recorder is required")
	}
	return &handler{inbox: options.Inbox, authorize: options.Authorize, broker: options.Broker, audit: options.Audit}, nil
}

func (h *handler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	approver, err := h.authorize(request)
	if err != nil || strings.TrimSpace(approver) == "" {
		_ = h.audit.Record(audit.Event{Broker: h.broker, Decision: "operator_auth", ErrorCode: "unauthorized"})
		writer.Header().Set("WWW-Authenticate", `Bearer realm="broker-operator"`)
		h.writeError(writer, http.StatusUnauthorized, "unauthorized", "operator authentication required", nil)
		return
	}
	path := strings.TrimSuffix(request.URL.Path, "/")
	if path == "/api/grants" {
		if request.Method != http.MethodGet {
			h.methodNotAllowed(writer, http.MethodGet)
			return
		}
		h.list(writer, request)
		return
	}
	if path == "/api/grants/events" {
		if request.Method != http.MethodGet {
			h.methodNotAllowed(writer, http.MethodGet)
			return
		}
		h.events(writer, request)
		return
	}
	h.serveGrantPath(writer, request, path, approver)
}

func (h *handler) serveGrantPath(writer http.ResponseWriter, request *http.Request, path string, approver string) {
	id, action, ok := parseGrantPath(path)
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
	h.decide(writer, request, id, action, approver)
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
	h.writeJSON(writer, http.StatusOK, page)
}

func (h *handler) detail(writer http.ResponseWriter, request *http.Request, id string) {
	item, err := h.inbox.Get(request.Context(), id)
	if err != nil {
		h.writeMappedError(writer, request, err)
		return
	}
	h.writeJSON(writer, http.StatusOK, item)
}

func (h *handler) decide(writer http.ResponseWriter, request *http.Request, id string, action string, approver string) {
	body, ok := h.readDecisionBody(writer, request)
	if !ok {
		return
	}
	command := grants.DecisionCommand{
		ID: id, Approver: approver, ExpectedRevision: body.ExpectedRevision,
		ExpectedStatus: body.ExpectedStatus, Reason: body.Reason,
	}
	previous, _ := h.inbox.Get(request.Context(), id)
	grant, err := h.executeDecision(action, command, body)
	if errors.Is(err, errUnknownAction) {
		h.writeError(writer, http.StatusNotFound, "not_found", "route not found", nil)
		return
	}
	if err != nil {
		if auditErr := h.recordDecisionAudit(action, approver, body, previous, nil, err); auditErr != nil {
			h.writeError(writer, http.StatusInternalServerError, "audit_failed", "operator audit recording failed", nil)
			return
		}
		h.writeMappedError(writer, request, err)
		return
	}
	item := h.inbox.Project(request.Context(), grant)
	if err := h.recordDecisionAudit(action, approver, body, previous, &item, nil); err != nil {
		writer.Header().Set("X-Broker-Audit-Export", "failed")
	}
	h.writeJSON(writer, http.StatusOK, item)
}

var errUnknownAction = errors.New("unknown operator action")

func (h *handler) readDecisionBody(writer http.ResponseWriter, request *http.Request) (decisionBody, bool) {
	mediaType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		h.writeError(writer, http.StatusUnsupportedMediaType, "unsupported_media_type", "content type must be application/json", nil)
		return decisionBody{}, false
	}
	var body decisionBody
	if err := decodeStrictJSON(writer, request, &body); err != nil {
		h.writeError(writer, http.StatusBadRequest, "invalid_body", "request body is invalid", nil)
		return decisionBody{}, false
	}
	return body, true
}

func (h *handler) executeDecision(action string, command grants.DecisionCommand, body decisionBody) (grants.Grant, error) {
	switch action {
	case "approve":
		if body.DurationSeconds < 0 || body.DurationSeconds > math.MaxInt64/int64(time.Second) {
			return grants.Grant{}, grants.ErrInvalidCommand
		}
		return h.inbox.Store().OperatorApprove(grants.ApproveCommand{
			DecisionCommand: command, Duration: time.Duration(body.DurationSeconds) * time.Second, MaxUses: body.MaxUses,
		})
	case "deny":
		return h.inbox.Store().OperatorDeny(command)
	case "cancel":
		return h.inbox.Store().OperatorCancel(command)
	case "revoke":
		return h.inbox.Store().OperatorRevoke(command)
	default:
		return grants.Grant{}, errUnknownAction
	}
}

func (h *handler) recordDecisionAudit(action string, approver string, body decisionBody, previous operatorinbox.Item, current *operatorinbox.Item, decisionErr error) error {
	event := audit.Event{
		Broker: h.broker, Client: previous.Client, Operation: previous.Operation,
		Decision: action, Reason: body.Reason, GrantID: previous.ID, Approver: approver,
		Extensions: map[string]string{
			"expected_revision": strconv.FormatInt(body.ExpectedRevision, 10),
			"previous_status":   string(previous.Status),
			"previous_revision": strconv.FormatInt(previous.Revision, 10),
		},
	}
	if current != nil {
		event.Extensions["next_status"] = string(current.Status)
		event.Extensions["actual_revision"] = strconv.FormatInt(current.Revision, 10)
		if latest, err := h.inbox.Store().LatestEvent(current.ID); err == nil {
			event.Extensions["event_cursor"] = latest.Cursor
		}
	}
	var conflict *grants.RevisionConflictError
	if errors.As(decisionErr, &conflict) {
		event.ErrorCode = "revision_conflict"
		event.Extensions["next_status"] = string(conflict.Current.Status)
		event.Extensions["actual_revision"] = strconv.FormatInt(conflict.Current.Revision, 10)
	} else if decisionErr != nil {
		event.ErrorCode = "decision_failed"
	}
	return h.audit.Record(event)
}

func (h *handler) events(writer http.ResponseWriter, request *http.Request) {
	flusher, ok := writer.(http.Flusher)
	if !ok {
		h.writeError(writer, http.StatusInternalServerError, "stream_unavailable", "event streaming is unavailable", nil)
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
		var writeErr error
		cursor, writeErr = writeEventPage(writer, page, cursor)
		if writeErr != nil {
			return
		}
		flusher.Flush()
		page, err = h.nextEventPage(request, cursor, page.HasMore)
		if err != nil {
			return
		}
	}
}

func (h *handler) nextEventPage(request *http.Request, cursor string, hasMore bool) (grants.EventPage, error) {
	if hasMore {
		return h.inbox.Store().EventsAfter(cursor, 100)
	}
	return h.inbox.Store().WaitForEvents(request.Context(), cursor)
}

func writeEventPage(writer io.Writer, page grants.EventPage, cursor string) (string, error) {
	for _, event := range page.Events {
		data, err := json.Marshal(event)
		if err != nil {
			return cursor, err
		}
		if _, err := fmt.Fprintf(writer, "id: %s\nevent: %s\ndata: %s\n\n", event.Cursor, event.Kind, data); err != nil {
			return cursor, err
		}
		cursor = event.Cursor
	}
	return cursor, nil
}

func parseQuery(request *http.Request) (grants.Query, error) {
	values := request.URL.Query()
	limit, err := parseLimit(values.Get("limit"))
	if err != nil {
		return grants.Query{}, err
	}
	query := grants.Query{
		StatusGroup: grants.StatusGroup(values.Get("status")), Client: values.Get("client"),
		Operation: values.Get("operation"), Cursor: values.Get("cursor"), Limit: limit,
	}
	target, err := parseTargetFilter(values)
	if err != nil {
		return grants.Query{}, err
	}
	query.Target = target
	return query, nil
}

func parseLimit(value string) (int, error) {
	if value == "" {
		return 0, nil
	}
	limit, err := strconv.Atoi(value)
	if err != nil {
		return 0, fmt.Errorf("%w: invalid limit", grants.ErrInvalidQuery)
	}
	return limit, nil
}

func parseTargetFilter(values map[string][]string) (*policy.Target, error) {
	targetKind := policy.FirstValue(values["target_kind"])
	fields := make(map[string][]string)
	for key, list := range values {
		if strings.HasPrefix(key, "target.") && len(key) > len("target.") {
			fields[strings.TrimPrefix(key, "target.")] = append([]string(nil), list...)
		}
	}
	if targetKind != "" || len(fields) > 0 {
		if targetKind == "" {
			return nil, fmt.Errorf("%w: target_kind is required with target fields", grants.ErrInvalidQuery)
		}
		return &policy.Target{Kind: targetKind, Fields: fields}, nil
	}
	return nil, nil
}

func parseGrantPath(path string) (string, string, bool) {
	remainder, ok := strings.CutPrefix(path, "/api/grants/")
	if !ok || remainder == "" {
		return "", "", false
	}
	parts := strings.Split(remainder, "/")
	if len(parts) == 1 && parts[0] != "" {
		return parts[0], "", true
	}
	if len(parts) == 2 && parts[0] != "" && parts[1] != "" {
		return parts[0], parts[1], true
	}
	return "", "", false
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
		item := h.inboxItemOrNil(request, conflict.Current.ID)
		h.writeError(writer, http.StatusConflict, "revision_conflict", "request changed; refresh and retry", item)
		return
	}
	switch {
	case errors.Is(err, grants.ErrNotFound):
		h.writeError(writer, http.StatusNotFound, "not_found", "grant not found", nil)
	case errors.Is(err, grants.ErrInvalidCursor), errors.Is(err, grants.ErrInvalidGrantCursor):
		h.writeError(writer, http.StatusBadRequest, "invalid_cursor", "cursor is invalid", nil)
	case errors.Is(err, grants.ErrInvalidQuery):
		h.writeError(writer, http.StatusBadRequest, "invalid_query", "grant query is invalid", nil)
	case errors.Is(err, grants.ErrCursorExpired):
		h.writeError(writer, http.StatusGone, "cursor_expired", "cursor is no longer retained", nil)
	case errors.Is(err, grants.ErrInvalidCommand):
		h.writeError(writer, http.StatusBadRequest, "invalid_command", "decision command is invalid", nil)
	case errors.Is(err, grants.ErrNotPending), errors.Is(err, grants.ErrNotActive):
		h.writeError(writer, http.StatusConflict, "invalid_state", "grant is not in the required state", nil)
	default:
		h.writeError(writer, http.StatusInternalServerError, "internal_error", "operator request failed", nil)
	}
}

func (h *handler) inboxItemOrNil(request *http.Request, id string) *operatorinbox.Item {
	item, err := h.inbox.Get(request.Context(), id)
	if err != nil {
		return nil
	}
	return &item
}

func (h *handler) methodNotAllowed(writer http.ResponseWriter, allowed string) {
	writer.Header().Set("Allow", allowed)
	h.writeError(writer, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed", nil)
}

func (h *handler) writeError(writer http.ResponseWriter, status int, code string, message string, current *operatorinbox.Item) {
	h.writeJSON(writer, status, errorEnvelope{Error: apiError{Code: code, Message: message, Current: current}})
}

func (h *handler) writeJSON(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(value)
}
