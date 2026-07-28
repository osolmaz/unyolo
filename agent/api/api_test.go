package agentapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/osolmaz/unyolo/agent/runtime"
	"github.com/osolmaz/unyolo/agent/v1"
	unyoloauth "github.com/osolmaz/unyolo/auth"
)

const (
	discoveryPath  = "/.well-known/unyolo-agent"
	operationsPath = "/api/agent/v1/operations"
)

type fakeStore struct {
	operation agentv1.Operation
	getErr    error
	waitErr   error
	waitAfter int64
}

func (s *fakeStore) List(clientID string, options agentv1.ListOptions) (agentv1.OperationPage, error) {
	if s.getErr != nil {
		return agentv1.OperationPage{}, s.getErr
	}
	if clientID != "agent" {
		return agentv1.OperationPage{}, agentops.ErrNotFound
	}
	summary := agentv1.OperationSummary{
		APIVersion: agentv1.APIVersion, ID: s.operation.ID, Broker: s.operation.Broker, ClientID: clientID,
		IdempotencyKey: s.operation.IdempotencyKey, Operation: s.operation.Operation, State: s.operation.State,
		Revision: s.operation.Revision, CreatedAt: s.operation.CreatedAt, UpdatedAt: s.operation.UpdatedAt,
		Presentation: s.operation.Presentation,
	}
	return agentv1.OperationPage{APIVersion: agentv1.APIVersion, Operations: []agentv1.OperationSummary{summary}}, nil
}

func (s *fakeStore) Get(clientID, id string) (agentv1.Operation, error) {
	if s.getErr != nil {
		return agentv1.Operation{}, s.getErr
	}
	if clientID != "agent" || id != s.operation.ID {
		return agentv1.Operation{}, agentops.ErrNotFound
	}
	return s.operation, nil
}

func (s *fakeStore) Wait(_ context.Context, clientID, id string, after int64) (agentv1.Operation, error) {
	s.waitAfter = after
	if s.waitErr != nil {
		return agentv1.Operation{}, s.waitErr
	}
	return s.Get(clientID, id)
}

func (s *fakeStore) Cancel(clientID, id string) (agentv1.Operation, error) {
	if s.getErr != nil {
		return agentv1.Operation{}, s.getErr
	}
	if clientID != "agent" || id != s.operation.ID {
		return agentv1.Operation{}, agentops.ErrNotFound
	}
	s.operation.State = agentv1.StateCanceled
	return s.operation, nil
}

func TestNewRequiresDependencies(t *testing.T) {
	for _, options := range []Options{
		{},
		{Store: &fakeStore{}},
		{Store: &fakeStore{}, Authenticate: func(string) (string, error) { return "", nil }},
	} {
		if _, err := New(options); err == nil {
			t.Fatal("New accepted missing dependency")
		}
	}
}

func TestAuthenticationAndDiscovery(t *testing.T) {
	failures := 0
	server := newTestServer(t, &fakeStore{}, func(header string) (string, error) {
		switch header {
		case "Bearer good":
			return "agent", nil
		case "":
			return "", unyoloauth.ErrMissing
		default:
			return "", errors.New("invalid token")
		}
	}, func(context.Context, string, agentv1.SubmitRequest) (agentv1.Operation, bool, error) {
		return agentv1.Operation{}, false, nil
	}, func() { failures++ })
	defer server.Close()

	response, body := request(t, server, http.MethodGet, discoveryPath, "", nil)
	if response.StatusCode != http.StatusUnauthorized || response.Header.Get("WWW-Authenticate") != `Bearer realm="test-broker"` || !strings.Contains(body, "authentication_failed") {
		t.Fatalf("missing auth = %d %q %s", response.StatusCode, response.Header.Get("WWW-Authenticate"), body)
	}
	response, _ = request(t, server, http.MethodGet, discoveryPath, "Bearer bad", nil)
	if response.StatusCode != http.StatusForbidden || response.Header.Get("WWW-Authenticate") != "" {
		t.Fatalf("bad auth = %d %q", response.StatusCode, response.Header.Get("WWW-Authenticate"))
	}
	response, body = request(t, server, http.MethodGet, discoveryPath, "Bearer good", nil)
	if response.StatusCode != http.StatusOK || !strings.Contains(body, agentv1.APIVersion) || failures != 2 {
		t.Fatalf("discovery = %d %s, failures = %d", response.StatusCode, body, failures)
	}
}

func TestSubmitStrictBoundaryAndErrors(t *testing.T) {
	store := &fakeStore{}
	calls := 0
	submit := func(_ context.Context, client string, request agentv1.SubmitRequest) (agentv1.Operation, bool, error) {
		calls++
		if client != "agent" || request.Operation != "repo.create" {
			t.Fatalf("submit = %q %#v", client, request)
		}
		switch request.IdempotencyKey {
		case "conflict":
			return agentv1.Operation{}, false, agentops.ErrIdempotencyConflict
		case "provider":
			return agentv1.Operation{}, false, &Error{Status: http.StatusBadRequest, Code: "unsupported_operation", Message: "Unsupported"}
		case "failure":
			return agentv1.Operation{}, false, errors.New("database secret")
		case "limited":
			return agentv1.Operation{}, false, &Error{Status: http.StatusTooManyRequests, Code: "client_operation_limit", Message: "Operation admission limit reached", RetryAfterSeconds: 7}
		default:
			return validOperation("op/one", agentv1.StatePending), true, nil
		}
	}
	server := newTestServer(t, store, allowAuth, submit, nil)
	defer server.Close()

	valid := `{"idempotency_key":"one","operation":"repo.create","target":{},"arguments":{},"reason":"test"}`
	response, body := request(t, server, http.MethodPost, operationsPath, "Bearer good", strings.NewReader(valid))
	if response.StatusCode != http.StatusAccepted || response.Header.Get("Location") != operationsPath+"/op%2Fone" || response.Header.Get("Retry-After") != "2" || !strings.Contains(body, `"id":"op/one"`) {
		t.Fatalf("submit = %d %#v %s", response.StatusCode, response.Header, body)
	}

	invalid := []string{
		`{"idempotency_key":"one","operation":"repo.create","operation":"repo.create","target":{},"arguments":{},"reason":"test"}`,
		valid + `{}`,
		`{"idempotency_key":"","operation":"repo.create","target":{},"arguments":{},"reason":"test"}`,
		`{"idempotency_key":"bad value","operation":"repo.create","target":{},"arguments":{},"reason":"test"}`,
		`{"idempotency_key":"one","operation":"repo.create","target":{},"arguments":{},"reason":""}`,
		`{"idempotency_key":"one","operation":"repo.create","target":{},"arguments":{},"reason":"test","unknown":true}`,
	}
	for _, body := range invalid {
		response, text := request(t, server, http.MethodPost, operationsPath, "Bearer good", strings.NewReader(body))
		if response.StatusCode != http.StatusBadRequest || !strings.Contains(text, "invalid_request") {
			t.Fatalf("invalid submit = %d %s", response.StatusCode, text)
		}
	}
	response, _ = request(t, server, http.MethodPost, operationsPath, "Bearer good", strings.NewReader(strings.Repeat(" ", maxSubmitBytes+1)))
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("oversized submit = %d", response.StatusCode)
	}

	for key, want := range map[string]int{"conflict": http.StatusConflict, "provider": http.StatusBadRequest, "failure": http.StatusInternalServerError, "limited": http.StatusTooManyRequests} {
		body := strings.Replace(valid, `"one"`, `"`+key+`"`, 1)
		response, text := request(t, server, http.MethodPost, operationsPath, "Bearer good", strings.NewReader(body))
		if response.StatusCode != want || strings.Contains(text, "database secret") {
			t.Fatalf("%s = %d %s", key, response.StatusCode, text)
		}
		if key == "limited" && response.Header.Get("Retry-After") != "7" {
			t.Fatalf("limited Retry-After = %q", response.Header.Get("Retry-After"))
		}
	}
	if calls != 5 {
		t.Fatalf("submit calls = %d, want 5", calls)
	}
}

func TestGetWaitAndStoreErrors(t *testing.T) {
	store := &fakeStore{operation: validOperation("op", agentv1.StateSucceeded)}
	server := newTestServer(t, store, allowAuth, func(context.Context, string, agentv1.SubmitRequest) (agentv1.Operation, bool, error) {
		return agentv1.Operation{}, false, nil
	}, nil)
	defer server.Close()

	response, body := request(t, server, http.MethodGet, operationsPath+"/op", "Bearer good", nil)
	if response.StatusCode != http.StatusOK || !strings.Contains(body, `"state":"succeeded"`) || response.Header.Get("Location") != "" {
		t.Fatalf("get = %d %#v %s", response.StatusCode, response.Header, body)
	}
	response, _ = request(t, server, http.MethodGet, operationsPath+"/op/events?after_revision=7&wait_seconds=0", "Bearer good", nil)
	if response.StatusCode != http.StatusOK || store.waitAfter != 7 {
		t.Fatalf("wait = %d, after = %d", response.StatusCode, store.waitAfter)
	}
	for _, query := range []string{"after_revision=-1", "wait_seconds=-1", "wait_seconds=31", "after_revision=nope"} {
		response, _ = request(t, server, http.MethodGet, operationsPath+"/op/events?"+query, "Bearer good", nil)
		if response.StatusCode != http.StatusBadRequest {
			t.Fatalf("invalid query %q = %d", query, response.StatusCode)
		}
	}

	store.getErr = agentops.ErrNotFound
	response, body = request(t, server, http.MethodGet, operationsPath+"/missing", "Bearer good", nil)
	if response.StatusCode != http.StatusNotFound || !strings.Contains(body, "not_found") {
		t.Fatalf("not found = %d %s", response.StatusCode, body)
	}
	store.getErr = errors.New("database secret")
	response, body = request(t, server, http.MethodGet, operationsPath+"/op", "Bearer good", nil)
	if response.StatusCode != http.StatusInternalServerError || strings.Contains(body, "database secret") {
		t.Fatalf("store error = %d %s", response.StatusCode, body)
	}
	store.getErr = nil
	store.waitErr = errors.New("wait secret")
	response, body = request(t, server, http.MethodGet, operationsPath+"/op/events?wait_seconds=0", "Bearer good", nil)
	if response.StatusCode != http.StatusInternalServerError || strings.Contains(body, "wait secret") {
		t.Fatalf("wait error = %d %s", response.StatusCode, body)
	}
}

func TestListOperations(t *testing.T) {
	store := &fakeStore{operation: validOperation("op", agentv1.StatePending)}
	server := newTestServer(t, store, allowAuth, func(context.Context, string, agentv1.SubmitRequest) (agentv1.Operation, bool, error) {
		return agentv1.Operation{}, false, nil
	}, nil)
	defer server.Close()

	response, body := request(t, server, http.MethodGet, operationsPath+"?idempotency_key=one&state=pending&limit=1", "Bearer good", nil)
	if response.StatusCode != http.StatusOK || !strings.Contains(body, `"operations":[{"api_version":"unyolo.io/agent/v1"`) || !strings.Contains(body, `"next_cursor":null`) {
		t.Fatalf("list = %d %s", response.StatusCode, body)
	}
	for _, query := range []string{"limit=0", "limit=51", "limit=nope", "state=unknown", "cursor=", "idempotency_key=", "idempotency_key=bad%20value"} {
		response, body = request(t, server, http.MethodGet, operationsPath+"?"+query, "Bearer good", nil)
		if response.StatusCode != http.StatusBadRequest || !strings.Contains(body, "invalid_request") {
			t.Fatalf("invalid list %q = %d %s", query, response.StatusCode, body)
		}
	}
}

func TestCancelOperation(t *testing.T) {
	store := &fakeStore{operation: validOperation("op", agentv1.StatePending)}
	server := newTestServer(t, store, allowAuth, func(context.Context, string, agentv1.SubmitRequest) (agentv1.Operation, bool, error) {
		return agentv1.Operation{}, false, nil
	}, nil)
	defer server.Close()
	response, body := request(t, server, http.MethodPost, operationsPath+"/op/cancel", "Bearer good", nil)
	if response.StatusCode != http.StatusOK || !strings.Contains(body, `"state":"canceled"`) {
		t.Fatalf("cancel = %d %s", response.StatusCode, body)
	}
	store.getErr = agentops.ErrNotCancelable
	response, body = request(t, server, http.MethodPost, operationsPath+"/op/cancel", "Bearer good", nil)
	if response.StatusCode != http.StatusConflict || !strings.Contains(body, "operation_not_cancelable") {
		t.Fatalf("not cancelable = %d %s", response.StatusCode, body)
	}
}

func TestInvalidStoredOperationFailsClosed(t *testing.T) {
	store := &fakeStore{operation: validOperation("op", agentv1.StatePending)}
	store.operation.Target = json.RawMessage(`[]`)
	server := newTestServer(t, store, allowAuth, func(context.Context, string, agentv1.SubmitRequest) (agentv1.Operation, bool, error) {
		return agentv1.Operation{}, false, nil
	}, nil)
	defer server.Close()
	response, body := request(t, server, http.MethodGet, operationsPath+"/op", "Bearer good", nil)
	if response.StatusCode != http.StatusInternalServerError || !strings.Contains(body, "operation_store_unavailable") {
		t.Fatalf("invalid operation = %d %s", response.StatusCode, body)
	}
}

func newTestServer(t *testing.T, store Store, authenticate AuthenticateFunc, submit SubmitFunc, authFailure AuthFailureFunc) *httptest.Server {
	t.Helper()
	handler, err := New(Options{Store: store, Authenticate: authenticate, Submit: submit,
		Cancel: func(ctx context.Context, client, id string) (agentv1.Operation, error) {
			return store.Cancel(client, id)
		}, AuthFailure: authFailure, Realm: "test-broker"})
	if err != nil {
		t.Fatal(err)
	}
	router := echo.New()
	handler.Register(router)
	return httptest.NewServer(router)
}

func allowAuth(string) (string, error) { return "agent", nil }

func validOperation(id string, state agentv1.State) agentv1.Operation {
	now := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	operation := agentv1.Operation{
		APIVersion: agentv1.APIVersion, ID: id, Broker: "test-broker", ClientID: "agent", IdempotencyKey: "one",
		Operation: "repo.create", Target: json.RawMessage(`{}`), Arguments: json.RawMessage(`{}`), Reason: "test",
		State: state, Revision: 1, CreatedAt: now, UpdatedAt: now, Presentation: agentv1.Presentation{Title: "Create repository"},
	}
	if state.Terminal() {
		operation.TerminalAt = &now
	}
	return operation
}

func request(t *testing.T, server *httptest.Server, method, path, authorization string, body io.Reader) (*http.Response, string) {
	t.Helper()
	req, err := http.NewRequest(method, server.URL+path, body)
	if err != nil {
		t.Fatal(err)
	}
	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	response, err := server.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(response.Body)
	closeErr := response.Body.Close()
	if err := errors.Join(err, closeErr); err != nil {
		t.Fatal(err)
	}
	return response, string(data)
}
