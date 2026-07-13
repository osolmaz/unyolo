package httpapi

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/osolmaz/brokerkit/agentconformance"
	"github.com/osolmaz/brokerkit/agentv1"
	"github.com/osolmaz/brokerkit/audit"
	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/config"
	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/policy"
	bknotify "github.com/osolmaz/brokerkit/notify"
	"github.com/osolmaz/brokerkit/operatorv1"
)

const (
	agentDiscoveryPath  = "/.well-known/brokerkit-agent"
	agentOperationsPath = "/api/agent/v1/operations"
)

func TestAgentV1Conformance(t *testing.T) {
	var conformanceCreated atomic.Bool
	stateDir := filepath.Join(t.TempDir(), "state")
	policyJSON := `{"rules":[{"id":"create","effect":"request","clients":["agent"],"operations":["repo.create"],"targets":[{"kind":"repo","type":"dataset","owner":"alice","name":"conformance"}],"attrs":{"visibility":"private"},"grant_policy":{"mode":"execution","default_minutes":5,"max_minutes":5,"request_ttl_minutes":5,"default_max_uses":1,"max_uses":1}}]}`
	scope, err := policy.Parse([]byte(policyJSON))
	if err != nil {
		t.Fatal(err)
	}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/whoami-v2":
			writeJSON(w, http.StatusOK, map[string]string{"name": "alice"})
		case "/api/datasets/alice/conformance":
			if r.Method == http.MethodGet && conformanceCreated.Load() {
				writeJSON(w, http.StatusOK, map[string]any{"id": "alice/conformance", "sha": "created", "private": true})
				return
			}
			http.NotFound(w, r)
		case "/api/repos/create":
			conformanceCreated.Store(true)
			writeJSON(w, http.StatusCreated, map[string]any{})
		default:
			http.NotFound(w, r)
		}
	}))
	defer upstream.Close()

	var current *Server
	start := func() (agentconformance.Endpoint, error) {
		ctx, cancel := context.WithCancel(context.Background())
		handler, err := New(Options{Config: config.Config{
			HFToken: testToken, Clients: []config.Client{{Name: "agent", Secret: testSecret}},
			Operators: []config.Client{{Name: "operator", Secret: testOtherSecret}}, StateDir: stateDir,
			MaxPackBytes: 25 * 1024 * 1024, HFTimeout: 5 * time.Second,
		}, Scope: scope, Audit: audit.New(io.Discard), UpstreamBaseURL: upstream.URL, Context: ctx})
		if err != nil {
			cancel()
			return agentconformance.Endpoint{}, err
		}
		current = handler
		server := httptest.NewServer(handler)
		return agentconformance.Endpoint{BaseURL: server.URL, HTTPClient: server.Client(), Close: func() error {
			server.Close()
			cancel()
			handler.backgroundWorkers.Wait()
			return handler.database.Close()
		}}, nil
	}
	agentconformance.RunAgentV1(t, agentconformance.Fixture{
		Start: start, Token: testSecret, WaitTime: 5 * time.Second,
		Request: agentv1.SubmitRequest{
			IdempotencyKey: "hf-conformance", Operation: "repo.create",
			Target:    json.RawMessage(`{"kind":"repo","type":"dataset","owner":"alice","name":"conformance"}`),
			Arguments: json.RawMessage(`{"visibility":"private"}`), Reason: "verify Agent V1 lifecycle",
		},
		Approve: func(ctx context.Context, operation agentv1.Operation) error {
			grant, err := current.grants.Get(operation.ApprovalID)
			if err != nil {
				return err
			}
			_, err = current.control.Decisions.Decide(ctx, grant.ID, operatorv1.ActionApprove, "operator", operatorv1.Decision{
				ExpectedRevision: grant.Revision, IdempotencyKey: "approve-hf-conformance",
			})
			return err
		},
		Verify: func(t *testing.T, operation agentv1.Operation) {
			t.Helper()
			if operation.State != agentv1.StateSucceeded || !strings.Contains(string(operation.Result), `"repo_id":"alice/conformance"`) {
				t.Fatalf("terminal operation = %#v", operation)
			}
		},
	})
}

func TestAgentRepoCreateApprovalExecutesOnce(t *testing.T) {
	var mu sync.Mutex
	createHits := 0
	exists := false
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+testToken {
			t.Fatalf("upstream authorization was not the broker token")
		}
		switch r.URL.Path {
		case "/api/whoami-v2":
			writeJSON(w, http.StatusOK, map[string]string{"name": "alice"})
		case "/api/datasets/alice/data":
			mu.Lock()
			present := exists
			mu.Unlock()
			if !present {
				http.NotFound(w, r)
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{"id": "alice/data", "sha": "created", "private": true})
		case "/api/repos/create":
			mu.Lock()
			createHits++
			exists = true
			mu.Unlock()
			var payload map[string]any
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Fatal(err)
			}
			if payload["name"] != "data" || payload["organization"] != nil || payload["type"] != "dataset" || payload["visibility"] != "private" {
				t.Fatalf("create payload = %#v", payload)
			}
			writeJSON(w, http.StatusCreated, map[string]any{})
		default:
			http.NotFound(w, r)
		}
	}))
	defer upstream.Close()

	policyJSON := `{"rules":[{"id":"create","effect":"request","clients":["agent"],"operations":["repo.create"],"targets":[{"kind":"repo","type":"dataset","owner":"alice","name":"data"}],"attrs":{"visibility":"private"},"grant_policy":{"mode":"execution","default_minutes":5,"max_minutes":5,"request_ttl_minutes":5,"default_max_uses":1,"max_uses":1}}]}`
	server, handler, cancel := newAgentOperationTestServer(t, upstream.URL, policyJSON)
	defer cancel()
	defer server.Close()

	body := `{"idempotency_key":"create-data","operation":"repo.create","target":{"kind":"repo","type":"dataset","owner":"alice","name":"data"},"arguments":{"visibility":"private"},"reason":"create test data"}`
	response, text := doRequest(t, http.MethodPost, server.URL+agentOperationsPath, "Bearer "+testSecret, strings.NewReader(body))
	if response.StatusCode != http.StatusAccepted || strings.Contains(text, testToken) || strings.Contains(text, testSecret) {
		t.Fatalf("submit = %d %s", response.StatusCode, text)
	}
	var operation agentv1.Operation
	if err := json.Unmarshal([]byte(text), &operation); err != nil || operation.State != agentv1.StatePending || operation.ApprovalID == "" {
		t.Fatalf("operation = %#v, %v", operation, err)
	}
	grant, err := handler.grants.Get(operation.ApprovalID)
	if err != nil {
		t.Fatal(err)
	}
	_, err = handler.control.Decisions.Decide(context.Background(), grant.ID, operatorv1.ActionApprove, "alice", operatorv1.Decision{
		ExpectedRevision: grant.Revision, IdempotencyKey: "approve-create-data",
	})
	if err != nil {
		t.Fatal(err)
	}
	operation = waitForTestOperation(t, server.URL, operation.ID)
	if operation.State != agentv1.StateSucceeded || !strings.Contains(string(operation.Result), `"repo_id":"alice/data"`) {
		t.Fatalf("completed operation = %#v", operation)
	}
	response, replay := doRequest(t, http.MethodPost, server.URL+agentOperationsPath, "Bearer "+testSecret, strings.NewReader(body))
	if response.StatusCode != http.StatusOK {
		t.Fatalf("replay = %d %s", response.StatusCode, replay)
	}
	mu.Lock()
	defer mu.Unlock()
	if createHits != 1 {
		t.Fatalf("create hits = %d, want 1", createHits)
	}
}

func TestAgentRepoCreateSendsNotifierOnlyApproval(t *testing.T) {
	upstream := newAbsentRepoUpstream(t, "alice", "dataset", "data")
	defer upstream.Close()
	notifier := &bknotify.Memory{}
	server, handler, cancel := newAgentOperationTestServer(t, upstream.URL, `{"rules":[{"id":"create","effect":"request","clients":["agent"],"operations":["repo.create"],"targets":[{"kind":"repo","type":"dataset","owner":"alice","name":"data"}],"attrs":{"visibility":"private"},"grant_policy":{"mode":"execution","default_minutes":5,"max_minutes":5,"request_ttl_minutes":5,"default_max_uses":1,"max_uses":1}}]}`, notifier)
	defer cancel()
	defer server.Close()
	body := `{"idempotency_key":"notify","operation":"repo.create","target":{"kind":"repo","type":"dataset","owner":"alice","name":"data"},"arguments":{"visibility":"private"},"reason":"notify operator"}`
	response, text := doRequest(t, http.MethodPost, server.URL+agentOperationsPath, "Bearer "+testSecret, strings.NewReader(body))
	var operation agentv1.Operation
	if response.StatusCode != http.StatusAccepted || json.Unmarshal([]byte(text), &operation) != nil || len(notifier.Messages) != 1 {
		t.Fatalf("submit = %d %#v, notifications = %d", response.StatusCode, operation, len(notifier.Messages))
	}
	grant, err := handler.grants.Get(operation.ApprovalID)
	if err != nil || grant.Notification == nil {
		t.Fatalf("grant notification = %#v, %v", grant.Notification, err)
	}
}

func TestAgentRepoCreateApprovalOutlivesRequestContext(t *testing.T) {
	upstream := newAbsentRepoUpstream(t, "alice", "dataset", "data")
	defer upstream.Close()
	notifier := &contextCheckingNotifier{}
	server, handler, cancelServer := newAgentOperationTestServer(t, upstream.URL, `{"rules":[{"id":"create","effect":"request","clients":["agent"],"operations":["repo.create"],"targets":[{"kind":"repo","type":"dataset","owner":"alice","name":"data"}],"attrs":{"visibility":"private"},"grant_policy":{"mode":"execution","default_minutes":5,"max_minutes":5,"request_ttl_minutes":5,"default_max_uses":1,"max_uses":1}}]}`, notifier)
	defer cancelServer()
	defer server.Close()
	ctx, cancelRequest := context.WithCancel(context.Background())
	cancelRequest()
	body := `{"idempotency_key":"disconnect","operation":"repo.create","target":{"kind":"repo","type":"dataset","owner":"alice","name":"data"},"arguments":{"visibility":"private"},"reason":"survive disconnect"}`
	var request agentv1.SubmitRequest
	if err := json.Unmarshal([]byte(body), &request); err != nil {
		t.Fatal(err)
	}
	operation, created, err := handler.submitAgentOperation(ctx, "agent", request)
	if err != nil || !created || operation.State != agentv1.StatePending || !notifier.sent {
		t.Fatalf("submit = %#v, %v, created = %v, sent = %v", operation, err, created, notifier.sent)
	}
}

type contextCheckingNotifier struct{ sent bool }

func (n *contextCheckingNotifier) SendApproval(ctx context.Context, _ bknotify.ApprovalMessage) (bknotify.MessageRef, error) {
	if err := ctx.Err(); err != nil {
		return bknotify.MessageRef{}, err
	}
	n.sent = true
	return bknotify.MessageRef{Kind: "test", ChatID: 1, MessageID: 1}, nil
}

func (*contextCheckingNotifier) UpdateStatus(context.Context, bknotify.MessageRef, string) error {
	return nil
}

func TestAgentRepoCreateFailsClosedWhenNotifierFails(t *testing.T) {
	upstream := newAbsentRepoUpstream(t, "alice", "dataset", "data")
	defer upstream.Close()
	server, handler, cancel := newAgentOperationTestServer(t, upstream.URL, `{"rules":[{"id":"create","effect":"request","clients":["agent"],"operations":["repo.create"],"targets":[{"kind":"repo","type":"dataset","owner":"alice","name":"data"}],"attrs":{"visibility":"private"},"grant_policy":{"mode":"execution","default_minutes":5,"max_minutes":5,"request_ttl_minutes":5,"default_max_uses":1,"max_uses":1}}]}`, failingGrantNotifier{})
	defer cancel()
	defer server.Close()
	body := `{"idempotency_key":"notify-failure","operation":"repo.create","target":{"kind":"repo","type":"dataset","owner":"alice","name":"data"},"arguments":{"visibility":"private"},"reason":"notify operator"}`
	response, text := doRequest(t, http.MethodPost, server.URL+agentOperationsPath, "Bearer "+testSecret, strings.NewReader(body))
	var operation agentv1.Operation
	if response.StatusCode != http.StatusOK || json.Unmarshal([]byte(text), &operation) != nil || operation.State != agentv1.StateFailed || operation.Error == nil || operation.Error.Code != "approval_notification_failed" {
		t.Fatalf("submit = %d %#v", response.StatusCode, operation)
	}
	values, err := handler.grants.ListForClient("agent")
	if err != nil || len(values) != 1 || string(values[0].Status) != "canceled" {
		t.Fatalf("grants = %#v, %v", values, err)
	}
}

func TestAgentRepoCreateAllowAndValidation(t *testing.T) {
	var exists atomic.Bool
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/whoami-v2":
			writeJSON(w, http.StatusOK, map[string]string{"name": "alice"})
		case "/api/datasets/alice/data":
			if !exists.Load() {
				http.NotFound(w, r)
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{"id": "alice/data", "sha": "created", "private": true})
		case "/api/repos/create":
			exists.Store(true)
			writeJSON(w, http.StatusCreated, map[string]any{})
		default:
			http.NotFound(w, r)
		}
	}))
	defer upstream.Close()
	policyJSON := `{"rules":[{"id":"create","effect":"allow","clients":["agent"],"operations":["repo.create"],"targets":[{"kind":"repo","type":"dataset","owner":"alice","name":"data"}],"attrs":{"visibility":"private"}}]}`
	server, _, cancel := newAgentOperationTestServer(t, upstream.URL, policyJSON)
	defer cancel()
	defer server.Close()

	response, _ := doRequest(t, http.MethodGet, server.URL+agentDiscoveryPath, "", nil)
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("anonymous discovery = %d", response.StatusCode)
	}
	invalid := `{"idempotency_key":"bad","operation":"repo.create","target":{"kind":"repo","type":"dataset","owner":"alice","name":"data"},"arguments":{"visibility":"private","token":"secret"},"reason":"bad"}`
	response, _ = doRequest(t, http.MethodPost, server.URL+agentOperationsPath, "Bearer "+testSecret, strings.NewReader(invalid))
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("unknown argument = %d", response.StatusCode)
	}
	valid := `{"idempotency_key":"allow","operation":"repo.create","target":{"kind":"repo","type":"dataset","owner":"alice","name":"data"},"arguments":{"visibility":"private"},"reason":"create"}`
	response, text := doRequest(t, http.MethodPost, server.URL+agentOperationsPath, "Bearer "+testSecret, strings.NewReader(valid))
	if response.StatusCode != http.StatusAccepted {
		t.Fatalf("allow submit = %d %s", response.StatusCode, text)
	}
	var operation agentv1.Operation
	_ = json.Unmarshal([]byte(text), &operation)
	if got := waitForTestOperation(t, server.URL, operation.ID); got.State != agentv1.StateSucceeded {
		t.Fatalf("allow operation = %#v", got)
	}
}

func TestAgentRepoCreateConcurrentIdempotentAllow(t *testing.T) {
	var mu sync.Mutex
	createHits := 0
	exists := false
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/whoami-v2":
			writeJSON(w, http.StatusOK, map[string]string{"name": "alice"})
		case "/api/datasets/alice/race":
			mu.Lock()
			present := exists
			mu.Unlock()
			if !present {
				http.NotFound(w, r)
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{"id": "alice/race", "sha": "created", "private": true})
		case "/api/repos/create":
			mu.Lock()
			createHits++
			exists = true
			mu.Unlock()
			writeJSON(w, http.StatusCreated, map[string]any{})
		default:
			http.NotFound(w, r)
		}
	}))
	defer upstream.Close()
	server, _, cancel := newAgentOperationTestServer(t, upstream.URL, `{"rules":[{"id":"create","effect":"allow","clients":["agent"],"operations":["repo.create"],"targets":[{"kind":"repo","type":"dataset","owner":"alice","name":"race"}],"attrs":{"visibility":"private"}}]}`)
	defer cancel()
	defer server.Close()
	body := `{"idempotency_key":"concurrent","operation":"repo.create","target":{"kind":"repo","type":"dataset","owner":"alice","name":"race"},"arguments":{"visibility":"private"},"reason":"concurrent retry"}`
	var wg sync.WaitGroup
	errorsSeen := make(chan string, 12)
	for range 12 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			response, text := doRequest(t, http.MethodPost, server.URL+agentOperationsPath, "Bearer "+testSecret, strings.NewReader(body))
			if response.StatusCode != http.StatusOK && response.StatusCode != http.StatusAccepted {
				errorsSeen <- text
				return
			}
			var operation agentv1.Operation
			if json.Unmarshal([]byte(text), &operation) != nil || operation.State == agentv1.StateFailed {
				errorsSeen <- text
			}
		}()
	}
	wg.Wait()
	close(errorsSeen)
	for message := range errorsSeen {
		t.Fatalf("concurrent submission failed: %s", message)
	}
	operation := waitForTestOperation(t, server.URL, operationIDFromSubmission(t, server.URL, body))
	if operation.State != agentv1.StateSucceeded {
		t.Fatalf("operation = %#v", operation)
	}
	mu.Lock()
	defer mu.Unlock()
	if createHits != 1 {
		t.Fatalf("create hits = %d", createHits)
	}
}

func operationIDFromSubmission(t *testing.T, serverURL, body string) string {
	t.Helper()
	response, text := doRequest(t, http.MethodPost, serverURL+agentOperationsPath, "Bearer "+testSecret, strings.NewReader(body))
	var operation agentv1.Operation
	if response.StatusCode != http.StatusOK || json.Unmarshal([]byte(text), &operation) != nil {
		t.Fatalf("replay = %d %s", response.StatusCode, text)
	}
	return operation.ID
}

func TestAgentOperationRoutesAndSubmissionErrors(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/whoami-v2" {
			writeJSON(w, http.StatusOK, map[string]string{"name": "alice"})
			return
		}
		http.NotFound(w, r)
	}))
	defer upstream.Close()
	server, _, cancel := newAgentOperationTestServer(t, upstream.URL, `{"rules":[{"id":"deny","effect":"deny","clients":["agent"],"operations":["repo.create"],"targets":[{"kind":"repo","type":"dataset","owner":"alice","name":"*"}]}]}`)
	defer cancel()
	defer server.Close()

	tests := []struct {
		name string
		body string
		want int
	}{
		{"unsupported", `{"idempotency_key":"unsupported","operation":"repo.delete","target":{},"arguments":{},"reason":"test"}`, http.StatusBadRequest},
		{"duplicate field", `{"idempotency_key":"duplicate","operation":"repo.create","operation":"repo.create","target":{},"arguments":{},"reason":"test"}`, http.StatusBadRequest},
		{"trailing data", `{"idempotency_key":"trailing","operation":"repo.create","target":{},"arguments":{},"reason":"test"}{}`, http.StatusBadRequest},
		{"missing reason", `{"idempotency_key":"missing","operation":"repo.create","target":{},"arguments":{}}`, http.StatusBadRequest},
		{"invalid target", `{"idempotency_key":"target","operation":"repo.create","target":{"kind":"repo","type":"dataset","owner":"alice","name":"bad/name"},"arguments":{"visibility":"private"},"reason":"test"}`, http.StatusBadRequest},
		{"invalid sdk", `{"idempotency_key":"sdk","operation":"repo.create","target":{"kind":"repo","type":"dataset","owner":"alice","name":"data"},"arguments":{"visibility":"private","sdk":"docker"},"reason":"test"}`, http.StatusBadRequest},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response, _ := doRequest(t, http.MethodPost, server.URL+agentOperationsPath, "Bearer "+testSecret, strings.NewReader(test.body))
			if response.StatusCode != test.want {
				t.Fatalf("status = %d, want %d", response.StatusCode, test.want)
			}
		})
	}

	denied := `{"idempotency_key":"same","operation":"repo.create","target":{"kind":"repo","type":"dataset","owner":"alice","name":"data"},"arguments":{"visibility":"private"},"reason":"test"}`
	response, text := doRequest(t, http.MethodPost, server.URL+agentOperationsPath, "Bearer "+testSecret, strings.NewReader(denied))
	var operation agentv1.Operation
	if response.StatusCode != http.StatusOK || json.Unmarshal([]byte(text), &operation) != nil || operation.State != agentv1.StateDenied {
		t.Fatalf("denied submit = %d %#v", response.StatusCode, operation)
	}
	response, _ = doRequest(t, http.MethodPost, server.URL+agentOperationsPath, "Bearer "+testSecret, strings.NewReader(strings.Replace(denied, `"name":"data"`, `"name":"other"`, 1)))
	if response.StatusCode != http.StatusConflict {
		t.Fatalf("idempotency conflict = %d", response.StatusCode)
	}

	for _, path := range []string{
		agentOperationsPath + "/missing",
		agentOperationsPath + "/" + operation.ID + "/events?after_revision=nope",
		agentOperationsPath + "/" + operation.ID + "/events?wait_seconds=31",
	} {
		response, _ = doRequest(t, http.MethodGet, server.URL+path, "Bearer "+testSecret, nil)
		if response.StatusCode != map[bool]int{true: http.StatusNotFound, false: http.StatusBadRequest}[strings.HasSuffix(path, "/missing")] {
			t.Fatalf("GET %s = %d", path, response.StatusCode)
		}
	}
	response, text = doRequest(t, http.MethodGet, server.URL+agentOperationsPath+"/"+operation.ID+"/events?after_revision=0&wait_seconds=0", "Bearer "+testSecret, nil)
	if response.StatusCode != http.StatusOK || !strings.Contains(text, operation.ID) {
		t.Fatalf("event poll = %d %s", response.StatusCode, text)
	}
}

func TestAgentRepoCreateUpstreamFailures(t *testing.T) {
	for _, test := range []struct {
		name     string
		status   int
		wantCode string
	}{
		{name: "rejected", status: http.StatusForbidden, wantCode: "operation_upstream_authorization_failed"},
		{name: "unavailable", status: http.StatusInternalServerError, wantCode: "operation_upstream_unavailable"},
	} {
		t.Run(test.name, func(t *testing.T) {
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/api/whoami-v2":
					writeJSON(w, http.StatusOK, map[string]string{"name": "alice"})
				case "/api/models/alice/model":
					http.NotFound(w, r)
				case "/api/repos/create":
					w.WriteHeader(test.status)
				default:
					http.NotFound(w, r)
				}
			}))
			defer upstream.Close()
			server, _, cancel := newAgentOperationTestServer(t, upstream.URL, `{"rules":[{"id":"create","effect":"allow","clients":["agent"],"operations":["repo.create"],"targets":[{"kind":"repo","type":"model","owner":"alice","name":"model"}],"attrs":{"visibility":"public"}}]}`)
			defer cancel()
			defer server.Close()
			body := `{"idempotency_key":"failure","operation":"repo.create","target":{"kind":"repo","type":"model","owner":"alice","name":"model"},"arguments":{"visibility":"public"},"reason":"test failure"}`
			response, text := doRequest(t, http.MethodPost, server.URL+agentOperationsPath, "Bearer "+testSecret, strings.NewReader(body))
			var operation agentv1.Operation
			if response.StatusCode != http.StatusAccepted || json.Unmarshal([]byte(text), &operation) != nil {
				t.Fatalf("submit = %d %s", response.StatusCode, text)
			}
			operation = waitForTestOperation(t, server.URL, operation.ID)
			if operation.State != agentv1.StateFailed || operation.Error == nil || operation.Error.Code != test.wantCode {
				t.Fatalf("operation = %#v", operation)
			}
		})
	}
}

func newAgentOperationTestServer(t *testing.T, upstreamURL, scopeJSON string, notifiers ...bknotify.Notifier) (*httptest.Server, *Server, context.CancelFunc) {
	t.Helper()
	scope, err := policy.Parse([]byte(scopeJSON))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	operators := []config.Client{{Name: "operator", Secret: testOtherSecret}}
	var notifier bknotify.Notifier
	if len(notifiers) > 0 {
		notifier = notifiers[0]
		operators = nil
	}
	handler, err := New(Options{Config: config.Config{
		HFToken: testToken, Clients: []config.Client{{Name: "agent", Secret: testSecret}},
		Operators: operators, StateDir: filepath.Join(t.TempDir(), "state"),
		MaxPackBytes: 25 * 1024 * 1024, HFTimeout: 5 * time.Second,
	}, Scope: scope, Audit: audit.New(io.Discard), UpstreamBaseURL: upstreamURL, Context: ctx, GrantNotifier: notifier})
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	stop := func() {
		cancel()
		handler.backgroundWorkers.Wait()
	}
	return httptest.NewServer(handler), handler, stop
}

func newAbsentRepoUpstream(t *testing.T, owner, repoType, name string) *httptest.Server {
	t.Helper()
	path := "/api/" + repoType + "s/" + owner + "/" + name
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/whoami-v2":
			writeJSON(w, http.StatusOK, map[string]string{"name": owner})
		case path:
			http.NotFound(w, r)
		default:
			t.Fatalf("unexpected upstream request: %s %s", r.Method, r.URL.Path)
		}
	}))
}

func waitForTestOperation(t *testing.T, serverURL, id string) agentv1.Operation {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		response, text := doRequest(t, http.MethodGet, serverURL+agentOperationsPath+"/"+id, "Bearer "+testSecret, nil)
		if response.StatusCode != http.StatusOK {
			t.Fatalf("get operation = %d %s", response.StatusCode, text)
		}
		var operation agentv1.Operation
		if err := json.Unmarshal([]byte(text), &operation); err != nil {
			t.Fatal(err)
		}
		if operation.State.Terminal() {
			return operation
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatal("operation did not finish")
	return agentv1.Operation{}
}
