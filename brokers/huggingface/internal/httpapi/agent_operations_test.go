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
	"testing"
	"time"

	"github.com/osolmaz/brokerkit/agentops"
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

func TestAgentRepoCreateApprovalExecutesOnce(t *testing.T) {
	var mu sync.Mutex
	createHits := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+testToken {
			t.Fatalf("upstream authorization was not the broker token")
		}
		switch r.URL.Path {
		case "/api/whoami-v2":
			writeJSON(w, http.StatusOK, map[string]string{"name": "alice"})
		case "/api/repos/create":
			mu.Lock()
			createHits++
			mu.Unlock()
			var payload map[string]any
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Fatal(err)
			}
			if payload["name"] != "data" || payload["organization"] != nil || payload["type"] != "dataset" || payload["private"] != true {
				t.Fatalf("create payload = %#v", payload)
			}
			writeJSON(w, http.StatusCreated, map[string]any{})
		default:
			http.NotFound(w, r)
		}
	}))
	defer upstream.Close()

	policyJSON := `{"rules":[{"id":"create","effect":"request","clients":["agent"],"operations":["repo.create"],"targets":[{"kind":"repo","type":"dataset","owner":"alice","name":"data"}],"attrs":{"private":"true"},"grant_policy":{"mode":"execution","default_minutes":5,"max_minutes":5,"request_ttl_minutes":5,"default_max_uses":1,"max_uses":1}}]}`
	server, handler, cancel := newAgentOperationTestServer(t, upstream.URL, policyJSON)
	defer cancel()
	defer server.Close()

	body := `{"idempotency_key":"create-data","operation":"repo.create","target":{"kind":"repo","type":"dataset","owner":"alice","name":"data"},"arguments":{"private":true},"reason":"create test data"}`
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

func TestAgentRepoCreateRetryReconcilesUnboundOperation(t *testing.T) {
	upstream := httptest.NewServer(http.NotFoundHandler())
	defer upstream.Close()
	policyJSON := `{"rules":[{"id":"create","effect":"request","clients":["agent"],"operations":["repo.create"],"targets":[{"kind":"repo","type":"dataset","owner":"alice","name":"data"}],"attrs":{"private":"true"},"grant_policy":{"mode":"execution","default_minutes":5,"max_minutes":5,"request_ttl_minutes":5,"default_max_uses":1,"max_uses":1}}]}`
	server, handler, cancel := newAgentOperationTestServer(t, upstream.URL, policyJSON)
	defer cancel()
	defer server.Close()
	body := `{"idempotency_key":"recover","operation":"repo.create","target":{"kind":"repo","type":"dataset","owner":"alice","name":"data"},"arguments":{"private":true},"reason":"recover after restart"}`
	var request agentv1.SubmitRequest
	if err := json.Unmarshal([]byte(body), &request); err != nil {
		t.Fatal(err)
	}
	stored, created, err := handler.operations.Submit(agentops.Submit{
		Broker: "hf-broker", ClientID: "agent", IdempotencyKey: request.IdempotencyKey, Operation: request.Operation,
		Target: request.Target, Arguments: request.Arguments, Reason: request.Reason,
		Presentation: agentv1.Presentation{Title: "Create Hugging Face repository", Summary: "Create private dataset alice/data"},
	})
	if err != nil || !created || stored.ApprovalID != "" {
		t.Fatalf("stored = %#v, %v, %v", stored, created, err)
	}
	response, text := doRequest(t, http.MethodPost, server.URL+agentOperationsPath, "Bearer "+testSecret, strings.NewReader(body))
	var operation agentv1.Operation
	if response.StatusCode != http.StatusOK || json.Unmarshal([]byte(text), &operation) != nil || operation.ApprovalID == "" {
		t.Fatalf("reconciled = %d %#v", response.StatusCode, operation)
	}
}

func TestAgentRepoCreateSendsNotifierOnlyApproval(t *testing.T) {
	upstream := httptest.NewServer(http.NotFoundHandler())
	defer upstream.Close()
	notifier := &bknotify.Memory{}
	server, handler, cancel := newAgentOperationTestServer(t, upstream.URL, `{"rules":[{"id":"create","effect":"request","clients":["agent"],"operations":["repo.create"],"targets":[{"kind":"repo","type":"dataset","owner":"alice","name":"data"}],"attrs":{"private":"true"},"grant_policy":{"mode":"execution","default_minutes":5,"max_minutes":5,"request_ttl_minutes":5,"default_max_uses":1,"max_uses":1}}]}`, notifier)
	defer cancel()
	defer server.Close()
	body := `{"idempotency_key":"notify","operation":"repo.create","target":{"kind":"repo","type":"dataset","owner":"alice","name":"data"},"arguments":{"private":true},"reason":"notify operator"}`
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
	upstream := httptest.NewServer(http.NotFoundHandler())
	defer upstream.Close()
	notifier := &contextCheckingNotifier{}
	server, handler, cancelServer := newAgentOperationTestServer(t, upstream.URL, `{"rules":[{"id":"create","effect":"request","clients":["agent"],"operations":["repo.create"],"targets":[{"kind":"repo","type":"dataset","owner":"alice","name":"data"}],"attrs":{"private":"true"},"grant_policy":{"mode":"execution","default_minutes":5,"max_minutes":5,"request_ttl_minutes":5,"default_max_uses":1,"max_uses":1}}]}`, notifier)
	defer cancelServer()
	defer server.Close()
	ctx, cancelRequest := context.WithCancel(context.Background())
	cancelRequest()
	body := `{"idempotency_key":"disconnect","operation":"repo.create","target":{"kind":"repo","type":"dataset","owner":"alice","name":"data"},"arguments":{"private":true},"reason":"survive disconnect"}`
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
	upstream := httptest.NewServer(http.NotFoundHandler())
	defer upstream.Close()
	server, handler, cancel := newAgentOperationTestServer(t, upstream.URL, `{"rules":[{"id":"create","effect":"request","clients":["agent"],"operations":["repo.create"],"targets":[{"kind":"repo","type":"dataset","owner":"alice","name":"data"}],"attrs":{"private":"true"},"grant_policy":{"mode":"execution","default_minutes":5,"max_minutes":5,"request_ttl_minutes":5,"default_max_uses":1,"max_uses":1}}]}`, failingGrantNotifier{})
	defer cancel()
	defer server.Close()
	body := `{"idempotency_key":"notify-failure","operation":"repo.create","target":{"kind":"repo","type":"dataset","owner":"alice","name":"data"},"arguments":{"private":true},"reason":"notify operator"}`
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
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/whoami-v2" {
			writeJSON(w, http.StatusOK, map[string]string{"name": "alice"})
			return
		}
		writeJSON(w, http.StatusCreated, map[string]any{})
	}))
	defer upstream.Close()
	policyJSON := `{"rules":[{"id":"create","effect":"allow","clients":["agent"],"operations":["repo.create"],"targets":[{"kind":"repo","type":"dataset","owner":"alice","name":"data"}],"attrs":{"private":"true"}}]}`
	server, _, cancel := newAgentOperationTestServer(t, upstream.URL, policyJSON)
	defer cancel()
	defer server.Close()

	response, _ := doRequest(t, http.MethodGet, server.URL+agentDiscoveryPath, "", nil)
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("anonymous discovery = %d", response.StatusCode)
	}
	invalid := `{"idempotency_key":"bad","operation":"repo.create","target":{"kind":"repo","type":"dataset","owner":"alice","name":"data"},"arguments":{"private":true,"token":"secret"},"reason":"bad"}`
	response, _ = doRequest(t, http.MethodPost, server.URL+agentOperationsPath, "Bearer "+testSecret, strings.NewReader(invalid))
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("unknown argument = %d", response.StatusCode)
	}
	valid := `{"idempotency_key":"allow","operation":"repo.create","target":{"kind":"repo","type":"dataset","owner":"alice","name":"data"},"arguments":{"private":true},"reason":"create"}`
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
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/whoami-v2" {
			writeJSON(w, http.StatusOK, map[string]string{"name": "alice"})
			return
		}
		mu.Lock()
		createHits++
		mu.Unlock()
		writeJSON(w, http.StatusCreated, map[string]any{})
	}))
	defer upstream.Close()
	server, _, cancel := newAgentOperationTestServer(t, upstream.URL, `{"rules":[{"id":"create","effect":"allow","clients":["agent"],"operations":["repo.create"],"targets":[{"kind":"repo","type":"dataset","owner":"alice","name":"race"}],"attrs":{"private":"true"}}]}`)
	defer cancel()
	defer server.Close()
	body := `{"idempotency_key":"concurrent","operation":"repo.create","target":{"kind":"repo","type":"dataset","owner":"alice","name":"race"},"arguments":{"private":true},"reason":"concurrent retry"}`
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
		writeJSON(w, http.StatusOK, map[string]string{"name": "alice"})
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
		{"invalid target", `{"idempotency_key":"target","operation":"repo.create","target":{"kind":"repo","type":"dataset","owner":"alice","name":"bad/name"},"arguments":{"private":true},"reason":"test"}`, http.StatusBadRequest},
		{"invalid sdk", `{"idempotency_key":"sdk","operation":"repo.create","target":{"kind":"repo","type":"dataset","owner":"alice","name":"data"},"arguments":{"private":true,"sdk":"docker"},"reason":"test"}`, http.StatusBadRequest},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response, _ := doRequest(t, http.MethodPost, server.URL+agentOperationsPath, "Bearer "+testSecret, strings.NewReader(test.body))
			if response.StatusCode != test.want {
				t.Fatalf("status = %d, want %d", response.StatusCode, test.want)
			}
		})
	}

	denied := `{"idempotency_key":"same","operation":"repo.create","target":{"kind":"repo","type":"dataset","owner":"alice","name":"data"},"arguments":{"private":true},"reason":"test"}`
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
		{name: "rejected", status: http.StatusForbidden, wantCode: "upstream_rejected"},
		{name: "unknown", status: http.StatusInternalServerError, wantCode: "upstream_result_unknown"},
	} {
		t.Run(test.name, func(t *testing.T) {
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/api/whoami-v2" {
					writeJSON(w, http.StatusOK, map[string]string{"name": "alice"})
					return
				}
				w.WriteHeader(test.status)
			}))
			defer upstream.Close()
			server, _, cancel := newAgentOperationTestServer(t, upstream.URL, `{"rules":[{"id":"create","effect":"allow","clients":["agent"],"operations":["repo.create"],"targets":[{"kind":"repo","type":"model","owner":"alice","name":"model"}],"attrs":{"private":"false"}}]}`)
			defer cancel()
			defer server.Close()
			body := `{"idempotency_key":"failure","operation":"repo.create","target":{"kind":"repo","type":"model","owner":"alice","name":"model"},"arguments":{"private":false},"reason":"test failure"}`
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
