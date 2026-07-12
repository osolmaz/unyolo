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

	"github.com/osolmaz/brokerkit/agentv1"
	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/audit"
	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/config"
	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/policy"
	"github.com/osolmaz/brokerkit/operatorv1"
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
		ExpectedRevision: grant.Revision, IdempotencyKey: "approve-create-data", DecisionReason: "approved in test",
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

func newAgentOperationTestServer(t *testing.T, upstreamURL, scopeJSON string) (*httptest.Server, *Server, context.CancelFunc) {
	t.Helper()
	scope, err := policy.Parse([]byte(scopeJSON))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	handler, err := New(Options{Config: config.Config{
		HFToken: testToken, Clients: []config.Client{{Name: "agent", Secret: testSecret}},
		Operators: []config.Client{{Name: "operator", Secret: testOtherSecret}}, StateDir: filepath.Join(t.TempDir(), "state"),
		MaxPackBytes: 25 * 1024 * 1024, HFTimeout: 5 * time.Second,
	}, Scope: scope, Audit: audit.New(io.Discard), UpstreamBaseURL: upstreamURL, Context: ctx})
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	return httptest.NewServer(handler), handler, cancel
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
