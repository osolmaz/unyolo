package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/osolmaz/unyolo/agent/conformance"
	"github.com/osolmaz/unyolo/agent/v1"
	unyoloapprovalnotify "github.com/osolmaz/unyolo/approval/notification"
	unyolonotify "github.com/osolmaz/unyolo/approval/notifier"
	"github.com/osolmaz/unyolo/authorization/grants"
	"github.com/osolmaz/unyolo/brokers/huggingface/internal/config"
	"github.com/osolmaz/unyolo/brokers/huggingface/internal/hfgrant"
	"github.com/osolmaz/unyolo/brokers/huggingface/internal/hfplan"
	"github.com/osolmaz/unyolo/brokers/huggingface/internal/policy"
	"github.com/osolmaz/unyolo/operator/v1"
	"github.com/osolmaz/unyolo/telemetry/audit"
)

const (
	agentDiscoveryPath  = "/.well-known/unyolo-agent"
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

func TestAgentPrivateRepositoryReadExecutesDirectly(t *testing.T) {
	var contentHits atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+testToken {
			t.Fatalf("upstream authorization was not the broker token")
		}
		if r.URL.Path != "/datasets/alice/private/resolve/main/README.md" {
			http.NotFound(w, r)
			return
		}
		contentHits.Add(1)
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("X-Repo-Commit", "abc")
		_, _ = w.Write([]byte("private content"))
	}))
	defer upstream.Close()
	policyJSON := `{"rules":[{"id":"read-private","effect":"allow","clients":["agent"],"operations":["repo.contents.read"],"targets":[{"kind":"repo","type":"dataset","owner":"alice","name":"private","paths":["README.md"]}]}]}`
	server, _, cancel := newAgentOperationTestServer(t, upstream.URL, policyJSON)
	defer cancel()
	defer server.Close()
	body := `{"idempotency_key":"read-private","operation":"repo.contents.read","target":{"kind":"repo","type":"dataset","owner":"alice","name":"private"},"arguments":{"path":"README.md"},"reason":"read private repository"}`
	response, text := doRequest(t, http.MethodPost, server.URL+agentOperationsPath, "Bearer "+testSecret, strings.NewReader(body))
	if response.StatusCode != http.StatusCreated && response.StatusCode != http.StatusAccepted {
		t.Fatalf("submit = %d %s", response.StatusCode, text)
	}
	var operation agentv1.Operation
	if err := json.Unmarshal([]byte(text), &operation); err != nil {
		t.Fatal(err)
	}
	operation = waitForTestOperation(t, server.URL, operation.ID)
	if operation.State != agentv1.StateSucceeded || operation.ApprovalID != "" ||
		!strings.Contains(string(operation.Result), `"content":"private content"`) ||
		!strings.Contains(string(operation.Result), `"encoding":"utf-8"`) {
		t.Fatalf("operation = %#v", operation)
	}
	if contentHits.Load() != 1 {
		t.Fatalf("content hits = %d, want 1", contentHits.Load())
	}
}

func TestAgentRepositoryDiscoveryQueriesUpstreamAndFiltersPolicy(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/datasets" || r.URL.Query().Get("author") != "alice" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(`[{"id":"alice/private","private":true},{"id":"alice/denied","private":true}]`))
	}))
	defer upstream.Close()
	policyJSON := `{"rules":[
		{"id":"deny-one","effect":"deny","clients":["agent"],"operations":["repo.list","repo.metadata.read"],"targets":[{"kind":"repo","type":"dataset","owner":"alice","name":"denied"}]},
		{"id":"discover","effect":"allow","clients":["agent"],"operations":["repo.list","repo.metadata.read"],"targets":[{"kind":"repo","type":"dataset","owner":"alice","name":"*"}]}
	]}`
	server, _, cancel := newAgentOperationTestServer(t, upstream.URL, policyJSON)
	defer cancel()
	defer server.Close()
	body := `{"idempotency_key":"list-private","operation":"repo.list","target":{"kind":"repo","type":"dataset","owner":"alice","name":"*"},"arguments":{"limit":10},"reason":"discover repositories"}`
	response, text := doRequest(t, http.MethodPost, server.URL+agentOperationsPath, "Bearer "+testSecret, strings.NewReader(body))
	if response.StatusCode != http.StatusCreated && response.StatusCode != http.StatusAccepted {
		t.Fatalf("submit = %d %s", response.StatusCode, text)
	}
	var operation agentv1.Operation
	if err := json.Unmarshal([]byte(text), &operation); err != nil {
		t.Fatal(err)
	}
	operation = waitForTestOperation(t, server.URL, operation.ID)
	if operation.State != agentv1.StateSucceeded || operation.ApprovalID != "" ||
		!strings.Contains(string(operation.Result), `"id":"alice/private"`) || strings.Contains(string(operation.Result), "alice/denied") ||
		strings.Contains(string(operation.Result), `"private"`) {
		t.Fatalf("operation = %#v", operation)
	}
}

func TestAgentRepositoryDiscoveryReusesApprovedWindowGrant(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/datasets" || r.URL.Query().Get("author") != "alice" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(`[{"id":"alice/private","private":true},{"id":"alice/denied","private":true}]`))
	}))
	defer upstream.Close()
	policyJSON := `{"rules":[
		{"id":"deny-one","effect":"deny","clients":["agent"],"operations":["repo.list"],"targets":[{"kind":"repo","type":"dataset","owner":"alice","name":"denied"}]},
		{"id":"discover","effect":"request","clients":["agent"],"operations":["repo.list"],"targets":[{"kind":"repo","type":"dataset","owner":"alice","name":"*"}],"grant_policy":{"mode":"window","default_minutes":5,"max_minutes":5,"request_ttl_minutes":5,"default_max_uses":2,"max_uses":2}}
	]}`
	server, handler, cancel := newAgentOperationTestServer(t, upstream.URL, policyJSON)
	defer cancel()
	defer server.Close()

	submit := func(key string) agentv1.Operation {
		t.Helper()
		body := `{"idempotency_key":"` + key + `","operation":"repo.list","target":{"kind":"repo","type":"dataset","owner":"alice","name":"*"},"arguments":{"limit":10},"reason":"discover repositories"}`
		response, text := doRequest(t, http.MethodPost, server.URL+agentOperationsPath, "Bearer "+testSecret, strings.NewReader(body))
		if response.StatusCode != http.StatusAccepted && response.StatusCode != http.StatusCreated {
			t.Fatalf("submit %s = %d %s", key, response.StatusCode, text)
		}
		var operation agentv1.Operation
		if err := json.Unmarshal([]byte(text), &operation); err != nil {
			t.Fatal(err)
		}
		return operation
	}

	first := submit("discover-approved-1")
	if first.State != agentv1.StatePending || first.ApprovalID == "" {
		t.Fatalf("first operation = %#v", first)
	}
	grant, err := handler.grants.Get(first.ApprovalID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = handler.control.Decisions.Decide(context.Background(), grant.ID, operatorv1.ActionApprove, "alice", operatorv1.Decision{
		ExpectedRevision: grant.Revision, IdempotencyKey: "approve-discovery",
	}); err != nil {
		t.Fatal(err)
	}
	first = waitForTestOperation(t, server.URL, first.ID)
	if first.State != agentv1.StateSucceeded {
		t.Fatalf("first repository list operation = %#v", first)
	}
	grant, err = handler.grants.Get(grant.ID)
	if err != nil {
		t.Fatal(err)
	}
	reserved, err := handler.grants.ReserveUse(grant.ID, "manual-policy-check", grant.Operation)
	if err != nil {
		t.Fatal(err)
	}
	allowed := policyAllowsRepositoryResult("agent", handler.policy,
		policy.Target{Kind: policy.KindRepo, Type: policy.TypeDataset, Owner: "alice", Name: "private"},
		policy.OpRepoList, &reserved.Grant, handler.planValidator, handler.utcNow())
	_, _ = handler.grants.ReleaseUse(grant.ID, reserved.Use.RequestID)
	if !allowed {
		t.Fatalf("reserved repository grant did not authorize its result: %+v", reserved)
	}
	assertApprovedRepositoryList(t, first, grant.ID)

	second := submit("discover-approved-2")
	if second.ApprovalID != grant.ID || second.State == agentv1.StatePending {
		t.Fatalf("reused operation = %#v", second)
	}
	second = waitForTestOperation(t, server.URL, second.ID)
	assertApprovedRepositoryList(t, second, grant.ID)
	grantsForClient, err := handler.grants.ListForClient("agent")
	if err != nil || len(grantsForClient) != 1 || grantsForClient[0].UsedCount != 2 {
		t.Fatalf("grants after reuse = %+v, %v", grantsForClient, err)
	}
}

func TestAgentSealedJobRunReusesBroadWindowAcrossChangedArguments(t *testing.T) {
	var jobMu sync.Mutex
	var jobFlavors []string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+testToken {
			t.Fatalf("upstream authorization was not the broker token")
		}
		switch r.URL.Path {
		case "/api/whoami-v2":
			writeJSON(w, http.StatusOK, map[string]string{"name": "alice"})
		case "/api/jobs/alice":
			var payload map[string]any
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Fatal(err)
			}
			secrets, ok := payload["secrets"].(map[string]any)
			flavor, flavorOK := payload["flavor"].(string)
			if !ok || secrets["TOKEN"] != "hidden" || !flavorOK {
				t.Fatalf("job payload = %#v", payload)
			}
			jobMu.Lock()
			jobFlavors = append(jobFlavors, flavor)
			jobMu.Unlock()
			writeJSON(w, http.StatusOK, map[string]any{})
		default:
			http.NotFound(w, r)
		}
	}))
	defer upstream.Close()

	policyJSON := `{"rules":[{"id":"run-job","effect":"request","clients":["agent"],"operations":["job.run"],"targets":[{"kind":"job","owner":"alice","name":"namespace=alice"}],"grant_policy":{"mode":"window","default_minutes":5,"max_minutes":5,"request_ttl_minutes":5,"default_max_uses":5,"max_uses":5}}]}`
	server, handler, cancel := newAgentOperationTestServer(t, upstream.URL, policyJSON)
	defer cancel()
	defer server.Close()

	requested, created, err := hfgrant.Request(handler.grants, handler.plans, hfgrant.Input{
		Client: "agent", ClientRequestID: "broad-job-window", Operation: "job.run", Mode: hfgrant.ModeWindow,
		PolicyTarget: &policy.Target{Kind: policy.TargetKind("job"), Owner: "alice", Name: "namespace=alice"},
		Reason:       "allow the requested number of jobs with changing arguments", RequestedDuration: 5 * time.Minute,
		PendingTimeout: 5 * time.Minute, MaxUses: 5, MaxUsesSpecified: true,
	})
	if err != nil || !created || len(requested.Grant.Attrs) != 0 {
		t.Fatalf("broad grant request = %+v, %v, created=%v", requested, err, created)
	}
	grant := requested.Grant
	if _, err = handler.control.Decisions.Decide(context.Background(), grant.ID, operatorv1.ActionApprove, "alice", operatorv1.Decision{
		ExpectedRevision: grant.Revision, IdempotencyKey: "approve-broad-job-window",
	}); err != nil {
		t.Fatal(err)
	}

	submit := func(requestKey, flavor string) agentv1.Operation {
		t.Helper()
		headers := map[string]string{"Content-Type": "application/octet-stream", "X-Broker-Operation": "job.run", "X-Broker-Idempotency-Key": requestKey}
		response, text := doRequestWithHeaders(t, http.MethodPost, server.URL+"/api/agent/v1/sealed-payloads", "Bearer "+testSecret,
			headers, strings.NewReader(`{"secrets":{"TOKEN":"hidden"}}`))
		if response.StatusCode != http.StatusCreated || strings.Contains(text, "hidden") {
			t.Fatalf("sealed upload = %d %s", response.StatusCode, text)
		}
		var reference map[string]any
		if err := json.Unmarshal([]byte(text), &reference); err != nil {
			t.Fatal(err)
		}
		body, err := json.Marshal(map[string]any{
			"idempotency_key": requestKey,
			"operation":       "job.run",
			"target":          map[string]any{"namespace": "alice"},
			"arguments":       map[string]any{"public": map[string]any{"flavor": flavor}, "sealed_payload": reference},
			"reason":          "run a test job",
		})
		if err != nil {
			t.Fatal(err)
		}
		response, text = doRequest(t, http.MethodPost, server.URL+agentOperationsPath, "Bearer "+testSecret, strings.NewReader(string(body)))
		var operation agentv1.Operation
		if (response.StatusCode != http.StatusAccepted && response.StatusCode != http.StatusOK) || json.Unmarshal([]byte(text), &operation) != nil {
			t.Fatalf("submit = %d %s", response.StatusCode, text)
		}
		return operation
	}

	for index, flavor := range []string{"cpu-basic", "cpu-upgrade"} {
		operation := submit(fmt.Sprintf("job-window-%d", index+1), flavor)
		if operation.State == agentv1.StatePending || operation.ApprovalID != grant.ID {
			t.Fatalf("job %d did not reuse broad grant: %#v", index+1, operation)
		}
		operation = waitForTestOperation(t, server.URL, operation.ID)
		if operation.State != agentv1.StateSucceeded {
			t.Fatalf("job %d = %#v", index+1, operation)
		}
	}
	jobMu.Lock()
	defer jobMu.Unlock()
	updated, err := handler.grants.Get(grant.ID)
	if err != nil || updated.UsedCount != 2 || len(jobFlavors) != 2 || jobFlavors[0] != "cpu-basic" || jobFlavors[1] != "cpu-upgrade" {
		t.Fatalf("reused broad grant = %#v, flavors=%v, %v", updated, jobFlavors, err)
	}
}

func assertApprovedRepositoryList(t *testing.T, operation agentv1.Operation, grantID string) {
	t.Helper()
	if operation.State != agentv1.StateSucceeded || operation.ApprovalID != grantID ||
		!strings.Contains(string(operation.Result), `"id":"alice/private"`) || strings.Contains(string(operation.Result), "alice/denied") {
		t.Fatalf("repository list operation = %#v", operation)
	}
}

func TestAgentRepositoryTreeApprovalPreservesDeniedPaths(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/api/datasets/alice/private/tree/main/docs") {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(`[
			{"type":"file","path":"docs/README.md","oid":"abc","size":4},
			{"type":"file","path":"docs/secret.txt","oid":"def","size":6}
		]`))
	}))
	defer upstream.Close()
	policyJSON := `{"rules":[
		{"id":"deny-secret","effect":"deny","clients":["agent"],"operations":["repo.tree.list"],"targets":[{"kind":"repo","type":"dataset","owner":"alice","name":"private","paths":["docs/secret.txt"]}]},
		{"id":"list-docs","effect":"request","clients":["agent"],"operations":["repo.tree.list"],"targets":[{"kind":"repo","type":"dataset","owner":"alice","name":"private","paths":["docs"]}],"grant_policy":{"mode":"window","default_minutes":5,"max_minutes":5,"request_ttl_minutes":5,"default_max_uses":1,"max_uses":1}}
	]}`
	server, handler, cancel := newAgentOperationTestServer(t, upstream.URL, policyJSON)
	defer cancel()
	defer server.Close()
	body := `{"idempotency_key":"tree-approved","operation":"repo.tree.list","target":{"kind":"repo","type":"dataset","owner":"alice","name":"private"},"arguments":{"path":"docs","recursive":true},"reason":"list documentation"}`
	response, text := doRequest(t, http.MethodPost, server.URL+agentOperationsPath, "Bearer "+testSecret, strings.NewReader(body))
	var operation agentv1.Operation
	if response.StatusCode != http.StatusAccepted || json.Unmarshal([]byte(text), &operation) != nil || operation.ApprovalID == "" {
		t.Fatalf("submit = %d %s", response.StatusCode, text)
	}
	grant, err := handler.grants.Get(operation.ApprovalID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = handler.control.Decisions.Decide(context.Background(), grant.ID, operatorv1.ActionApprove, "alice", operatorv1.Decision{
		ExpectedRevision: grant.Revision, IdempotencyKey: "approve-tree",
	}); err != nil {
		t.Fatal(err)
	}
	operation = waitForTestOperation(t, server.URL, operation.ID)
	if operation.State != agentv1.StateSucceeded || !strings.Contains(string(operation.Result), "docs/README.md") ||
		strings.Contains(string(operation.Result), "docs/secret.txt") {
		t.Fatalf("tree operation = %#v error=%+v", operation, operation.Error)
	}
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
	notifier := &unyoloapprovalnotify.Memory{}
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
	message := notifier.Messages[0]
	if !strings.Contains(message.Presentation.Title, "Create Hugging Face repository") ||
		!strings.Contains(message.Presentation.Summary, "Create private dataset alice/data") ||
		message.Presentation.PlanHash != grant.Metadata[hfplan.MetadataDigest] {
		t.Fatalf("approval message omitted immutable operation details: %+v", message.Presentation)
	}
}

func TestAgentRequesterCancelsPendingOperationAndApproval(t *testing.T) {
	upstream := newAbsentRepoUpstream(t, "alice", "dataset", "data")
	defer upstream.Close()
	server, handler, cancel := newAgentOperationTestServer(t, upstream.URL, `{"rules":[{"id":"create","effect":"request","clients":["agent"],"operations":["repo.create"],"targets":[{"kind":"repo","type":"dataset","owner":"alice","name":"data"}],"attrs":{"visibility":"private"},"grant_policy":{"mode":"execution","default_minutes":5,"max_minutes":5,"request_ttl_minutes":5,"default_max_uses":1,"max_uses":1}}]}`, &unyoloapprovalnotify.Memory{})
	defer cancel()
	defer server.Close()
	body := `{"idempotency_key":"cancel-pending","operation":"repo.create","target":{"kind":"repo","type":"dataset","owner":"alice","name":"data"},"arguments":{"visibility":"private"},"reason":"cancel this request"}`
	response, text := doRequest(t, http.MethodPost, server.URL+agentOperationsPath, "Bearer "+testSecret, strings.NewReader(body))
	var submitted agentv1.Operation
	if response.StatusCode != http.StatusAccepted || json.Unmarshal([]byte(text), &submitted) != nil {
		t.Fatalf("submit = %d %s", response.StatusCode, text)
	}
	response, text = doRequest(t, http.MethodPost, server.URL+agentOperationsPath+"/"+submitted.ID+"/cancel", "Bearer "+testSecret, nil)
	var canceled agentv1.Operation
	if response.StatusCode != http.StatusOK || json.Unmarshal([]byte(text), &canceled) != nil || canceled.State != agentv1.StateCanceled {
		t.Fatalf("cancel = %d %#v", response.StatusCode, canceled)
	}
	grant, err := handler.grants.Get(submitted.ApprovalID)
	if err != nil || grant.Status != grants.StatusCanceled {
		t.Fatalf("approval = %#v, %v", grant, err)
	}
	response, _ = doRequest(t, http.MethodPost, server.URL+agentOperationsPath+"/"+submitted.ID+"/cancel", "Bearer "+testSecret, nil)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("cancel replay = %d", response.StatusCode)
	}
}

func TestAgentRequesterCancelsApprovalBeforeBindingRecovery(t *testing.T) {
	upstream := newAbsentRepoUpstream(t, "alice", "dataset", "cancel-unbound")
	defer upstream.Close()
	handler := newRecoveryTestServer(t, upstream.URL, emptyPolicyJSON())
	defer func() { _ = handler.Close() }()
	operation, requested := seedPendingRepoCreateGrant(t, handler, "op_cancel_unbound", "cancel-unbound")
	if operation.ApprovalID != "" {
		t.Fatalf("seeded operation unexpectedly bound approval %q", operation.ApprovalID)
	}
	canceled, err := handler.cancelAgentOperation(t.Context(), "agent", operation.ID)
	if err != nil || canceled.State != agentv1.StateCanceled {
		t.Fatalf("cancelAgentOperation() = %+v, %v", canceled, err)
	}
	grant, err := handler.grants.Get(requested.Grant.ID)
	if err != nil || grant.Status != grants.StatusCanceled {
		t.Fatalf("recovered approval = %+v, %v", grant, err)
	}
}

func TestGrantCancellationFailureIsNotDiscarded(t *testing.T) {
	upstream := newAbsentRepoUpstream(t, "alice", "dataset", "cancel-error")
	defer upstream.Close()
	handler := newRecoveryTestServer(t, upstream.URL, emptyPolicyJSON())
	defer func() { _ = handler.Close() }()
	_, requested := seedPendingRepoCreateGrant(t, handler, "op_cancel_error", "cancel-error")
	if err := handler.cancelGrantForClient(requested.Grant, "other-client"); !errors.Is(err, grants.ErrNotFound) {
		t.Fatalf("cancelGrantForClient() = %v", err)
	}
	stored, err := handler.grants.Get(requested.Grant.ID)
	if err != nil || stored.Status != grants.StatusPending {
		t.Fatalf("grant after refused close = %+v, %v", stored, err)
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

func (n *contextCheckingNotifier) SendApproval(ctx context.Context, _ unyoloapprovalnotify.Approval) (unyolonotify.MessageRef, error) {
	if err := ctx.Err(); err != nil {
		return unyolonotify.MessageRef{}, err
	}
	n.sent = true
	return unyolonotify.MessageRef{Kind: "test", ChatID: 1, MessageID: 1}, nil
}

func (*contextCheckingNotifier) UpdateStatus(context.Context, unyolonotify.MessageRef, unyolonotify.Status) error {
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
	if err := json.Unmarshal([]byte(text), &operation); err != nil {
		t.Fatal(err)
	}
	if operation.State != agentv1.StateApproved || operation.Revision != 1 || operation.PlanDigest == "" || operation.ApprovalID != "" {
		t.Fatalf("direct operation was not atomically approved with its plan: %#v", operation)
	}
	if got := waitForTestOperation(t, server.URL, operation.ID); got.State != agentv1.StateSucceeded {
		t.Fatalf("allow operation = %#v", got)
	}
}

func TestAgentApprovalBindingPrecedesNotification(t *testing.T) {
	upstream := newAbsentRepoUpstream(t, "alice", "dataset", "serialized")
	defer upstream.Close()
	notifier := &blockingApprovalNotifier{entered: make(chan struct{}), release: make(chan struct{})}
	server, handler, cancel := newAgentOperationTestServer(t, upstream.URL, `{"rules":[{"id":"create","effect":"request","clients":["agent"],"operations":["repo.create"],"targets":[{"kind":"repo","type":"dataset","owner":"alice","name":"serialized"}],"attrs":{"visibility":"private"},"grant_policy":{"mode":"execution","default_minutes":5,"max_minutes":5,"request_ttl_minutes":5,"default_max_uses":1,"max_uses":1}}]}`, notifier)
	defer cancel()
	defer server.Close()

	request := agentv1.SubmitRequest{IdempotencyKey: "serialized", Operation: "repo.create",
		Target:    json.RawMessage(`{"kind":"repo","type":"dataset","owner":"alice","name":"serialized"}`),
		Arguments: json.RawMessage(`{"visibility":"private"}`), Reason: "serialize plan binding"}
	type submitResult struct {
		operation agentv1.Operation
		created   bool
		err       error
	}
	result := make(chan submitResult, 1)
	go func() {
		operation, created, err := handler.submitAgentOperation(t.Context(), "agent", request)
		result <- submitResult{operation: operation, created: created, err: err}
	}()
	select {
	case <-notifier.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("approval notifier was not called")
	}

	unfinished, err := handler.operations.ListUnfinished()
	if err != nil || len(unfinished) != 1 || unfinished[0].PlanDigest == "" || unfinished[0].ApprovalID == "" {
		t.Fatalf("operation before notification = %#v, %v", unfinished, err)
	}
	handler.advanceOperations(t.Context())
	current, err := handler.operations.GetByID(unfinished[0].ID)
	if err != nil || current.State != agentv1.StatePending {
		t.Fatalf("operation advanced before approval: %#v, %v", current, err)
	}
	select {
	case completed := <-result:
		t.Fatalf("submission returned before notification completed: %#v", completed)
	default:
	}
	close(notifier.release)
	completed := <-result
	if completed.err != nil || !completed.created || completed.operation.PlanDigest == "" || completed.operation.ApprovalID == "" {
		t.Fatalf("submit = %#v", completed)
	}
}

type blockingApprovalNotifier struct {
	entered chan struct{}
	release chan struct{}
}

func (n *blockingApprovalNotifier) SendApproval(ctx context.Context, _ unyoloapprovalnotify.Approval) (unyolonotify.MessageRef, error) {
	close(n.entered)
	select {
	case <-n.release:
		return unyolonotify.MessageRef{Kind: "test", ChatID: 1, MessageID: 1}, nil
	case <-ctx.Done():
		return unyolonotify.MessageRef{}, ctx.Err()
	}
}

func (*blockingApprovalNotifier) UpdateStatus(context.Context, unyolonotify.MessageRef, unyolonotify.Status) error {
	return nil
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
	paddedBody := strings.Replace(body, `"concurrent"`, `" concurrent "`, 1)
	var wg sync.WaitGroup
	errorsSeen := make(chan string, 12)
	for index := range 12 {
		requestBody := body
		if index%2 == 0 {
			requestBody = paddedBody
		}
		wg.Add(1)
		go func(body string) {
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
		}(requestBody)
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

func newAgentOperationTestServer(t *testing.T, upstreamURL, scopeJSON string, notifiers ...unyoloapprovalnotify.Notifier) (*httptest.Server, *Server, context.CancelFunc) {
	t.Helper()
	scope, err := policy.Parse([]byte(scopeJSON))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	operators := []config.Client{{Name: "operator", Secret: testOtherSecret}}
	var notifier unyoloapprovalnotify.Notifier
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
