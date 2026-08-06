package httpapi

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/osolmaz/unyolo/authorization/grants"
	"github.com/osolmaz/unyolo/brokers/huggingface/internal/config"
	"github.com/osolmaz/unyolo/brokers/huggingface/internal/policy"
	operatorclient "github.com/osolmaz/unyolo/operator/client"
	operatorv1 "github.com/osolmaz/unyolo/operator/v1"
	"github.com/osolmaz/unyolo/telemetry/audit"
)

const fetchApprovalOperatorSecret = "operator-secret-abcdefghijklmnopqrstuvwxyz"

func fetchRequestScope(t *testing.T) policy.Policy {
	t.Helper()
	scp, err := policy.Parse([]byte(`{"rules":[{
		"id":"request-fetch",
		"effect":"request",
		"clients":["agent"],
		"operations":["git.fetch"],
		"targets":[{"kind":"repo","type":"dataset","owner":"acme","name":"repo"}],
		"grant_policy":{"mode":"window","default_minutes":5,"max_minutes":60,"request_ttl_minutes":5,"default_max_uses":100,"max_uses":100}
	}]}`))
	if err != nil {
		t.Fatal(err)
	}
	return scp
}

// TestGitFetchApprovalRequiredThenRetrySucceeds drives the full HTTP flow:
// fetch without a rule match creates a durable approval, the operator
// approves it through the operator API, and the retried fetch succeeds.
func TestGitFetchApprovalRequiredThenRetrySucceeds(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	dir := t.TempDir()
	upstreamRepo := seedBareRepo(t, dir)
	upstream := newGitUpstream(t, upstreamRepo, testToken)
	defer upstream.server.Close()
	var auditLog bytes.Buffer
	handler, err := New(Options{
		Config: config.Config{HFToken: testToken, Clients: []config.Client{{Name: "agent", Secret: testSecret}},
			Operators: []config.Client{{Name: "onur", Secret: fetchApprovalOperatorSecret}},
			StateDir:  filepath.Join(dir, "state"), MaxPackBytes: 25 * 1024 * 1024, HFTimeout: 10 * time.Second},
		Scope: fetchRequestScope(t), Audit: audit.New(&auditLog), UpstreamBaseURL: upstream.server.URL,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = handler.Close() }()
	broker := httptest.NewServer(handler)
	defer broker.Close()
	operator := newFetchApprovalOperator(t, handler)

	infoRefs := broker.URL + "/datasets/acme/repo.git/info/refs?service=git-upload-pack"
	resp, body := doRequest(t, http.MethodGet, infoRefs, "Bearer "+testSecret, nil)
	if resp.StatusCode != http.StatusForbidden || !strings.Contains(body, "approval required (") {
		t.Fatalf("first discovery = %d %q, want approval hint", resp.StatusCode, body)
	}
	if got := upstream.totalHits(); got != 0 {
		t.Fatalf("unapproved fetch reached upstream: hits = %d", got)
	}
	approvePendingFetch(t, handler, operator)

	resp, _ = doRequest(t, http.MethodGet, infoRefs, "Bearer "+testSecret, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("approved discovery = %d, want 200", resp.StatusCode)
	}
	resp, _ = doRequest(t, http.MethodGet, infoRefs, "Bearer "+testSecret, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("second approved discovery = %d, want the window grant to cover it", resp.StatusCode)
	}
	if got := upstream.totalHits(); got == 0 {
		t.Fatal("approved fetch never reached upstream")
	}
	items, err := handler.grants.ListForClient("agent")
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 {
		t.Fatalf("grants = %d, want 1 window grant for the whole session", len(items))
	}
}

// TestGitFetchWithoutApprovalStaysDenied confirms an unapproved retry keeps
// failing closed without creating duplicate requests.
func TestGitFetchWithoutApprovalStaysDenied(t *testing.T) {
	dir := t.TempDir()
	var auditLog bytes.Buffer
	handler, err := New(Options{
		Config: config.Config{HFToken: testToken, Clients: []config.Client{{Name: "agent", Secret: testSecret}},
			Operators: []config.Client{{Name: "onur", Secret: fetchApprovalOperatorSecret}},
			StateDir:  filepath.Join(dir, "state"), MaxPackBytes: 25 * 1024 * 1024, HFTimeout: 10 * time.Second},
		Scope: fetchRequestScope(t), Audit: audit.New(&auditLog), UpstreamBaseURL: "http://127.0.0.1:1",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = handler.Close() }()
	broker := httptest.NewServer(handler)
	defer broker.Close()

	infoRefs := broker.URL + "/datasets/acme/repo.git/info/refs?service=git-upload-pack"
	for attempt := 0; attempt < 2; attempt++ {
		resp, body := doRequest(t, http.MethodGet, infoRefs, "Bearer "+testSecret, nil)
		if resp.StatusCode != http.StatusForbidden || !strings.Contains(body, "approval required (") {
			t.Fatalf("attempt %d = %d %q", attempt+1, resp.StatusCode, body)
		}
	}
	items, err := handler.grants.ListForClient("agent")
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 {
		t.Fatalf("grants = %d, want 1 shared pending approval across retries", len(items))
	}
}

func newFetchApprovalOperator(t *testing.T, handler *Server) *operatorclient.Client {
	t.Helper()
	operatorServer := httptest.NewServer(handler.OperatorHandler())
	t.Cleanup(operatorServer.Close)
	client, err := operatorclient.New(strings.Replace(operatorServer.URL, "http://", "tcp://", 1), fetchApprovalOperatorSecret, operatorServer.Client())
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func approvePendingFetch(t *testing.T, handler *Server, operator *operatorclient.Client) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		page, err := operator.List(t.Context(), operatorv1.Query{Status: grants.StatusGroupPending})
		if err != nil {
			t.Fatal(err)
		}
		if len(page.Requests) == 1 {
			approved, err := operator.Decide(t.Context(), page.Requests[0].ID, operatorv1.ActionApprove, operatorv1.Decision{
				ExpectedRevision: page.Requests[0].Revision, IdempotencyKey: "test-fetch-approve",
			})
			if err != nil || approved.Status != grants.StatusActive {
				t.Fatalf("Decide() = %+v, %v", approved, err)
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("timed out waiting for the fetch approval request")
}
