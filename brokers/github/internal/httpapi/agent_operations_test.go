package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/osolmaz/brokerkit/agentconformance"
	"github.com/osolmaz/brokerkit/agentops"
	"github.com/osolmaz/brokerkit/agentv1"
	"github.com/osolmaz/brokerkit/brokers/github/internal/config"
	"github.com/osolmaz/brokerkit/brokers/github/internal/policy"
	"github.com/osolmaz/brokerkit/grants"
	"github.com/osolmaz/brokerkit/notify"
	"github.com/osolmaz/brokerkit/operatorv1"
)

func TestAgentV1Conformance(t *testing.T) {
	stateDirectory := filepath.Join(t.TempDir(), "state")
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/repos/dutifuldev/gh-broker/pulls" || r.Header.Get("Authorization") != "Bearer "+testGitHubToken {
			t.Fatalf("upstream request = %s, auth %q", r.URL.Path, r.Header.Get("Authorization"))
		}
		var payload pullRequestArguments
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil || payload.Title != "Agent cutover" || payload.Head != "bob/work" || payload.Base != "main" {
			t.Fatalf("upstream payload = %#v, %v", payload, err)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{"number": 42, "html_url": "https://github.com/dutifuldev/gh-broker/pull/42"})
	}))
	defer upstream.Close()
	upstreamURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}

	var current *Server
	start := func() (agentconformance.Endpoint, error) {
		handler, err := New(config.Config{
			ClientID: "bob", SharedSecret: testSharedSecret, GitHubToken: testGitHubToken, StateDir: stateDirectory,
			OperatorID: "operator", OperatorSecret: "operator-secret-abcdefghijklmnopqrstuvwxyz",
		}, requestPRPolicy(t))
		if err != nil {
			return agentconformance.Endpoint{}, err
		}
		handler.githubAPIBaseURL = upstreamURL
		handler.githubClient = upstream.Client()
		ctx, cancel := context.WithCancel(context.Background())
		handler.Start(ctx)
		current = handler
		server := httptest.NewServer(handler.Handler())
		return agentconformance.Endpoint{BaseURL: server.URL, HTTPClient: server.Client(), Close: func() error {
			server.Close()
			cancel()
			handler.backgroundWorkers.Wait()
			return handler.Close()
		}}, nil
	}

	agentconformance.RunAgentV1(t, agentconformance.Fixture{
		Start: start, Token: testSharedSecret, WaitTime: 5 * time.Second,
		Request: agentv1.SubmitRequest{
			IdempotencyKey: "github-conformance", Operation: "pr.create",
			Target:    json.RawMessage(`{"kind":"repo","owner":"dutifuldev","name":"gh-broker"}`),
			Arguments: json.RawMessage(`{"title":"Agent cutover","body":"ready","head":"bob/work","base":"main"}`),
			Reason:    "verify GitHub Agent V1 lifecycle",
		},
		Approve: func(ctx context.Context, operation agentv1.Operation) error {
			grant, err := current.grants.Get(operation.ApprovalID)
			if err != nil {
				return err
			}
			_, err = current.control.Decisions.Decide(ctx, grant.ID, operatorv1.ActionApprove, "operator", operatorv1.Decision{
				ExpectedRevision: grant.Revision, IdempotencyKey: "approve-github-conformance",
			})
			return err
		},
		Verify: func(t *testing.T, operation agentv1.Operation) {
			t.Helper()
			if operation.State != agentv1.StateSucceeded || !strings.Contains(string(operation.Result), `"number":42`) {
				t.Fatalf("terminal operation = %#v", operation)
			}
		},
	})
}

func TestAgentPullRequestValidation(t *testing.T) {
	valid := agentv1.SubmitRequest{
		Target:    json.RawMessage(`{"kind":"repo","owner":"dutifuldev","name":"gh-broker"}`),
		Arguments: json.RawMessage(`{"title":"work","head":"bob/work","base":"main"}`),
	}
	if _, _, attrs, err := decodePullRequestOperation(valid); err != nil || attrs["head_ref"] != "refs/heads/bob/work" {
		t.Fatalf("valid operation attrs = %#v, %v", attrs, err)
	}
	for _, change := range []func(*agentv1.SubmitRequest){
		func(request *agentv1.SubmitRequest) {
			request.Target = json.RawMessage(`{"kind":"repo","owner":"bad/name","name":"repo"}`)
		},
		func(request *agentv1.SubmitRequest) {
			request.Arguments = json.RawMessage(`{"title":"work","head":"evil:bob/work","base":"main"}`)
		},
		func(request *agentv1.SubmitRequest) {
			request.Arguments = json.RawMessage(`{"title":"","head":"bob/work","base":"main"}`)
		},
		func(request *agentv1.SubmitRequest) {
			request.Target = json.RawMessage(`{"kind":"repo","owner":"dutifuldev","name":"gh-broker","extra":true}`)
		},
		func(request *agentv1.SubmitRequest) {
			request.Arguments = json.RawMessage(strings.Repeat(" ", maxAgentGitHubBody+1))
		},
	} {
		request := valid
		change(&request)
		if _, _, _, err := decodePullRequestOperation(request); err == nil {
			t.Fatal("invalid pull request operation was accepted")
		}
	}
}

func TestAgentPullRequestDirectAllowAndDenial(t *testing.T) {
	allow, err := policy.New(policy.Scope{Rules: []policy.Rule{{
		ID: "allow-pr", Effect: policy.EffectAllow, Clients: []string{"bob"}, Operations: []policy.Operation{policy.OperationPullRequestCreate},
		Targets: []policy.Target{{Kind: "repo", Owner: "dutifuldev", Name: "gh-broker"}},
		Attrs:   map[string][]string{"refs": {"refs/heads/bob/work"}, "head_refs": {"refs/heads/bob/work"}, "base_refs": {"refs/heads/main"}},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	server := newTestServerWithPolicyAndHandler(t, allow, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"number":7,"html_url":"https://github.com/dutifuldev/gh-broker/pull/7"}`))
	})
	operation, _, err := server.submitAgentOperation(t.Context(), "bob", validPullRequestSubmission("allow"))
	if err != nil || operation.State != agentv1.StateApproved {
		t.Fatalf("allowed submit = %#v, %v", operation, err)
	}
	server.advanceAgentOperation(t.Context(), operation)
	completed, err := server.operations.GetByID(operation.ID)
	if err != nil || completed.State != agentv1.StateSucceeded {
		t.Fatalf("completed = %#v, %v", completed, err)
	}

	deny, err := policy.New(policy.Scope{Rules: []policy.Rule{{
		ID: "deny-pr", Effect: policy.EffectDeny, Clients: []string{"bob"}, Operations: []policy.Operation{policy.OperationPullRequestCreate},
		Targets: []policy.Target{{Kind: "repo", Owner: "dutifuldev", Name: "gh-broker"}},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	deniedServer := newTestServerWithPolicyAndHandler(t, deny, func(http.ResponseWriter, *http.Request) {})
	denied, _, err := deniedServer.submitAgentOperation(t.Context(), "bob", validPullRequestSubmission("denied"))
	if err != nil || denied.State != agentv1.StateDenied {
		t.Fatalf("denied submit = %#v, %v", denied, err)
	}

	failing := newTestServerWithPolicyAndHandler(t, allow, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusForbidden) })
	failed, _, err := failing.submitAgentOperation(t.Context(), "bob", validPullRequestSubmission("upstream-denied"))
	if err != nil {
		t.Fatal(err)
	}
	failing.advanceAgentOperation(t.Context(), failed)
	failed, _ = failing.operations.GetByID(failed.ID)
	if failed.State != agentv1.StateFailed || failed.Error == nil || failed.Error.Code != "upstream_rejected" {
		t.Fatalf("upstream rejection = %#v", failed)
	}
}

func TestAgentApprovalNotificationsFailClosed(t *testing.T) {
	for _, test := range []struct {
		name     string
		notifier *captureNotifier
		failed   bool
	}{
		{name: "delivered", notifier: &captureNotifier{}},
		{name: "send failure", notifier: &captureNotifier{sendErr: errors.New("unavailable")}, failed: true},
		{name: "invalid reference", notifier: &captureNotifier{invalidRef: true}, failed: true},
		{name: "not configured", failed: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := newTestServerWithPolicyAndHandler(t, requestPRPolicy(t), func(http.ResponseWriter, *http.Request) {})
			if test.notifier != nil {
				server.notifier = test.notifier
			}
			operation, _, err := server.submitAgentOperation(t.Context(), "bob", validPullRequestSubmission(test.name))
			if err != nil {
				t.Fatal(err)
			}
			if test.failed && operation.State != agentv1.StateFailed {
				t.Fatalf("operation = %#v, want failed", operation)
			}
			if !test.failed {
				if operation.State != agentv1.StatePending || operation.ApprovalID == "" || len(test.notifier.messages) != 1 {
					t.Fatalf("operation = %#v, messages = %d", operation, len(test.notifier.messages))
				}
				if err := server.existingAgentNotification(operation.ApprovalID); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestAgentCancellationClosesApproval(t *testing.T) {
	for _, active := range []bool{false, true} {
		server := newTestServerWithPolicyAndHandler(t, requestPRPolicy(t), func(http.ResponseWriter, *http.Request) {})
		server.operatorConfigured = true
		operation, _, err := server.submitAgentOperation(t.Context(), "bob", validPullRequestSubmission(fmt.Sprintf("cancel-%t", active)))
		if err != nil || operation.ApprovalID == "" {
			t.Fatalf("submit active=%t: %#v, %v", active, operation, err)
		}
		grant, _ := server.grants.Get(operation.ApprovalID)
		if active {
			_, err = server.control.Decisions.Decide(t.Context(), grant.ID, operatorv1.ActionApprove, "operator", operatorv1.Decision{
				ExpectedRevision: grant.Revision, IdempotencyKey: "approve-before-cancel",
			})
			if err != nil {
				t.Fatal(err)
			}
		}
		canceled, err := server.cancelAgentOperation(t.Context(), "bob", operation.ID)
		closed, getErr := server.grants.Get(operation.ApprovalID)
		want := grants.StatusCanceled
		if active {
			want = grants.StatusRevoked
		}
		if err != nil || getErr != nil || canceled.State != agentv1.StateCanceled || closed.Status != want {
			t.Fatalf("cancel active=%t: operation=%#v grant=%#v err=%v/%v", active, canceled, closed, err, getErr)
		}
	}
}

func TestConcurrentAgentReplayCreatesOneApproval(t *testing.T) {
	server := newTestServerWithPolicyAndHandler(t, requestPRPolicy(t), func(http.ResponseWriter, *http.Request) {})
	server.operatorConfigured = true
	type submissionResult struct {
		operation agentv1.Operation
		err       error
	}
	results := make(chan submissionResult, 2)
	var workers sync.WaitGroup
	for range 2 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			operation, _, err := server.submitAgentOperation(t.Context(), "bob", validPullRequestSubmission("concurrent"))
			results <- submissionResult{operation: operation, err: err}
		}()
	}
	workers.Wait()
	close(results)
	var operationID string
	for result := range results {
		if result.err != nil || result.operation.ApprovalID == "" {
			t.Fatalf("concurrent submission = %#v, %v", result.operation, result.err)
		}
		if operationID != "" && result.operation.ID != operationID {
			t.Fatalf("operation IDs = %q and %q", operationID, result.operation.ID)
		}
		operationID = result.operation.ID
	}
	stored, err := server.grants.ListForClient("bob")
	if err != nil || len(stored) != 1 {
		t.Fatalf("stored grants = %#v, %v", stored, err)
	}
}

func TestAgentApprovalTransitionsAndReservations(t *testing.T) {
	server := newTestServerWithPolicyAndHandler(t, requestPRPolicy(t), func(http.ResponseWriter, *http.Request) {})
	submission := validPullRequestSubmission("transition")
	operation, _, err := server.operations.Submit(agentops.Submit{
		Broker: "gh-broker", ClientID: "bob", IdempotencyKey: "transition", Operation: "pr.create",
		Target: submission.Target, Arguments: submission.Arguments, Reason: "test", Presentation: agentv1.Presentation{Title: "test"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if reserved, ok := server.reserveAgentApproval(operation); reserved || !ok {
		t.Fatalf("direct reservation = %v, %v", reserved, ok)
	}
	request := grants.Request{
		Client: "bob", ClientRequestID: operation.ID, Operation: "pr.create",
		Target: policy.CoreTarget(policy.Target{Kind: "repo", Owner: "dutifuldev", Name: "gh-broker"}),
		Attrs:  map[string][]string{"ref": {"refs/heads/bob/work"}, "head_ref": {"refs/heads/bob/work"}, "base_ref": {"refs/heads/main"}},
		Reason: "test", Duration: 5 * time.Minute, PendingTimeout: time.Minute, MaxUses: 1,
	}
	result, _, err := server.requestGrant(request)
	if err != nil {
		t.Fatal(err)
	}
	operation, err = server.operations.SetApproval(operation.ID, result.Grant.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got := server.syncAgentApproval(operation); got.State != agentv1.StatePending {
		t.Fatalf("pending sync = %#v", got)
	}
	_, err = server.control.Decisions.Decide(t.Context(), result.Grant.ID, operatorv1.ActionApprove, "operator", operatorv1.Decision{
		ExpectedRevision: result.Grant.Revision, IdempotencyKey: "approve-transition",
	})
	if err != nil {
		t.Fatal(err)
	}
	approved := server.syncAgentApproval(operation)
	if approved.State != agentv1.StateApproved {
		t.Fatalf("approved sync = %#v", approved)
	}
	reserved, ok := server.reserveAgentApproval(approved)
	if !reserved || !ok {
		t.Fatalf("approved reservation = %v, %v", reserved, ok)
	}
	if _, err := server.grants.ReleaseUse(result.Grant.ID); err != nil {
		t.Fatal(err)
	}
	reservedGrants, err := server.reserveGrantUse(result.Grant.ID)
	if err != nil || len(reservedGrants) != 1 {
		t.Fatalf("grant reservation = %#v, %v", reservedGrants, err)
	}
	server.releaseGrantUses(reservedGrants)
	grant, err := server.grants.Get(result.Grant.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := server.control.Decisions.Decide(t.Context(), grant.ID, operatorv1.ActionRevoke, "operator", operatorv1.Decision{
		ExpectedRevision: grant.Revision, IdempotencyKey: "revoke-transition",
	}); err != nil {
		t.Fatal(err)
	}
	if got := server.syncAgentApproval(approved); got.State != agentv1.StateCanceled {
		t.Fatalf("revoked sync = %#v", got)
	}
	deniedOperation, _, err := server.operations.Submit(agentops.Submit{
		Broker: "gh-broker", ClientID: "bob", IdempotencyKey: "denied-transition", Operation: "pr.create",
		Target: submission.Target, Arguments: submission.Arguments, Reason: "test", Presentation: agentv1.Presentation{Title: "test"},
	})
	if err != nil {
		t.Fatal(err)
	}
	deniedRequest := request
	deniedRequest.ClientRequestID = deniedOperation.ID
	deniedResult, _, err := server.requestGrant(deniedRequest)
	if err != nil {
		t.Fatal(err)
	}
	deniedOperation, err = server.operations.SetApproval(deniedOperation.ID, deniedResult.Grant.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := server.control.Decisions.Decide(t.Context(), deniedResult.Grant.ID, operatorv1.ActionDeny, "operator", operatorv1.Decision{
		ExpectedRevision: deniedResult.Grant.Revision, IdempotencyKey: "deny-transition",
	}); err != nil {
		t.Fatal(err)
	}
	if got := server.syncAgentApproval(deniedOperation); got.State != agentv1.StateDenied {
		t.Fatalf("denied sync = %#v", got)
	}
	list := do(t, server, http.MethodGet, "/api/grants", bearerAuth())
	if list.Code != http.StatusOK || !strings.Contains(list.Body.String(), grant.ID) {
		t.Fatalf("grant list = %d %s", list.Code, list.Body.String())
	}
}

func TestAdvanceAgentOperationRejectsInvalidStoredPayload(t *testing.T) {
	server := newTestServer(t)
	operation, _, err := server.operations.Submit(agentops.Submit{
		Broker: "gh-broker", ClientID: "bob", IdempotencyKey: "invalid-stored", Operation: "pr.create",
		Target: json.RawMessage(`{}`), Arguments: json.RawMessage(`{}`), Reason: "test", Presentation: agentv1.Presentation{Title: "test"},
	})
	if err != nil {
		t.Fatal(err)
	}
	server.advanceAgentOperation(t.Context(), operation)
	failed, err := server.operations.GetByID(operation.ID)
	if err != nil || failed.State != agentv1.StateFailed || failed.Error == nil || failed.Error.Code != "invalid_stored_operation" {
		t.Fatalf("invalid stored operation = %#v, %v", failed, err)
	}
}

func TestDecodePullRequestResponse(t *testing.T) {
	for _, test := range []struct {
		status     int
		body       string
		definitive bool
		ok         bool
	}{
		{status: http.StatusCreated, body: `{"number":1,"html_url":"https://example.test/pr/1"}`, definitive: true, ok: true},
		{status: http.StatusForbidden, body: `{}`, definitive: true},
		{status: http.StatusBadGateway, body: `{}`},
		{status: http.StatusCreated, body: `{}`},
		{status: http.StatusCreated, body: `{"number":1}`},
		{status: http.StatusCreated, body: strings.Repeat("x", maxAgentGitHubBody+1)},
	} {
		response := &http.Response{StatusCode: test.status, Body: io.NopCloser(strings.NewReader(test.body))}
		result, definitive, err := decodePullRequestResponse(response)
		if (err == nil) != test.ok || definitive != test.definitive || test.ok && result.Number != 1 {
			t.Fatalf("decode = %#v, %v, %v", result, definitive, err)
		}
	}
}

func TestFailPullRequestExecutionClassifiesResult(t *testing.T) {
	server := newTestServer(t)
	for _, definitive := range []bool{true, false} {
		operation, _, err := server.operations.Submit(agentops.Submit{
			Broker: "gh-broker", ClientID: "bob", IdempotencyKey: fmt.Sprintf("failure-%v", definitive), Operation: "pr.create",
			Target: json.RawMessage(`{}`), Arguments: json.RawMessage(`{}`), Reason: "test", Presentation: agentv1.Presentation{Title: "test"},
		})
		if err != nil {
			t.Fatal(err)
		}
		server.failPullRequestExecution(operation, false, definitive)
		failed, _ := server.operations.GetByID(operation.ID)
		if failed.State != agentv1.StateFailed || failed.Error == nil {
			t.Fatalf("failed operation = %#v", failed)
		}
	}
}

func validPullRequestSubmission(key string) agentv1.SubmitRequest {
	return agentv1.SubmitRequest{
		IdempotencyKey: key, Operation: "pr.create",
		Target:    json.RawMessage(`{"kind":"repo","owner":"dutifuldev","name":"gh-broker"}`),
		Arguments: json.RawMessage(`{"title":"work","head":"bob/work","base":"main"}`), Reason: "test pull request",
	}
}

var _ notify.Notifier = (*captureNotifier)(nil)
