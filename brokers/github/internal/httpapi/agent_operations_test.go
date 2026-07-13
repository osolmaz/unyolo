package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/osolmaz/brokerkit/agentconformance"
	"github.com/osolmaz/brokerkit/agentv1"
	"github.com/osolmaz/brokerkit/brokers/github/internal/config"
	"github.com/osolmaz/brokerkit/brokers/github/internal/policy"
	"github.com/osolmaz/brokerkit/operatorv1"
)

func TestGeneratedAgentV1Conformance(t *testing.T) {
	stateDirectory := filepath.Join(t.TempDir(), "state")
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/repos/dutifuldev/gh-broker/pulls" || request.Header.Get("Authorization") != "Bearer "+testGitHubToken {
			t.Fatalf("upstream request = %s, auth %q", request.URL.Path, request.Header.Get("Authorization"))
		}
		var payload map[string]any
		if err := json.NewDecoder(request.Body).Decode(&payload); err != nil || payload["title"] != "Agent cutover" || payload["head"] != "bob/work" || payload["base"] != "main" {
			t.Fatalf("upstream payload = %#v, %v", payload, err)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id":7,"node_id":"PR_7","number":42,"state":"open","url":"https://api.github.test/repos/dutifuldev/gh-broker/pulls/42","created_at":"2026-07-14T00:00:00Z","updated_at":"2026-07-14T00:00:00Z"}`))
	}))
	defer upstream.Close()

	var current *Server
	start := func() (agentconformance.Endpoint, error) {
		handler, err := New(config.Config{
			ClientID: "bob", SharedSecret: testSharedSecret, GitHubToken: testGitHubToken,
			GitHubTokenFile: "/protected/github-token", StateDir: stateDirectory,
			GitHubAPIBaseURL: upstream.URL, GitHubWebBaseURL: upstream.URL,
			OperatorID: "operator", OperatorSecret: "operator-secret-abcdefghijklmnopqrstuvwxyz",
		}, generatedRequestPolicy(t))
		if err != nil {
			return agentconformance.Endpoint{}, err
		}
		ctx, cancel := context.WithCancel(context.Background())
		handler.Start(ctx)
		current = handler
		server := httptest.NewServer(handler.Handler())
		return agentconformance.Endpoint{BaseURL: server.URL, HTTPClient: server.Client(), Close: func() error {
			server.Close()
			cancel()
			return handler.Close()
		}}, nil
	}

	agentconformance.RunAgentV1(t, agentconformance.Fixture{
		Start: start, Token: testSharedSecret, WaitTime: 5 * time.Second,
		Request: generatedPullRequestSubmission("github-conformance"),
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

func TestGeneratedAgentDirectAllowAndDenial(t *testing.T) {
	allow := generatedPolicy(t, policy.EffectAllow)
	server := newTestServerWithPolicyAndHandler(t, allow, func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/repos/dutifuldev/gh-broker/pulls" {
			t.Fatalf("upstream path = %q", request.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"number":7,"state":"open","url":"https://api.github.test/pulls/7"}`))
	})
	operation, _, err := server.submitAgentOperation(t.Context(), "bob", generatedPullRequestSubmission("allow"))
	if err != nil || operation.State != agentv1.StateApproved {
		t.Fatalf("allowed submit = %#v, %v", operation, err)
	}
	server.operationRuntime.Advance(t.Context(), operation)
	completed, err := server.operations.GetByID(operation.ID)
	if err != nil || completed.State != agentv1.StateSucceeded {
		t.Fatalf("completed = %#v, %v", completed, err)
	}

	deniedServer := newTestServerWithPolicyAndHandler(t, generatedPolicy(t, policy.EffectDeny), func(http.ResponseWriter, *http.Request) {
		t.Fatal("denied operation reached upstream")
	})
	denied, _, err := deniedServer.submitAgentOperation(t.Context(), "bob", generatedPullRequestSubmission("deny"))
	if err != nil || denied.State != agentv1.StateDenied || denied.Error == nil || denied.Error.Code != "operation_policy_denied" {
		t.Fatalf("denied submit = %#v, %v", denied, err)
	}
}

func TestGeneratedAgentRejectsUnknownAndInvalidOperations(t *testing.T) {
	server := newTestServerWithPolicyAndHandler(t, generatedPolicy(t, policy.EffectAllow), func(http.ResponseWriter, *http.Request) {})
	unknown := generatedPullRequestSubmission("unknown")
	unknown.Operation = "github.raw.request"
	if _, _, err := server.submitAgentOperation(t.Context(), "bob", unknown); err == nil || !strings.Contains(err.Error(), "not registered") {
		t.Fatalf("unknown operation error = %v", err)
	}
	invalid := generatedPullRequestSubmission("invalid")
	invalid.Arguments = json.RawMessage(`{"input":{"title":"work","head":"bob/work","base":"main","unexpected":true}}`)
	if _, _, err := server.submitAgentOperation(t.Context(), "bob", invalid); err == nil {
		t.Fatal("invalid generated arguments were accepted")
	}
}

func generatedPullRequestSubmission(key string) agentv1.SubmitRequest {
	return agentv1.SubmitRequest{
		IdempotencyKey: key,
		Operation:      "pull_request.create",
		Target:         json.RawMessage(`{"kind":"repo","owner":"dutifuldev","name":"gh-broker"}`),
		Arguments:      json.RawMessage(`{"input":{"title":"Agent cutover","body":"ready","head":"bob/work","base":"main"}}`),
		Reason:         "verify generated GitHub operation lifecycle",
	}
}

func generatedRequestPolicy(t *testing.T) *policy.Policy {
	t.Helper()
	return generatedPolicy(t, policy.EffectRequest)
}

func generatedPolicy(t *testing.T, effect policy.Effect) *policy.Policy {
	t.Helper()
	value, err := policy.New(policy.Scope{Rules: []policy.Rule{{
		ID: "generated-pull-request", Effect: effect, Clients: []string{"bob"},
		Operations: []policy.Operation{policy.OperationPullRequestCreate},
		Targets:    []policy.Target{{Kind: "repo", Owner: "dutifuldev", Name: "gh-broker"}},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	return value
}
