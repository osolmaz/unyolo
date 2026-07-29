package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/osolmaz/unyolo/agent/api"
	"github.com/osolmaz/unyolo/agent/conformance"
	"github.com/osolmaz/unyolo/agent/v1"
	"github.com/osolmaz/unyolo/authorization/grants"
	corepolicy "github.com/osolmaz/unyolo/authorization/policy"
	"github.com/osolmaz/unyolo/brokers/github/internal/config"
	"github.com/osolmaz/unyolo/brokers/github/internal/ghplan"
	"github.com/osolmaz/unyolo/brokers/github/internal/githubauth"
	"github.com/osolmaz/unyolo/brokers/github/internal/operations"
	"github.com/osolmaz/unyolo/brokers/github/internal/policy"
	"github.com/osolmaz/unyolo/operator/v1"
)

type lifecycleContextKey struct{}

func TestGeneratedAgentV1Conformance(t *testing.T) {
	stateDirectory := filepath.Join(t.TempDir(), "state")
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/repos/osolmaz/gh-broker/pulls" || request.Header.Get("Authorization") != "Bearer "+testGitHubToken {
			t.Fatalf("upstream request = %s, auth %q", request.URL.Path, request.Header.Get("Authorization"))
		}
		var payload map[string]any
		if err := json.NewDecoder(request.Body).Decode(&payload); err != nil || payload["title"] != "Agent cutover" || payload["head"] != "bob/work" || payload["base"] != "main" {
			t.Fatalf("upstream payload = %#v, %v", payload, err)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id":7,"node_id":"PR_7","number":42,"state":"open","url":"https://api.github.test/repos/osolmaz/gh-broker/pulls/42","created_at":"2026-07-14T00:00:00Z","updated_at":"2026-07-14T00:00:00Z"}`))
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

func TestGeneratedWindowGrantAuthorizesTwoIndependentOperations(t *testing.T) {
	upstreamCalls := 0
	server := newTestServerWithPolicyAndHandler(t, generatedRequestPolicy(t), func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/repos/osolmaz/gh-broker/pulls" {
			t.Fatalf("unexpected upstream request %s", request.URL.Path)
		}
		upstreamCalls++
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"number":42,"state":"open","url":"https://api.github.test/pulls/42"}`))
	})
	server.notifier = &captureNotifier{}
	runtime, err := server.newOperationRuntime()
	if err != nil {
		t.Fatal(err)
	}
	server.operationRuntime = runtime

	first, _, err := server.submitAgentOperation(t.Context(), "bob", generatedPullRequestSubmission("window-first"))
	if err != nil || first.State != agentv1.StatePending {
		t.Fatalf("first submission = %+v, %v", first, err)
	}
	grant, err := server.grants.Get(first.ApprovalID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := server.control.Decisions.Decide(t.Context(), grant.ID, operatorv1.ActionApprove, "operator", operatorv1.Decision{
		ExpectedRevision: grant.Revision, IdempotencyKey: "approve-window",
	}); err != nil {
		t.Fatal(err)
	}
	server.operationRuntime.Advance(t.Context(), first)
	first, _ = server.operations.GetByID(first.ID)
	if first.State != agentv1.StateSucceeded {
		t.Fatalf("first operation = %+v", first)
	}

	second, _, err := server.submitAgentOperation(t.Context(), "bob", generatedPullRequestSubmission("window-second"))
	if err != nil || second.State != agentv1.StateApproved || second.ApprovalID != grant.ID || second.PlanDigest == first.PlanDigest {
		t.Fatalf("second submission = %+v, %v", second, err)
	}
	server.operationRuntime.Advance(t.Context(), second)
	second, _ = server.operations.GetByID(second.ID)
	stored, grantErr := server.grants.Get(grant.ID)
	uses, usesErr := server.grants.ListUses(grant.ID)
	if second.State != agentv1.StateSucceeded || upstreamCalls != 2 || grantErr != nil || stored.UsedCount != 2 ||
		stored.ReservedCount != 0 || usesErr != nil || len(uses) != 2 {
		t.Fatalf("second operation = %+v; calls=%d grant=%+v, %v uses=%+v, %v", second, upstreamCalls, stored, grantErr, uses, usesErr)
	}
}

func TestAdminMergeRequiresApprovalAndExecutesExactRevision(t *testing.T) {
	const headSHA = "1111111111111111111111111111111111111111"
	const baseSHA = "2222222222222222222222222222222222222222"
	upstreamCalls := 0
	brokerPolicy, err := policy.New(policy.Scope{Rules: []policy.Rule{{
		ID: "admin-merge", Effect: policy.EffectRequest, Clients: []string{"bob"},
		Operations: []policy.Operation{policy.Operation("pull_request.merge_admin")},
		Targets:    []policy.Target{{Kind: "pull_request", Owner: "osolmaz", Repo: "solmazio", Number: 98}},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	server := newTestServerWithPolicyAndHandler(t, brokerPolicy, func(w http.ResponseWriter, request *http.Request) {
		upstreamCalls++
		switch request.URL.Path {
		case "/user":
			_, _ = w.Write([]byte(`{"id":2453968,"login":"osolmaz"}`))
		case "/repos/osolmaz/solmazio/pulls/98":
			_, _ = w.Write([]byte(`{"id":4081694590,"number":98,"node_id":"PR_node","state":"open","draft":false,"merged":false,"mergeable":true,"mergeable_state":"blocked","head":{"sha":"` + headSHA + `"},"base":{"sha":"` + baseSHA + `","ref":"main"}}`))
		case "/graphql":
			_, _ = w.Write([]byte(`{"data":{"mergePullRequest":{"__typename":"MergePullRequestPayload"}}}`))
		default:
			t.Fatalf("unexpected upstream request %s", request.URL.Path)
		}
	})
	server.notifier = &captureNotifier{}
	runtime, err := server.newOperationRuntime()
	if err != nil {
		t.Fatal(err)
	}
	server.operationRuntime = runtime
	submission := agentv1.SubmitRequest{IdempotencyKey: "admin-merge-98", Operation: "pull_request.merge_admin",
		Target:    json.RawMessage(`{"kind":"pull_request","owner":"osolmaz","repo":"solmazio","number":98}`),
		Arguments: json.RawMessage(`{"merge_method":"squash"}`), Reason: "merge the exact reviewed revision"}
	operation, _, err := server.submitAgentOperation(t.Context(), "bob", submission)
	if err != nil || operation.State != agentv1.StatePending || operation.ApprovalID == "" || upstreamCalls != 2 {
		t.Fatalf("pending admin merge = %+v calls=%d err=%v", operation, upstreamCalls, err)
	}
	grant, err := server.grants.Get(operation.ApprovalID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := server.control.Decisions.Decide(t.Context(), grant.ID, operatorv1.ActionApprove, "operator", operatorv1.Decision{
		ExpectedRevision: grant.Revision, IdempotencyKey: "approve-admin-merge-98",
	}); err != nil {
		t.Fatal(err)
	}
	server.operationRuntime.Advance(t.Context(), operation)
	completed, err := server.operations.GetByID(operation.ID)
	if err != nil || completed.State != agentv1.StateSucceeded || !strings.Contains(string(completed.Result), `"head_sha":"`+headSHA+`"`) || upstreamCalls != 5 {
		t.Fatalf("completed admin merge = %+v calls=%d err=%v", completed, upstreamCalls, err)
	}
}

func TestGeneratedAgentDirectAllowAndDenial(t *testing.T) {
	allow := generatedPolicy(t, policy.EffectAllow)
	server := newTestServerWithPolicyAndHandler(t, allow, func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/repos/osolmaz/gh-broker/pulls" {
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

func TestCurrentCredentialResolverRejectsMissingProvider(t *testing.T) {
	if _, err := (&currentGitHubCredentialResolver{}).snapshot(ghplan.Plan{}); err == nil {
		t.Fatal("missing GitHub credential provider was accepted")
	}
}

func TestReusedRuntimeGrantBounds(t *testing.T) {
	for name, test := range map[string]struct {
		grant        grants.Grant
		mode         corepolicy.GrantMode
		wantDuration time.Duration
		wantErr      bool
	}{
		"approved duration": {
			grant: grants.Grant{Metadata: map[string]string{grants.MetadataMode: string(corepolicy.GrantModeWindow)},
				RequestedDuration: 5 * time.Minute, Duration: 10 * time.Minute, PendingTimeout: time.Minute},
			mode: corepolicy.GrantModeWindow, wantDuration: 10 * time.Minute,
		},
		"legacy duration fallback": {
			grant: grants.Grant{Metadata: map[string]string{grants.MetadataMode: string(corepolicy.GrantModeWindow)},
				Duration: 10 * time.Minute, PendingTimeout: time.Minute},
			mode: corepolicy.GrantModeWindow, wantDuration: 10 * time.Minute,
		},
		"mismatched mode": {
			grant: grants.Grant{Metadata: map[string]string{grants.MetadataMode: string(corepolicy.GrantModeExecution)}},
			mode:  corepolicy.GrantModeWindow, wantErr: true,
		},
		"execution grant": {
			grant: grants.Grant{Metadata: map[string]string{grants.MetadataMode: string(corepolicy.GrantModeExecution)}},
			mode:  corepolicy.GrantModeExecution, wantErr: true,
		},
	} {
		t.Run(name, func(t *testing.T) {
			duration, pending, err := reusedRuntimeGrantBounds(test.grant, test.mode)
			if (err != nil) != test.wantErr || duration != test.wantDuration {
				t.Fatalf("bounds = %s, %s, %v", duration, pending, err)
			}
			if !test.wantErr && pending != time.Minute {
				t.Fatalf("pending = %s", pending)
			}
		})
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

func TestGeneratedAgentCancellation(t *testing.T) {
	server := newTestServerWithPolicyAndHandler(t, generatedPolicy(t, policy.EffectAllow), func(http.ResponseWriter, *http.Request) {
		t.Fatal("canceled operation reached upstream")
	})
	operation, _, err := server.submitAgentOperation(t.Context(), "bob", generatedPullRequestSubmission("cancel"))
	if err != nil || operation.State != agentv1.StateApproved {
		t.Fatalf("submitted operation = %#v, %v", operation, err)
	}
	canceled, err := server.cancelAgentOperation(t.Context(), "bob", operation.ID)
	if err != nil || canceled.State != agentv1.StateCanceled {
		t.Fatalf("canceled operation = %#v, %v", canceled, err)
	}
	stored, err := server.operations.GetByID(operation.ID)
	if err != nil || stored.State != agentv1.StateCanceled {
		t.Fatalf("stored operation = %#v, %v", stored, err)
	}

	requestServer := newTestServerWithPolicyAndHandler(t, generatedRequestPolicy(t), func(http.ResponseWriter, *http.Request) {
		t.Fatal("pending operation reached upstream")
	})
	requestServer.notifier = &captureNotifier{}
	runtime, err := requestServer.newOperationRuntime()
	if err != nil {
		t.Fatal(err)
	}
	requestServer.operationRuntime = runtime
	pending, _, err := requestServer.submitAgentOperation(t.Context(), "bob", generatedPullRequestSubmission("cancel-grant"))
	if err != nil || pending.State != agentv1.StatePending || pending.ApprovalID == "" {
		t.Fatalf("pending operation = %#v, %v", pending, err)
	}
	grant, err := requestServer.grants.Get(pending.ApprovalID)
	if err != nil {
		t.Fatal(err)
	}
	if err := requestServer.cancelGrantForClient(grant, "bob"); err != nil {
		t.Fatal(err)
	}
	grant, err = requestServer.grants.Get(grant.ID)
	if err != nil || grant.Status != grants.StatusCanceled {
		t.Fatalf("canceled grant = %#v, %v", grant, err)
	}
}

func TestGeneratedRuntimeErrorMapping(t *testing.T) {
	partial := &operations.PossiblePartialError{Err: errors.New("uncertain")}
	if definitiveExecutionFailure(nil) || definitiveExecutionFailure(partial) || !definitiveExecutionFailure(errors.New("rejected")) {
		t.Fatal("definitive execution classification drifted")
	}
	for name, test := range map[string]struct {
		execution   error
		reconcile   error
		wantCode    string
		wantMessage string
	}{
		"upstream rejection": {execution: githubauth.APIError{Code: "validation_failed", StatusCode: http.StatusUnprocessableEntity, Message: "Pull Request is not mergeable", RequestID: "ABCD:1234"}, wantCode: "validation_failed", wantMessage: "Pull Request is not mergeable (GitHub request ID ABCD:1234)"},
		"reconciliation":     {reconcile: errors.New("offline"), wantCode: "operation_reconciliation_failed", wantMessage: "reconciliation failed"},
		"unknown":            {execution: errors.New("offline"), wantCode: "upstream_result_unknown", wantMessage: "unknown"},
	} {
		t.Run(name, func(t *testing.T) {
			failure := operationExecutionFailure(test.execution, test.reconcile)
			if failure.Code != test.wantCode || !strings.Contains(failure.Message, test.wantMessage) {
				t.Fatalf("failure = %+v", failure)
			}
		})
	}
	for _, test := range []struct {
		err        error
		wantStatus int
		wantCode   string
	}{{githubauth.APIError{Code: "not_found", StatusCode: http.StatusNotFound}, http.StatusNotFound, "not_found"},
		{githubauth.APIError{Code: "unavailable", StatusCode: http.StatusBadGateway}, http.StatusBadGateway, "unavailable"},
		{errors.New("invalid target"), http.StatusBadRequest, "operation_input_invalid"}} {
		var mapped *agentapi.Error
		if err := mapOperationSubmissionError(test.err); !errors.As(err, &mapped) || mapped.Status != test.wantStatus || mapped.Code != test.wantCode {
			t.Fatalf("mapped error = %#v", err)
		}
	}
	operation := agentv1.Operation{Operation: "repo.delete", ID: "op_123"}
	if operationDebugID(operation) != "repo.delete:op_123" {
		t.Fatal("operation debug id drifted")
	}
	server := &Server{}
	fallback := t.Context()
	if server.agentLifecycleContext(fallback) != fallback {
		t.Fatal("fallback lifecycle context changed")
	}
	ctx := context.WithValue(t.Context(), lifecycleContextKey{}, "lifecycle")
	server.lifecycleContext = ctx
	if server.agentLifecycleContext(t.Context()) != ctx {
		t.Fatal("configured lifecycle context ignored")
	}
}

func TestGitGrantListRouteRemainsAuthenticated(t *testing.T) {
	server := newTestServerWithPolicyAndHandler(t, generatedPolicy(t, policy.EffectAllow), func(http.ResponseWriter, *http.Request) {})
	for name, token := range map[string]string{"authorized": testSharedSecret, "unauthorized": "wrong"} {
		t.Run(name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "/api/grants", http.NoBody)
			request.Header.Set("Authorization", "Bearer "+token)
			response := httptest.NewRecorder()
			server.Handler().ServeHTTP(response, request)
			want := http.StatusOK
			if name == "unauthorized" {
				want = http.StatusForbidden
			}
			if response.Code != want {
				t.Fatalf("status = %d body=%s", response.Code, response.Body.String())
			}
		})
	}
}

func generatedPullRequestSubmission(key string) agentv1.SubmitRequest {
	return agentv1.SubmitRequest{
		IdempotencyKey: key,
		Operation:      "pull_request.create",
		Target:         json.RawMessage(`{"kind":"repo","owner":"osolmaz","name":"gh-broker"}`),
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
		Operations: []policy.Operation{policy.Operation("pull_request.create")},
		Targets:    []policy.Target{{Kind: "repo", Owner: "osolmaz", Name: "gh-broker"}},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	return value
}
