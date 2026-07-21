package operations

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/osolmaz/brokerkit/brokers/github/internal/githubauth"
)

const (
	adminHeadSHA    = "1111111111111111111111111111111111111111"
	adminBaseSHA    = "2222222222222222222222222222222222222222"
	adminChangedSHA = "3333333333333333333333333333333333333333"
)

func TestAdminMergeBindsExactRevisionAndUsesPersistedGraphQL(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		requests++
		if request.Header.Get("Authorization") != "Bearer dev-canary" {
			t.Fatalf("authorization header was not supplied by the credential manager")
		}
		switch request.URL.Path {
		case "/user":
			_, _ = w.Write([]byte(`{"id":2453968,"login":"osolmaz"}`))
		case "/repos/osolmaz/solmazio/pulls/98":
			writeAdminMergeSnapshot(t, w, adminHeadSHA, adminBaseSHA, "blocked", true)
		case "/graphql":
			var payload struct {
				OperationName string `json:"operationName"`
				Query         string `json:"query"`
				Variables     struct {
					Input map[string]any `json:"input"`
				} `json:"variables"`
			}
			if json.NewDecoder(request.Body).Decode(&payload) != nil {
				t.Fatal("decode GraphQL request")
			}
			if payload.OperationName != "MutationMergePullRequest" || !strings.Contains(payload.Query, "mergePullRequest") ||
				payload.Variables.Input["pullRequestId"] != "PR_node" || payload.Variables.Input["expectedHeadOid"] != adminHeadSHA ||
				payload.Variables.Input["mergeMethod"] != "SQUASH" || payload.Variables.Input["clientMutationId"] != "operation-1" {
				t.Fatalf("GraphQL payload = %+v", payload)
			}
			_, _ = w.Write([]byte(`{"data":{"mergePullRequest":{"__typename":"MergePullRequestPayload","clientMutationId":"operation-1"}}}`))
		default:
			t.Fatalf("unexpected request %s %s", request.Method, request.URL.Path)
		}
	}))
	t.Cleanup(server.Close)

	adapter := mustLookupGenerated(t, newOperationsManager(t, server.URL), adminMergeOperation)
	input, err := adapter.Decode(
		json.RawMessage(`{"kind":"pull_request","owner":"osolmaz","repo":"solmazio","number":98}`),
		json.RawMessage(`{"merge_method":"squash","commit_title":"Reviewed title"}`),
	)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := adapter.Resolve(t.Context(), input)
	if err != nil {
		t.Fatal(err)
	}
	plan.ExecutionID = "operation-1"
	if plan.Credential.Kind != githubauth.KindDevelopmentToken || !strings.Contains(plan.Presentation.Summary, "may bypass") ||
		adapter.Authorize(plan).Operation != adminMergeOperation {
		t.Fatalf("plan = %+v", plan)
	}
	if strings.Contains(string(plan.Preconditions), "dev-canary") {
		t.Fatal("credential leaked into immutable preconditions")
	}
	outcome, err := adapter.Execute(t.Context(), plan)
	if err != nil || !outcome.Proven || outcome.UpstreamStatus != http.StatusOK {
		t.Fatalf("outcome = %+v err = %v", outcome, err)
	}
	assertJSONEqual(t, outcome.Result, `{"merged":true,"head_sha":"1111111111111111111111111111111111111111","base_sha":"2222222222222222222222222222222222222222","merge_method":"squash"}`)
	if requests != 5 {
		t.Fatalf("requests = %d, want identity and revision checks plus merge", requests)
	}
}

func TestAdminMergeRejectsStaleApprovalBeforeMutation(t *testing.T) {
	requests, pullRequestRequests := 0, 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		requests++
		if request.URL.Path == "/graphql" {
			t.Fatal("stale admin merge reached mutation")
		}
		if request.URL.Path == "/user" {
			_, _ = w.Write([]byte(`{"id":2453968,"login":"osolmaz"}`))
			return
		}
		pullRequestRequests++
		head := adminHeadSHA
		if pullRequestRequests > 1 {
			head = adminChangedSHA
		}
		writeAdminMergeSnapshot(t, w, head, adminBaseSHA, "blocked", true)
	}))
	t.Cleanup(server.Close)
	adapter := mustLookupGenerated(t, newOperationsManager(t, server.URL), adminMergeOperation)
	input, err := adapter.Decode(json.RawMessage(`{"kind":"pull_request","owner":"osolmaz","repo":"solmazio","number":98}`), json.RawMessage(`{"merge_method":"merge"}`))
	if err != nil {
		t.Fatal(err)
	}
	plan, err := adapter.Resolve(t.Context(), input)
	if err != nil {
		t.Fatal(err)
	}
	_, err = adapter.Execute(t.Context(), plan)
	var upstream githubauth.APIError
	if !errors.As(err, &upstream) || upstream.Code != "stale_pull_request_head" || !strings.Contains(upstream.Message, "changed after approval") {
		t.Fatalf("error = %#v", err)
	}
}

func TestAdminMergeRejectsConflictsAtSubmission(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/user" {
			_, _ = w.Write([]byte(`{"id":2453968,"login":"osolmaz"}`))
			return
		}
		writeAdminMergeSnapshot(t, w, adminHeadSHA, adminBaseSHA, "dirty", false)
	}))
	t.Cleanup(server.Close)
	adapter := mustLookupGenerated(t, newOperationsManager(t, server.URL), adminMergeOperation)
	input, err := adapter.Decode(json.RawMessage(`{"kind":"pull_request","owner":"osolmaz","repo":"solmazio","number":98}`), json.RawMessage(`{"merge_method":"merge"}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := adapter.Resolve(t.Context(), input); err == nil || !strings.Contains(err.Error(), "conflicts") {
		t.Fatalf("resolve error = %v", err)
	}
}

func writeAdminMergeSnapshot(t *testing.T, writer http.ResponseWriter, head, base, mergeableState string, mergeable bool) {
	t.Helper()
	_ = json.NewEncoder(writer).Encode(map[string]any{
		"id": 4081694590, "number": 98, "node_id": "PR_node", "state": "open", "draft": false, "merged": false,
		"mergeable": mergeable, "mergeable_state": mergeableState,
		"head": map[string]any{"sha": head}, "base": map[string]any{"sha": base, "ref": "main"},
	})
}
