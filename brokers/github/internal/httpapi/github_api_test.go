package httpapi

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	usebudget "github.com/osolmaz/unyolo/authorization/budget"
	corepolicy "github.com/osolmaz/unyolo/authorization/policy"
	"github.com/osolmaz/unyolo/brokers/github/internal/policy"
)

type upstreamCall struct {
	method, path, query, authorization, accept, apiVersion, body string
}

type fakeGitHubAPI struct {
	mu    sync.Mutex
	calls []upstreamCall
	node  string
}

func (f *fakeGitHubAPI) handler(t *testing.T) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if r.URL.Path == "/graphql" && strings.Contains(string(body), "NodeRepository") {
			_, _ = io.WriteString(w, f.node)
			return
		}
		f.mu.Lock()
		f.calls = append(f.calls, upstreamCall{method: r.Method, path: r.URL.EscapedPath(), query: r.URL.RawQuery,
			authorization: r.Header.Get("Authorization"), accept: r.Header.Get("Accept"),
			apiVersion: r.Header.Get("X-GitHub-Api-Version"), body: string(body)})
		f.mu.Unlock()
		w.Header().Set("Link", `<http://`+r.Host+`/repos/osolmaz/gh-broker/pulls?page=2>; rel="next"`)
		w.Header().Set("X-OAuth-Scopes", "repo")
		w.Header().Set("X-GitHub-Request-Id", "request-1")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"ok":true}`)
	}
}

func (f *fakeGitHubAPI) recorded() []upstreamCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]upstreamCall(nil), f.calls...)
}

func compatPolicy(t *testing.T) *policy.Policy {
	t.Helper()
	window := &corepolicy.GrantPolicy{Mode: "window", DefaultMinutes: 60, MaxMinutes: 120, RequestTTLMinutes: 15,
		DefaultMaxUses: usebudget.MaxFiniteUses, MaxUses: usebudget.MaxFiniteUses}
	execution := &corepolicy.GrantPolicy{Mode: "execution", DefaultMinutes: 10, MaxMinutes: 10, RequestTTLMinutes: 15, DefaultMaxUses: 1, MaxUses: 1}
	repository := []policy.Target{{Kind: "repo", Owner: "osolmaz", Name: "gh-broker"}}
	pullRequest := []policy.Target{{Kind: "pull_request", Owner: "osolmaz", Repo: "gh-broker"}}
	brokerPolicy, err := policy.New(policy.Scope{Rules: []policy.Rule{
		{ID: "read-pulls", Effect: policy.EffectAllow, Clients: []string{"bob"}, Operations: []policy.Operation{"pull_request.get"}, Targets: pullRequest},
		{ID: "graphql-read", Effect: policy.EffectAllow, Clients: []string{"bob"}, Operations: []policy.Operation{policy.OperationGraphQLRead}, Targets: repository},
		{ID: "request-pr-create", Effect: policy.EffectRequest, Clients: []string{"bob"}, Operations: []policy.Operation{"pull_request.create"},
			Targets: repository, GrantPolicy: window},
		{ID: "request-merge", Effect: policy.EffectRequest, Clients: []string{"bob"}, Operations: []policy.Operation{"pull_request.merge"},
			Targets: pullRequest, GrantPolicy: execution},
	}})
	if err != nil {
		t.Fatalf("policy.New(compatPolicy) error = %v", err)
	}
	return brokerPolicy
}

func newCompatServer(t *testing.T) (*Server, *fakeGitHubAPI, *captureNotifier) {
	t.Helper()
	fake := &fakeGitHubAPI{node: `{"data":{"node":{"__typename":"PullRequest","number":5,"repository":{"name":"gh-broker","owner":{"login":"osolmaz"}}}}}`}
	server := newTestServerWithPolicyAndHandler(t, compatPolicy(t), fake.handler(t))
	notifier := &captureNotifier{}
	server.notifier = notifier
	return server, fake, notifier
}

func tokenAuth() string { return "token " + testSharedSecret }

func graphQLRequest(t *testing.T, query string, variables map[string]any) []byte {
	t.Helper()
	body, err := json.Marshal(map[string]any{"query": query, "variables": variables})
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func TestGitHubRESTForwardsAllowedRead(t *testing.T) {
	t.Parallel()
	server, fake, _ := newCompatServer(t)
	response := doWithHeaders(t, server, http.MethodGet, "/api/v3/repos/osolmaz/gh-broker/pulls/5?per_page=10",
		map[string]string{"Authorization": tokenAuth(), "Accept": "application/vnd.github.v3.diff"}, nil)
	if response.Code != http.StatusOK || response.Body.String() != `{"ok":true}` {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	calls := fake.recorded()
	want := upstreamCall{method: http.MethodGet, path: "/repos/osolmaz/gh-broker/pulls/5", query: "per_page=10",
		authorization: "Bearer " + testGitHubToken, accept: "application/vnd.github.v3.diff", apiVersion: "2026-03-10"}
	if len(calls) != 1 || calls[0] != want {
		t.Fatalf("upstream calls = %+v, want %+v", calls, want)
	}
	if link := response.Header().Get("Link"); link != `<http://example.com/api/v3/repos/osolmaz/gh-broker/pulls?page=2>; rel="next"` {
		t.Fatalf("Link = %q", link)
	}
	if response.Header().Get("X-OAuth-Scopes") != "" || response.Header().Get("X-GitHub-Request-Id") != "request-1" {
		t.Fatalf("response headers = %v", response.Header())
	}
}

func TestGitHubCompatibleRoutesRequireClientSecret(t *testing.T) {
	t.Parallel()
	server, fake, _ := newCompatServer(t)
	for authorization, status := range map[string]int{"": http.StatusUnauthorized, "token wrong-secret": http.StatusForbidden} {
		for _, path := range []string{"/api/v3/repos/osolmaz/gh-broker/pulls/5", "/api/graphql"} {
			method := http.MethodGet
			if path == "/api/graphql" {
				method = http.MethodPost
			}
			if response := do(t, server, method, path, authorization); response.Code != status {
				t.Fatalf("%s %q status = %d, want %d", path, authorization, response.Code, status)
			}
		}
	}
	if response := do(t, server, http.MethodGet, "/api/v3/repos/osolmaz/gh-broker/pulls/5", bearerAuth()); response.Code != http.StatusOK {
		t.Fatalf("bearer status = %d", response.Code)
	}
	if len(fake.recorded()) != 1 {
		t.Fatalf("upstream calls = %d, want 1", len(fake.recorded()))
	}
}

func TestGitHubRESTRefusesBeforeUpstream(t *testing.T) {
	t.Parallel()
	server, fake, _ := newCompatServer(t)
	cases := []struct {
		method, path string
		status       int
		fragment     string
	}{
		{http.MethodGet, "/api/v3/user/repos", http.StatusForbidden, "user credential"},
		{http.MethodGet, "/api/v3/repos/osolmaz/gh-broker/nothing", http.StatusNotFound, "Not Found"},
		{http.MethodGet, "/api/v3/repos/other/repo/pulls/1", http.StatusForbidden, "no matching policy rule"},
		{http.MethodGet, "/api/v3/repos/osolmaz/gh-broker/pulls/x", http.StatusBadRequest, "invalid number"},
		{http.MethodPost, "/api/v3/repos/osolmaz/gh-broker/merge-upstream", http.StatusForbidden, "no matching policy rule"},
	}
	for _, item := range cases {
		response := doWithBody(t, server, item.method, item.path, tokenAuth(), []byte(`{"branch":"main"}`))
		var message struct {
			Message string `json:"message"`
		}
		_ = json.Unmarshal(response.Body.Bytes(), &message)
		if response.Code != item.status || !strings.Contains(message.Message, item.fragment) {
			t.Fatalf("%s %s = %d %s, want %d %q", item.method, item.path, response.Code, response.Body.String(), item.status, item.fragment)
		}
	}
	if calls := fake.recorded(); len(calls) != 0 {
		t.Fatalf("upstream calls = %+v, want none", calls)
	}
}

func TestGitHubRESTHoldsRequestUntilApproval(t *testing.T) {
	t.Parallel()
	server, fake, notifier := newCompatServer(t)
	body := []byte(`{"title":"Work","head":"bob/work","base":"main"}`)
	responses := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		responses <- doWithBody(t, server, http.MethodPost, "/api/v3/repos/osolmaz/gh-broker/pulls", tokenAuth(), body)
	}()
	grant, token := waitForGitApproval(t, server, notifier, 1)
	if grant.Operation != "pull_request.create" || !strings.HasPrefix(grant.Reason, "GitHub API request requires approval: ") ||
		grant.Attrs["base_ref"][0] != "refs/heads/main" || grant.Attrs["head_ref"][0] != "refs/heads/bob/work" || grant.Attrs["request_digest"] != nil {
		t.Fatalf("grant = %+v", grant)
	}
	if _, err := server.grants.Approve(grant.ID, token, "operator"); err != nil {
		t.Fatal(err)
	}
	response := <-responses
	calls := fake.recorded()
	if response.Code != http.StatusOK || len(calls) != 1 || calls[0].body != string(body) || calls[0].method != http.MethodPost {
		t.Fatalf("status = %d, calls = %+v", response.Code, calls)
	}
	followUp := doWithBody(t, server, http.MethodPost, "/api/v3/repos/osolmaz/gh-broker/pulls", tokenAuth(), body)
	if followUp.Code != http.StatusOK || len(fake.recorded()) != 2 {
		t.Fatalf("window follow-up status = %d, calls = %d", followUp.Code, len(fake.recorded()))
	}
}

func TestGitHubRESTApprovalDenialReturnsForbidden(t *testing.T) {
	t.Parallel()
	server, fake, notifier := newCompatServer(t)
	responses := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		responses <- doWithBody(t, server, http.MethodPost, "/api/v3/repos/osolmaz/gh-broker/pulls", tokenAuth(), []byte(`{"head":"x","base":"main"}`))
	}()
	grant, token := waitForGitApproval(t, server, notifier, 1)
	if _, err := server.grants.Deny(grant.ID, token, "operator"); err != nil {
		t.Fatal(err)
	}
	response := <-responses
	if response.Code != http.StatusForbidden || !strings.Contains(response.Body.String(), "approval denied") || len(fake.recorded()) != 0 {
		t.Fatalf("status = %d, body = %s, calls = %d", response.Code, response.Body.String(), len(fake.recorded()))
	}
}

func TestGitHubGraphQLForwardsIntrospectionAndRepositoryReads(t *testing.T) {
	t.Parallel()
	server, fake, _ := newCompatServer(t)
	introspection := graphQLRequest(t, `{ PullRequest: __type(name: "PullRequest") { fields { name } } }`, nil)
	read := graphQLRequest(t, `query($owner: String!) { viewer { login } repository(owner: $owner, name: "gh-broker") { id } }`,
		map[string]any{"owner": "osolmaz"})
	for _, body := range [][]byte{introspection, read} {
		if response := doWithBody(t, server, http.MethodPost, "/api/graphql", tokenAuth(), body); response.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
		}
	}
	calls := fake.recorded()
	if len(calls) != 2 || calls[0].path != "/graphql" || calls[1].body != string(read) || calls[1].authorization != "Bearer "+testGitHubToken {
		t.Fatalf("calls = %+v", calls)
	}
	denied := graphQLRequest(t, `{ repository(owner: "other", name: "repo") { id } }`, nil)
	if response := doWithBody(t, server, http.MethodPost, "/api/graphql", tokenAuth(), denied); response.Code != http.StatusForbidden {
		t.Fatalf("unlisted repository status = %d", response.Code)
	}
	mixed := graphQLRequest(t, `{ a: repository(owner: "osolmaz", name: "gh-broker") { id } b: repository(owner: "other", name: "repo") { id } }`, nil)
	if response := doWithBody(t, server, http.MethodPost, "/api/graphql", tokenAuth(), mixed); response.Code != http.StatusForbidden || len(fake.recorded()) != 2 {
		t.Fatalf("mixed repository status = %d, calls = %d", response.Code, len(fake.recorded()))
	}
}

func TestGitHubGraphQLMutationResolvesSubjectAndBindsExecutionApproval(t *testing.T) {
	t.Parallel()
	server, fake, notifier := newCompatServer(t)
	body := graphQLRequest(t, `mutation($input: MergePullRequestInput!) { mergePullRequest(input: $input) { pullRequest { merged } } }`,
		map[string]any{"input": map[string]any{"pullRequestId": "PR_5", "mergeMethod": "SQUASH"}})
	responses := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		responses <- doWithBody(t, server, http.MethodPost, "/api/graphql", tokenAuth(), body)
	}()
	grant, token := waitForGitApproval(t, server, notifier, 1)
	target := grant.Target.Fields
	if grant.Operation != "pull_request.merge" || grant.Attrs["merge_method"][0] != "squash" || len(grant.Attrs["request_digest"]) != 1 ||
		target["owner"][0] != "osolmaz" || target["repo"][0] != "gh-broker" || target["number"][0] != "5" {
		t.Fatalf("grant = %+v", grant)
	}
	if _, err := server.grants.Approve(grant.ID, token, "operator"); err != nil {
		t.Fatal(err)
	}
	if response := <-responses; response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	if calls := fake.recorded(); len(calls) != 1 || calls[0].body != string(body) {
		t.Fatalf("calls = %+v", calls)
	}
}

func TestGitHubGraphQLRefusesUnservedRequests(t *testing.T) {
	t.Parallel()
	server, fake, _ := newCompatServer(t)
	fake.node = `{"data":{"node":null}}`
	cases := map[string]int{
		`mutation { addStar(input: {starrableId: "x"}) { clientMutationId } }`:                http.StatusForbidden,
		`mutation { addComment(input: {subjectId: "I_1", body: "hi"}) { clientMutationId } }`: http.StatusNotFound,
		`{ search(query: "x", type: ISSUE, first: 1) { issueCount } }`:                        http.StatusForbidden,
	}
	for query, status := range cases {
		if response := doWithBody(t, server, http.MethodPost, "/api/graphql", tokenAuth(), graphQLRequest(t, query, nil)); response.Code != status {
			t.Fatalf("%s status = %d, want %d, body = %s", query, response.Code, status, response.Body.String())
		}
	}
	large := make([]byte, graphQLBodyLimit+1)
	if response := doWithBody(t, server, http.MethodPost, "/api/graphql", tokenAuth(), large); response.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("large body status = %d", response.Code)
	}
	if calls := fake.recorded(); len(calls) != 0 {
		t.Fatalf("upstream calls = %+v", calls)
	}
}

func TestGitHubAPIURLHelpers(t *testing.T) {
	base, _ := url.Parse("https://ghe.example/api/v3")
	root := githubAPIRoot(base)
	joined, err := githubAPIURL(root, "/repos/a/b/contents/x%20y", "ref=main")
	if err != nil || joined.String() != "https://ghe.example/api/v3/repos/a/b/contents/x%20y?ref=main" {
		t.Fatalf("joined = %v, err = %v", joined, err)
	}
	if _, err := githubAPIURL(root, "/%zz", ""); err == nil {
		t.Fatal("invalid escaping accepted")
	}
	header := http.Header{"Location": {"https://api.github.com/repos/a/b/pulls/1"}}
	rewriteGitHubAPILinks(header, "https://api.github.com/", "https://broker:8443/api/v3/")
	if header.Get("Location") != "https://broker:8443/api/v3/repos/a/b/pulls/1" {
		t.Fatalf("Location = %q", header.Get("Location"))
	}
	if compatError(errors.New("other")).Error() == "" {
		t.Fatal("unclassified error has no message")
	}
}

func TestHeldApprovalReasonNamesTheRequest(t *testing.T) {
	for operation, want := range map[policy.Operation]string{
		policy.OperationGitFetch:         "Git fetch requires approval",
		policy.OperationGitLFSWrite:      "Git LFS write requires approval",
		policy.OperationGitPushAdvertise: "Git push discovery requires approval",
		policy.OperationGraphQLRead:      "GitHub GraphQL read requires approval",
		"pull_request.merge":             "GitHub API request requires approval: Merge a pull request",
		"unknown.operation":              "GitHub request requires approval",
	} {
		if got := heldApprovalReason(operation); got != want {
			t.Fatalf("heldApprovalReason(%s) = %q, want %q", operation, got, want)
		}
	}
}
