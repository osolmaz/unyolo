package httpapi

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/osolmaz/brokerkit/brokers/github/internal/githubauth"
	"github.com/osolmaz/brokerkit/brokers/github/internal/policy"
)

func TestProtectedDefaultBranchWriteFailsBeforeGitDispatch(t *testing.T) {
	t.Parallel()
	server, gitCalls := newProtectedWriteTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/dutifuldev/gh-broker":
			_, _ = w.Write([]byte(`{"default_branch":"main"}`))
		case "/repos/dutifuldev/gh-broker/rules/branches/main":
			_, _ = w.Write([]byte(`[]`))
		case "/repos/dutifuldev/gh-broker/branches/main/protection":
			_, _ = w.Write([]byte(`{"required_status_checks":null}`))
		default:
			http.NotFound(w, r)
		}
	})
	response := doWithHeaders(t, server, http.MethodPost, "/dutifuldev/gh-broker.git/git-receive-pack", map[string]string{
		"Authorization": bearerAuth(), "Content-Type": "application/x-git-receive-pack-request",
	}, receivePackCommands(commandLine(oid("1"), oid("2"), "refs/heads/main")))
	if response.Code != http.StatusForbidden || *gitCalls != 0 {
		t.Fatalf("status=%d git calls=%d body=%s", response.Code, *gitCalls, response.Body.String())
	}
}

func TestUninspectableBranchStateFailsClosed(t *testing.T) {
	t.Parallel()
	server, gitCalls := newProtectedWriteTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "denied", http.StatusForbidden)
	})
	response := doWithHeaders(t, server, http.MethodPost, "/dutifuldev/gh-broker.git/git-receive-pack", map[string]string{
		"Authorization": bearerAuth(), "Content-Type": "application/x-git-receive-pack-request",
	}, receivePackCommands(commandLine(oid("1"), oid("2"), "refs/heads/work")))
	if response.Code != http.StatusServiceUnavailable || *gitCalls != 0 {
		t.Fatalf("status=%d git calls=%d body=%s", response.Code, *gitCalls, response.Body.String())
	}
}

func newProtectedWriteTestServer(t *testing.T, apiHandler http.HandlerFunc) (*Server, *int) {
	t.Helper()
	brokerPolicy, err := policy.New(policy.Scope{Rules: []policy.Rule{{
		ID: "allow-test-write", Effect: policy.EffectAllow, Clients: []string{"bob"},
		Operations: []policy.Operation{policy.OperationGitPushForce},
		Targets:    []policy.Target{{Kind: "repo", Owner: "dutifuldev", Name: "gh-broker"}},
		Attrs:      map[string][]string{"refs": {"refs/heads/*"}},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	gitCalls := 0
	server := newTestServerWithPolicyAndHandler(t, brokerPolicy, func(w http.ResponseWriter, _ *http.Request) {
		gitCalls++
		w.WriteHeader(http.StatusOK)
	})
	api := httptest.NewServer(apiHandler)
	t.Cleanup(api.Close)
	server.githubAPIBaseURL, err = url.Parse(api.URL)
	if err != nil {
		t.Fatal(err)
	}
	server.githubCredentials, err = githubauth.New(githubauth.Config{DevelopmentToken: []byte(testGitHubToken), DevelopmentTokenFile: "/protected/github-token",
		APIBaseURL: server.githubAPIBaseURL, WebBaseURL: server.githubAPIBaseURL, HTTPClient: api.Client()})
	if err != nil {
		t.Fatal(err)
	}
	return server, &gitCalls
}
