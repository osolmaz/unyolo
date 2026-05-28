package httpapi

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/dutifuldev/gitcba/internal/config"
	"github.com/dutifuldev/gitcba/internal/githubaccess"
)

const testSharedSecret = "0123456789abcdef0123456789abcdef"
const testGitHubToken = "github-token"

func TestGitCompatibleRoutesRequireAuth(t *testing.T) {
	t.Parallel()
	server := newTestServer(t)
	request := httptest.NewRequestWithContext(
		context.Background(),
		http.MethodGet,
		"/dutifuldev/gitcba.git/info/refs?service=git-upload-pack",
		http.NoBody,
	)
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusUnauthorized)
	}
}

func TestHealth(t *testing.T) {
	t.Parallel()
	server := newTestServer(t)
	request := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/healthz", http.NoBody)
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
	}
}

func TestGitRoutesUseGitHubAccessPolicy(t *testing.T) {
	t.Parallel()
	server := newTestServer(t)

	allowed := do(t, server, http.MethodGet, "/dutifuldev/gitcba.git/info/refs?service=git-upload-pack", bearerAuth())
	if allowed.Code != http.StatusOK {
		t.Fatalf("allowed status = %d, body = %s", allowed.Code, allowed.Body.String())
	}

	denied := do(t, server, http.MethodGet, "/outside/repo.git/info/refs?service=git-upload-pack", bearerAuth())
	if denied.Code != http.StatusForbidden {
		t.Fatalf("denied status = %d, want %d", denied.Code, http.StatusForbidden)
	}
}

func TestGitReceivePackAllowsExplicitRepositoryOwner(t *testing.T) {
	t.Parallel()
	server := newTestServer(t)
	response := do(t, server, http.MethodPost, "/openclaw/openclaw.git/git-receive-pack", basicAuth())
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
}

func TestGitReceivePackRejectsMainBranchUpdate(t *testing.T) {
	t.Parallel()
	server := newTestServer(t)
	response := doWithBody(
		t,
		server,
		http.MethodPost,
		"/dutifuldev/gitcba.git/git-receive-pack",
		bearerAuth(),
		receivePackBody("refs/heads/main"),
	)
	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
}

func TestGitReceivePackRejectsDefaultBranchUpdate(t *testing.T) {
	t.Parallel()
	server := newTestServerWithDefaultBranch(t, "trunk")
	response := doWithBody(
		t,
		server,
		http.MethodPost,
		"/dutifuldev/gitcba.git/git-receive-pack",
		bearerAuth(),
		receivePackBody("refs/heads/trunk"),
	)
	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
}

func TestGitReceivePackAllowsFeatureBranchUpdate(t *testing.T) {
	t.Parallel()
	var gotGitPush bool
	server := newTestServerWithHandler(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/repos/dutifuldev/gitcba" {
			_, _ = w.Write([]byte(`{"default_branch":"main"}`))
			return
		}
		gotGitPush = r.URL.Path == "/dutifuldev/gitcba.git/git-receive-pack"
		w.WriteHeader(http.StatusOK)
	})
	response := doWithBody(
		t,
		server,
		http.MethodPost,
		"/dutifuldev/gitcba.git/git-receive-pack",
		bearerAuth(),
		receivePackBody("refs/heads/gitcba-smoke"),
	)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	if !gotGitPush {
		t.Fatal("git receive-pack was not proxied")
	}
}

func TestGitReceivePackRejectsMalformedRequest(t *testing.T) {
	t.Parallel()
	server := newTestServer(t)
	response := doWithBody(
		t,
		server,
		http.MethodPost,
		"/dutifuldev/gitcba.git/git-receive-pack",
		bearerAuth(),
		[]byte("bad"),
	)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusBadRequest)
	}
}

func TestPullRequestRouteUsesGitHubShape(t *testing.T) {
	t.Parallel()
	var gotPath string
	server := newTestServerWithHandler(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusCreated)
	})
	response := do(t, server, http.MethodPost, "/repos/dutifuldev/gitcba/pulls", bearerAuth())
	if response.Code != http.StatusCreated {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	if gotPath != "/repos/dutifuldev/gitcba/pulls" {
		t.Fatalf("upstream path = %q, want GitHub pulls path", gotPath)
	}
}

func TestGitProxyUsesServerSideCredential(t *testing.T) {
	t.Parallel()
	var gotAuthorization string
	server := newTestServerWithHandler(t, func(w http.ResponseWriter, r *http.Request) {
		gotAuthorization = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	})
	response := do(t, server, http.MethodGet, "/dutifuldev/gitcba.git/info/refs?service=git-upload-pack", bearerAuth())
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	if gotAuthorization != githubGitAuthorization(testGitHubToken) {
		t.Fatalf("upstream authorization was not server-side GitHub auth")
	}
}

func TestUnsupportedGitServiceIsRejected(t *testing.T) {
	t.Parallel()
	server := newTestServer(t)
	response := do(t, server, http.MethodGet, "/dutifuldev/gitcba.git/info/refs?service=bad-service", bearerAuth())
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusBadRequest)
	}
}

func TestNoCredentialEndpoints(t *testing.T) {
	t.Parallel()
	server := newTestServer(t)
	for _, path := range []string{"/v1/credentials", "/v1/credentials/cred_123"} {
		response := do(t, server, http.MethodGet, path, bearerAuth())
		if response.Code != http.StatusNotFound {
			t.Fatalf("%s status = %d, want %d", path, response.Code, http.StatusNotFound)
		}
	}
}

func TestNoGitHubAccessEndpoint(t *testing.T) {
	t.Parallel()
	server := newTestServer(t)
	response := do(t, server, http.MethodGet, "/v1/github-access", bearerAuth())
	if response.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusNotFound)
	}
}

func newTestServer(t *testing.T) *Server {
	t.Helper()
	return newTestServerWithDefaultBranch(t, "main")
}

func newTestServerWithDefaultBranch(t *testing.T, defaultBranch string) *Server {
	t.Helper()
	return newTestServerWithHandler(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/repos/dutifuldev/gitcba" || r.URL.Path == "/repos/openclaw/openclaw" {
			_, _ = w.Write([]byte(`{"default_branch":"` + defaultBranch + `"}`))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("proxied"))
	})
}

func newTestServerWithHandler(t *testing.T, handler http.HandlerFunc) *Server {
	t.Helper()
	upstream := httptest.NewServer(handler)
	t.Cleanup(upstream.Close)
	server, err := New(config.Config{
		SharedSecret: testSharedSecret,
		GitHubToken:  testGitHubToken,
	}, githubaccess.Config{
		Owners: []string{"dutifuldev", "osolmaz"},
		Repositories: []githubaccess.RepositoryRef{
			{Owner: "openclaw", Name: "openclaw"},
		},
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	upstreamURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	server.githubClient = upstream.Client()
	server.githubGitBaseURL = upstreamURL
	server.githubAPIBaseURL = upstreamURL
	return server
}

func do(t *testing.T, server *Server, method string, path string, authorization string) *httptest.ResponseRecorder {
	t.Helper()
	return doWithBody(t, server, method, path, authorization, nil)
}

func doWithBody(
	t *testing.T,
	server *Server,
	method string,
	path string,
	authorization string,
	body []byte,
) *httptest.ResponseRecorder {
	t.Helper()
	var requestBody io.Reader = http.NoBody
	if len(body) > 0 {
		requestBody = bytes.NewReader(body)
	}
	request := httptest.NewRequestWithContext(context.Background(), method, path, requestBody)
	request.Header.Set("Authorization", authorization)
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	return response
}

func bearerAuth() string {
	return "Bearer " + testSharedSecret
}

func basicAuth() string {
	encoded := base64.StdEncoding.EncodeToString([]byte("git:" + testSharedSecret))
	return "Basic " + encoded
}

func receivePackBody(ref string) []byte {
	line := "0000000000000000000000000000000000000000 " +
		"1111111111111111111111111111111111111111 " +
		ref + "\x00 report-status\n"
	return append(pktLine(line), []byte("0000")...)
}

func pktLine(line string) []byte {
	return []byte(fmt.Sprintf("%04x%s", len(line)+4, line))
}
