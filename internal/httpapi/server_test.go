package httpapi

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dutifuldev/gitcba/internal/config"
	"github.com/dutifuldev/gitcba/internal/githubaccess"
)

const testSharedSecret = "0123456789abcdef0123456789abcdef"

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
	if allowed.Code != http.StatusNotImplemented {
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
	if response.Code != http.StatusNotImplemented {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
}

func TestPullRequestRouteUsesGitHubShape(t *testing.T) {
	t.Parallel()
	server := newTestServer(t)
	response := do(t, server, http.MethodPost, "/repos/dutifuldev/gitcba/pulls", bearerAuth())
	if response.Code != http.StatusNotImplemented {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), string(githubaccess.OperationCreatePullRequest)) {
		t.Fatalf("response body = %s, want operation marker", response.Body.String())
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
	server, err := New(config.Config{
		SharedSecret: testSharedSecret,
	}, githubaccess.Config{
		Owners: []string{"dutifuldev", "osolmaz"},
		Repositories: []githubaccess.RepositoryRef{
			{Owner: "openclaw", Name: "openclaw"},
		},
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return server
}

func do(t *testing.T, server *Server, method string, path string, authorization string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequestWithContext(context.Background(), method, path, http.NoBody)
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
