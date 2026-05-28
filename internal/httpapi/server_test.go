package httpapi

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dutifuldev/gitcba/internal/config"
	"github.com/dutifuldev/gitcba/internal/credential"
	"github.com/dutifuldev/gitcba/internal/policy"
)

const testAdminToken = "0123456789abcdef0123456789abcdef"

func TestCredentialRoutesRequireAuth(t *testing.T) {
	t.Parallel()
	server := newTestServer(t)
	request := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/v1/credentials", http.NoBody)
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

func TestCredentialResponsesDoNotExposeSecret(t *testing.T) {
	t.Parallel()
	server := newTestServer(t)
	rawSecret := "private-" + "repo-" + "read-" + "value"
	createBody := `{"tenant_id":"tenant-a","name":"github-read","kind":"github_token","secret":"` + rawSecret + `","scopes":["contents:read"]}`
	createResponse := doJSON(t, server, http.MethodPost, "/v1/credentials", "tenant-a", createBody)
	if createResponse.Code != http.StatusCreated {
		t.Fatalf("create status = %d, body = %s", createResponse.Code, createResponse.Body.String())
	}
	assertBodyDoesNotContain(t, createResponse.Body.String(), rawSecret)
	listResponse := doJSON(t, server, http.MethodGet, "/v1/credentials", "tenant-a", "")
	if listResponse.Code != http.StatusOK {
		t.Fatalf("list status = %d, body = %s", listResponse.Code, listResponse.Body.String())
	}
	assertBodyDoesNotContain(t, listResponse.Body.String(), rawSecret)
	id := extractID(t, createResponse.Body.String())
	getResponse := doJSON(t, server, http.MethodGet, "/v1/credentials/"+id, "tenant-a", "")
	if getResponse.Code != http.StatusOK {
		t.Fatalf("get status = %d, body = %s", getResponse.Code, getResponse.Body.String())
	}
	assertBodyDoesNotContain(t, getResponse.Body.String(), rawSecret)
}

func TestNoSecretRetrievalEndpoint(t *testing.T) {
	t.Parallel()
	server := newTestServer(t)
	response := doJSON(t, server, http.MethodGet, "/v1/credentials/cred_123/secret", "tenant-a", "")
	if response.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusNotFound)
	}
}

func TestRepositoryRoutesConfigureRepoPolicy(t *testing.T) {
	t.Parallel()
	server := newTestServer(t)
	body := `{
		"tenant_id":"tenant-a",
		"owner":"dutifuldev",
		"name":"private-repo",
		"private":true,
		"credential_id":"cred_123",
		"policy":{
			"allowed_agents":["openclaw"],
			"allowed_operations":["contents_read","pull_request_diff"],
			"allowed_branches":[],
			"allowed_paths":["README.md","internal/**"],
			"require_approval_for_writes":false
		}
	}`
	createResponse := doJSON(t, server, http.MethodPost, "/v1/repos", "tenant-a", body)
	if createResponse.Code != http.StatusCreated {
		t.Fatalf("create status = %d, body = %s", createResponse.Code, createResponse.Body.String())
	}
	id := extractID(t, createResponse.Body.String())
	getResponse := doJSON(t, server, http.MethodGet, "/v1/repos/"+id, "tenant-a", "")
	if getResponse.Code != http.StatusOK {
		t.Fatalf("get status = %d, body = %s", getResponse.Code, getResponse.Body.String())
	}
	if !strings.Contains(getResponse.Body.String(), `"credential_id":"cred_123"`) {
		t.Fatalf("get body missing credential id: %s", getResponse.Body.String())
	}
	listResponse := doJSON(t, server, http.MethodGet, "/v1/repos", "tenant-a", "")
	if listResponse.Code != http.StatusOK {
		t.Fatalf("list status = %d, body = %s", listResponse.Code, listResponse.Body.String())
	}
}

func TestRepositoryWritePolicyRequiresApproval(t *testing.T) {
	t.Parallel()
	server := newTestServer(t)
	body := `{
		"tenant_id":"tenant-a",
		"owner":"dutifuldev",
		"name":"private-repo",
		"private":true,
		"credential_id":"cred_123",
		"policy":{
			"allowed_agents":["openclaw"],
			"allowed_operations":["contents_write"],
			"allowed_branches":["main"],
			"allowed_paths":["README.md"],
			"require_approval_for_writes":false
		}
	}`
	response := doJSON(t, server, http.MethodPost, "/v1/repos", "tenant-a", body)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusBadRequest)
	}
}

func TestRepositoryGetNotFound(t *testing.T) {
	t.Parallel()
	server := newTestServer(t)
	response := doJSON(t, server, http.MethodGet, "/v1/repos/repo_missing", "tenant-a", "")
	if response.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusNotFound)
	}
}

func TestListRequiresTenantHeader(t *testing.T) {
	t.Parallel()
	server := newTestServer(t)
	response := doJSON(t, server, http.MethodGet, "/v1/credentials", "", "")
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusBadRequest)
	}
}

func newTestServer(t *testing.T) *Server {
	t.Helper()
	service := credential.NewService(
		credential.NewDiscardingSecretSink(),
		credential.NewMemoryMetadataStore(),
	)
	policyService := policy.NewService(policy.NewMemoryRepositoryStore())
	server, err := New(config.Config{
		APIPrefix:  "/v1",
		AdminToken: testAdminToken,
	}, service, policyService)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return server
}

func doJSON(t *testing.T, server *Server, method string, path string, tenant string, body string) *httptest.ResponseRecorder {
	t.Helper()
	var reader io.Reader = http.NoBody
	if body != "" {
		reader = bytes.NewBufferString(body)
	}
	request := httptest.NewRequestWithContext(context.Background(), method, path, reader)
	request.Header.Set("Authorization", "Bearer "+testAdminToken)
	request.Header.Set("X-CBA-Tenant", tenant)
	if body != "" {
		request.Header.Set("Content-Type", "application/json")
	}
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	return response
}

func assertBodyDoesNotContain(t *testing.T, body string, value string) {
	t.Helper()
	if strings.Contains(body, value) {
		t.Fatalf("response exposed original credential: %s", body)
	}
}

func extractID(t *testing.T, body string) string {
	t.Helper()
	const marker = `"id":"`
	start := strings.Index(body, marker)
	if start < 0 {
		t.Fatalf("response missing id: %s", body)
	}
	start += len(marker)
	end := strings.Index(body[start:], `"`)
	if end < 0 {
		t.Fatalf("response id is unterminated: %s", body)
	}
	return body[start : start+end]
}
