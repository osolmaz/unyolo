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
	server, err := New(config.Config{
		APIPrefix:  "/v1",
		AdminToken: testAdminToken,
	}, service)
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
