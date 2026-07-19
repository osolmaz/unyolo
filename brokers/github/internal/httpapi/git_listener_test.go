package httpapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/osolmaz/brokerkit/gitserver"
)

func TestGitHandlerHidesAgentAndWebhookRoutes(t *testing.T) {
	server := newTestServer(t)
	handler, err := server.GitHandler()
	if err != nil {
		t.Fatal(err)
	}
	identity := httptest.NewRequest(http.MethodGet, gitserver.IdentityPath, nil)
	identity.SetBasicAuth("brokerkit", testSharedSecret)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, identity)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"provider":"github"`) {
		t.Fatalf("identity = %d %q", response.Code, response.Body.String())
	}
	for _, route := range []string{"/api/agent/v1/operations", "/api/grants", "/webhooks/github", "/healthz"} {
		response = httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, route, nil))
		if response.Code != http.StatusNotFound {
			t.Fatalf("%s returned %d", route, response.Code)
		}
	}
}
