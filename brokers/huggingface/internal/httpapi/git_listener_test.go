package httpapi

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/osolmaz/brokerkit/git/server"
)

func TestGitHandlerHidesAgentAndInferenceRoutes(t *testing.T) {
	upstream := httptest.NewServer(http.NotFoundHandler())
	defer upstream.Close()
	server := newTestHandler(t, t.TempDir(), upstream.URL, io.Discard, emptyPolicyJSON())
	handler, err := server.GitHandler()
	if err != nil {
		t.Fatal(err)
	}
	identity := httptest.NewRequest(http.MethodGet, gitserver.IdentityPath, nil)
	identity.SetBasicAuth("brokerkit", testSecret)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, identity)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"provider":"huggingface"`) {
		t.Fatalf("identity = %d %q", response.Code, response.Body.String())
	}
	for _, route := range []string{"/api/agent/v1/operations", "/api/grants", "/v1/chat/completions", "/healthz"} {
		response = httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, route, nil))
		if response.Code != http.StatusNotFound {
			t.Fatalf("%s returned %d", route, response.Code)
		}
	}
}

func TestGitHandlerAcceptsBrokerLFSActionCapability(t *testing.T) {
	upstream := httptest.NewServer(http.NotFoundHandler())
	defer upstream.Close()
	server := newTestHandler(t, t.TempDir(), upstream.URL, io.Discard, emptyPolicyJSON())
	server.lfsActions["action"] = lfsAction{
		url: upstream.URL + "/object", client: "agent",
		route:   route{owner: "owner", name: "repo", tail: "info/lfs/objects/" + strings.Repeat("a", 64)},
		created: server.utcNow(),
	}
	handler, err := server.GitHandler()
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet,
		"/owner/repo/info/lfs/objects/"+strings.Repeat("a", 64)+"?"+lfsActionQuery+"=action", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code == http.StatusUnauthorized {
		t.Fatalf("broker LFS action was rejected before provider authentication: %s", response.Body.String())
	}
}
