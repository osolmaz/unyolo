package gitserver

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/osolmaz/brokerkit/auth"
)

func TestHandlerExposesOnlyIdentityAndAllowedGitRoutes(t *testing.T) {
	authenticator, err := auth.New(map[string]string{"bob": strings.Repeat("s", 32)}, auth.Options{})
	if err != nil {
		t.Fatal(err)
	}
	handler, err := New("github", authenticator, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}), func(method, path string) bool {
		return method == http.MethodPost && strings.HasSuffix(path, "/git-upload-pack")
	}, nil)
	if err != nil {
		t.Fatal(err)
	}

	identity := httptest.NewRequest(http.MethodGet, IdentityPath, nil)
	identity.SetBasicAuth("brokerkit", strings.Repeat("s", 32))
	identityResponse := httptest.NewRecorder()
	handler.ServeHTTP(identityResponse, identity)
	if identityResponse.Code != http.StatusOK || !strings.Contains(identityResponse.Body.String(), `"provider":"github"`) {
		t.Fatalf("identity response = %d %q", identityResponse.Code, identityResponse.Body.String())
	}

	for _, request := range []*http.Request{
		httptest.NewRequest(http.MethodGet, "/api/grants", nil),
		httptest.NewRequest(http.MethodPost, "/owner/repo.git/git-upload-pack/../api/grants", nil),
	} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code < 400 {
			t.Fatalf("route %q returned %d", request.URL.Path, response.Code)
		}
	}

	gitRequest := httptest.NewRequest(http.MethodPost, "/owner/repo.git/git-upload-pack", nil)
	gitResponse := httptest.NewRecorder()
	handler.ServeHTTP(gitResponse, gitRequest)
	if gitResponse.Code != http.StatusUnauthorized || gitResponse.Header().Get("WWW-Authenticate") != `Basic realm="brokerkit-git"` {
		t.Fatalf("unauthenticated Git response = %d, challenge %q", gitResponse.Code, gitResponse.Header().Get("WWW-Authenticate"))
	}

	gitRequest.SetBasicAuth("bob", strings.Repeat("s", 32))
	gitResponse = httptest.NewRecorder()
	handler.ServeHTTP(gitResponse, gitRequest)
	if gitResponse.Code != http.StatusNoContent {
		t.Fatalf("authenticated Git response = %d", gitResponse.Code)
	}
}

func TestHandlerDelegatesCapabilityAuthenticationAfterRouteValidation(t *testing.T) {
	authenticator, err := auth.New(map[string]string{"bob": strings.Repeat("s", 32)}, auth.Options{})
	if err != nil {
		t.Fatal(err)
	}
	handler, err := New("huggingface", authenticator, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}), func(method, requestPath string) bool {
		return method == http.MethodGet && strings.HasSuffix(requestPath, "/info/lfs/objects/object")
	}, func(request *http.Request) bool {
		return request.URL.Query().Get("action") != ""
	})
	if err != nil {
		t.Fatal(err)
	}

	delegated := httptest.NewRequest(http.MethodGet, "/owner/repo/info/lfs/objects/object?action=one-time", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, delegated)
	if response.Code != http.StatusNoContent {
		t.Fatalf("delegated response = %d", response.Code)
	}

	for _, target := range []string{
		"/owner/repo/info/lfs/objects/object",
		"/api/grants?action=one-time",
	} {
		response = httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, target, nil))
		if response.Code < 400 {
			t.Fatalf("undelegated route %q returned %d", target, response.Code)
		}
	}
}
