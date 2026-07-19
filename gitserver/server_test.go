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
	})
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
}
