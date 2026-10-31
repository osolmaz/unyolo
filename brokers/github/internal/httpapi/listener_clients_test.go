package httpapi

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/osolmaz/unyolo/brokers/github/internal/config"
)

const testSandboxSecret = "sandbox-secret-with-at-least-32-bytes"

func TestBindClientsKeepsEachClientOnItsListener(t *testing.T) {
	server := newSandboxTestServer(t, []string{"sandbox-a"})
	host := "Bearer " + testSharedSecret
	sandbox := "Bearer " + testSandboxSecret
	for name, test := range map[string]struct {
		listener      Listener
		authorization string
		status        int
	}{
		"host client on host listener":         {HostListener, host, http.StatusNoContent},
		"sandbox client on host listener":      {HostListener, sandbox, http.StatusForbidden},
		"sandbox client on sandbox listener":   {SandboxListener, sandbox, http.StatusNoContent},
		"host client on sandbox listener":      {SandboxListener, host, http.StatusForbidden},
		"gh token scheme on host listener":     {HostListener, "token " + testSandboxSecret, http.StatusForbidden},
		"git basic login on sandbox listener":  {SandboxListener, basic("x-access-token", testSandboxSecret), http.StatusNoContent},
		"git basic login on host listener":     {HostListener, basic("x-access-token", testSandboxSecret), http.StatusForbidden},
		"missing credential reaches the route": {SandboxListener, "", http.StatusNoContent},
		"unknown credential reaches the route": {HostListener, "Bearer " + strings.Repeat("x", 40), http.StatusNoContent},
	} {
		t.Run(name, func(t *testing.T) {
			handler := server.BindClients(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusNoContent)
			}), test.listener)
			request := httptest.NewRequest(http.MethodGet, "/api/v3/repos/octo/repo", nil)
			if test.authorization != "" {
				request.Header.Set("Authorization", test.authorization)
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.status {
				t.Fatalf("status = %d, want %d: %s", response.Code, test.status, response.Body.String())
			}
		})
	}
}

func TestBindClientsWithoutSandboxClientsKeepsTheHandler(t *testing.T) {
	server := newSandboxTestServer(t, nil)
	called := false
	handler := server.BindClients(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }), SandboxListener)
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header.Set("Authorization", "Bearer "+testSandboxSecret)
	handler.ServeHTTP(httptest.NewRecorder(), request)
	if !called {
		t.Fatal("handler was not called")
	}
}

func newSandboxTestServer(t *testing.T, sandboxClients []string) *Server {
	t.Helper()
	server, err := New(config.Config{
		ClientSecrets:  map[string]string{"bob": testSharedSecret, "sandbox-a": testSandboxSecret},
		SandboxClients: sandboxClients, GitHubToken: testGitHubToken, GitHubTokenFile: "/protected/github-token",
		GitHubAPIBaseURL: "https://api.github.com/", GitHubWebBaseURL: "https://github.com/", StateDir: t.TempDir(),
	}, testBrokerPolicy(t))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	t.Cleanup(func() { _ = server.Close() })
	return server
}

func basic(user, password string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+password))
}
