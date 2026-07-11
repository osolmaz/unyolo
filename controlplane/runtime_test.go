package controlplane

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/osolmaz/brokerkit/grants"
)

func TestRuntimeSeparatesClientAndOperatorCredentials(t *testing.T) {
	store := grants.New(filepath.Join(t.TempDir(), "grants.json"), grants.Options{})
	runtime, err := New(Options{
		Broker: "test-broker", Store: store,
		ClientSecrets:   map[string]string{"bob": "client-secret-abcdefghijklmnopqrstuvwxyz"},
		OperatorSecrets: map[string]string{"onur": "operator-secret-abcdefghijklmnopqrstuvwxyz"},
	})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/grants", nil)
	request.Header.Set("Authorization", "Bearer client-secret-abcdefghijklmnopqrstuvwxyz")
	response := httptest.NewRecorder()
	runtime.OperatorHandler.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("client credential status = %d, want 401", response.Code)
	}
	request = httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/grants", nil)
	request.Header.Set("Authorization", "Bearer operator-secret-abcdefghijklmnopqrstuvwxyz")
	response = httptest.NewRecorder()
	runtime.OperatorHandler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("operator credential status = %d, want 200: %s", response.Code, response.Body.String())
	}
}
