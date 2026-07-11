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
	request := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/.well-known/brokerkit-operator", nil)
	request.Header.Set("Authorization", "Bearer client-secret-abcdefghijklmnopqrstuvwxyz")
	response := httptest.NewRecorder()
	runtime.OperatorHandler.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("client credential status = %d, want 401", response.Code)
	}
	request = httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/.well-known/brokerkit-operator", nil)
	request.Header.Set("Authorization", "Bearer operator-secret-abcdefghijklmnopqrstuvwxyz")
	response = httptest.NewRecorder()
	runtime.OperatorHandler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("operator credential status = %d, want 200: %s", response.Code, response.Body.String())
	}
}

func TestRuntimeAllowsDisabledOperatorSurface(t *testing.T) {
	runtime, err := New(Options{
		Broker: "test-broker", Store: grants.New(filepath.Join(t.TempDir(), "grants.json"), grants.Options{}),
		ClientSecrets: map[string]string{"bob": "client-secret-abcdefghijklmnopqrstuvwxyz"},
	})
	if err != nil || runtime.OperatorHandler != nil {
		t.Fatalf("New() = %+v, %v", runtime, err)
	}
}

func TestRuntimeRejectsInvalidAssembly(t *testing.T) {
	store := grants.New(filepath.Join(t.TempDir(), "grants.json"), grants.Options{})
	clientSecret := "client-secret-abcdefghijklmnopqrstuvwxyz"
	for _, options := range []Options{
		{Store: store, ClientSecrets: map[string]string{"bob": clientSecret}},
		{Broker: "test-broker", ClientSecrets: map[string]string{"bob": clientSecret}},
		{Broker: "test-broker", Store: store},
		{Broker: "test-broker", Store: store, ClientSecrets: map[string]string{"bob": clientSecret}, OperatorSecrets: map[string]string{"onur": clientSecret}},
	} {
		if _, err := New(options); err == nil {
			t.Fatalf("New(%+v) unexpectedly succeeded", options)
		}
	}
}
