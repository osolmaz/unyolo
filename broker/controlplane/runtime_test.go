package controlplane

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	notifier "github.com/osolmaz/unyolo/approval/notifier"
	"github.com/osolmaz/unyolo/authorization/grants"
	"github.com/osolmaz/unyolo/telemetry/audit"
)

func TestRuntimeSeparatesClientAndOperatorCredentials(t *testing.T) {
	store := grants.New(filepath.Join(t.TempDir(), "grants.json"), grants.Options{})
	runtime, err := New(Options{
		Broker: "test-broker", Store: store,
		ClientSecrets:   map[string]string{"bob": "client-secret-abcdefghijklmnopqrstuvwxyz"},
		OperatorSecrets: map[string]string{"onur": "operator-secret-abcdefghijklmnopqrstuvwxyz"},
		Audit:           audit.New(io.Discard),
	})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/.well-known/unyolo-operator", nil)
	request.Header.Set("Authorization", "Bearer client-secret-abcdefghijklmnopqrstuvwxyz")
	response := httptest.NewRecorder()
	runtime.OperatorHandler.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("client credential status = %d, want 401", response.Code)
	}
	request = httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/.well-known/unyolo-operator", nil)
	request.Header.Set("Authorization", "Bearer operator-secret-abcdefghijklmnopqrstuvwxyz")
	response = httptest.NewRecorder()
	runtime.OperatorHandler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("operator credential status = %d, want 200: %s", response.Code, response.Body.String())
	}
	runtime.Metrics.AdmissionAccepted()
	request = httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/metrics", nil)
	request.Header.Set("Authorization", "Bearer operator-secret-abcdefghijklmnopqrstuvwxyz")
	response = httptest.NewRecorder()
	runtime.OperatorHandler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "unyolo_admission_requests_total") {
		t.Fatalf("operator metrics status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestRuntimeAllowsDisabledOperatorSurface(t *testing.T) {
	runtime, err := New(Options{
		Broker: "test-broker", Store: grants.New(filepath.Join(t.TempDir(), "grants.json"), grants.Options{}),
		ClientSecrets: map[string]string{"bob": "client-secret-abcdefghijklmnopqrstuvwxyz"},
		Audit:         audit.New(io.Discard),
	})
	if err != nil || runtime.OperatorHandler != nil {
		t.Fatalf("New() = %+v, %v", runtime, err)
	}
}

func TestRuntimeAllowsServerWithoutAgentClients(t *testing.T) {
	runtime, err := New(Options{
		Broker: "test-broker", Store: grants.New(filepath.Join(t.TempDir(), "grants.json"), grants.Options{}),
		OperatorSecrets: map[string]string{"onur": "operator-secret-abcdefghijklmnopqrstuvwxyz"}, Audit: audit.New(io.Discard),
	})
	if err != nil || runtime.Clients == nil || runtime.OperatorHandler == nil {
		t.Fatalf("New() = %+v, %v", runtime, err)
	}
}

func TestRuntimeDecisionReferencePreservesTelegramMessageIdentity(t *testing.T) {
	ref := notifier.MessageRef{Kind: "telegram", ChatID: 42, MessageID: 7, Renderer: "telegram-html-v1", Text: "approval",
		PresentationJSON: `{}`, PresentationDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		RenderedDigest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}
	runtime := &Runtime{}
	grant := grants.Grant{Notification: &ref}
	resolved, err := runtime.decisionReference(t.Context(), grant, notifier.Decision{ChatID: 42, MessageID: 7})
	if err != nil || resolved != ref {
		t.Fatalf("decisionReference() = %#v, %v", resolved, err)
	}
	if _, err := runtime.decisionReference(t.Context(), grant, notifier.Decision{ChatID: 42, MessageID: 8}); !errors.Is(err, errNotificationIdentity) {
		t.Fatalf("mismatched message error = %v", err)
	}
}

func TestRuntimeRejectsInvalidAssembly(t *testing.T) {
	store := grants.New(filepath.Join(t.TempDir(), "grants.json"), grants.Options{})
	clientSecret := "client-secret-abcdefghijklmnopqrstuvwxyz"
	recorder := audit.New(io.Discard)
	for _, options := range []Options{
		{Store: store, ClientSecrets: map[string]string{"bob": clientSecret}, Audit: recorder},
		{Broker: "test-broker", ClientSecrets: map[string]string{"bob": clientSecret}, Audit: recorder},
		{Broker: "test-broker", Store: store, ClientSecrets: map[string]string{"bob": clientSecret}, OperatorSecrets: map[string]string{"onur": clientSecret}, Audit: recorder},
		{Broker: "test-broker", Store: store, ClientSecrets: map[string]string{"bob": clientSecret}},
	} {
		if _, err := New(options); err == nil {
			t.Fatalf("New(%+v) unexpectedly succeeded", options)
		}
	}
}
