package credentialauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/opcatalog"
	"github.com/osolmaz/brokerkit/providercredential"
)

func TestInspectNormalizesFineGrainedCredential(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/whoami-v2" || r.Header.Get("Authorization") != "Bearer hf_candidate" {
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"name": "alice", "orgs": []any{map[string]any{"name": "team"}, map[string]any{"name": "team"}},
			"auth": map[string]any{"type": "access_token", "accessToken": map[string]any{
				"role": "fineGrained", "fineGrained": map[string]any{
					"global": []any{"post.write", "post.write", 1}, "canReadGatedRepos": true,
					"scoped": []any{map[string]any{"entity": map[string]any{"type": "org", "name": "team"}, "permissions": []any{"repo.write", "repo.write", nil}}},
				},
			}},
		})
	}))
	defer server.Close()

	result, err := (Inspector{BaseURL: server.URL, Client: server.Client(), Now: func() time.Time {
		return time.Date(2026, 7, 18, 12, 0, 0, 0, time.UTC)
	}}).Inspect(context.Background(), " hf_candidate\n")
	if err != nil {
		t.Fatal(err)
	}
	if result.Account != "alice" || result.TokenType != "fineGrained" || result.VerifiedAt != "2026-07-18T12:00:00Z" {
		t.Fatalf("unexpected result: %+v", result)
	}
	if len(result.Organizations) != 1 || len(result.GlobalPermissions) != 1 || len(result.Scopes) != 1 || !result.CanReadGatedRepos {
		t.Fatalf("capabilities were not normalized: %+v", result)
	}
	if len(result.FingerprintSHA256) != 64 || len(result.CapabilityDigest) != 64 {
		t.Fatalf("digests are not SHA-256: %+v", result)
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "hf_candidate") {
		t.Fatal("inspection leaked the token")
	}
}

func TestRequirementsCoverEveryRuntimeOperation(t *testing.T) {
	adapter := Adapter{}
	for _, descriptor := range opcatalog.MustAll() {
		if _, found := adapter.Requirement(descriptor.Name); !found {
			t.Fatalf("operation %s has no credential requirement", descriptor.Name)
		}
	}
}

func TestAdapterProjectsScopedCapabilities(t *testing.T) {
	inspection := Inspection{
		Account: "alice", TokenType: "fineGrained", FingerprintSHA256: strings.Repeat("c", 64),
		VerifiedAt: "2026-07-18T12:00:00Z", GlobalPermissions: []string{"post.write"},
		Scopes: []Scope{{EntityType: "repo", EntityName: "alice/private", Permissions: []string{"repo.content.read"}}},
	}
	snapshot, err := Snapshot(inspection, 4)
	if err != nil {
		t.Fatal(err)
	}
	requirement, _ := (Adapter{}).Requirement("repo.contents.read")
	if result := providercredential.Evaluate(snapshot, requirement, providercredential.Target{"owner": "alice", "resource": "alice/private"}); !result.Allowed {
		t.Fatalf("scoped repository capability did not match: %+v", result)
	}
}

func TestInspectRejectsUnsupportedAndRejectedCredentials(t *testing.T) {
	tests := []struct {
		name      string
		status    int
		body      string
		wantError string
	}{
		{name: "oauth", status: http.StatusOK, body: `{"name":"alice","auth":{"accessToken":{"role":"oauth"}}}`, wantError: "dedicated fine-grained"},
		{name: "legacy", status: http.StatusOK, body: `{"name":"alice","auth":{"accessToken":{"role":"write"}}}`, wantError: "dedicated fine-grained"},
		{name: "rejected", status: http.StatusUnauthorized, body: `{"error":"secret detail"}`, wantError: "did not accept"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(test.status)
				_, _ = w.Write([]byte(test.body))
			}))
			defer server.Close()
			_, err := (Inspector{BaseURL: server.URL, Client: server.Client()}).Inspect(context.Background(), "hf_candidate")
			if err == nil || !strings.Contains(err.Error(), test.wantError) || strings.Contains(err.Error(), "secret detail") {
				t.Fatalf("Inspect() error = %v", err)
			}
		})
	}
}

func TestTokenFormURLContainsNoPermissionOrResourcePrefill(t *testing.T) {
	if TokenFormURL != "https://huggingface.co/settings/tokens/new?tokenType=fineGrained" {
		t.Fatalf("unexpected token form URL: %s", TokenFormURL)
	}
}
