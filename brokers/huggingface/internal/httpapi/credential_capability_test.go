package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/osolmaz/brokerkit/agentapi"
	"github.com/osolmaz/brokerkit/agentv1"
	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/credentialauth"
	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/hfplan"
	"github.com/osolmaz/brokerkit/providercredential"
)

func TestCredentialCeilingRejectsBeforeOperationSubmission(t *testing.T) {
	server := newTestHandler(t, t.TempDir(), "http://127.0.0.1:1", &strings.Builder{}, `{"rules":[]}`)
	t.Cleanup(func() { _ = server.Close() })
	credential := testCredentialCeiling(t, "alice/private")
	server.credential = credential
	server.plans.SetCredentialService(credential)
	server.planValidator = hfplan.Validator{Store: server.plans, Credential: credential, Requirement: (credentialauth.Adapter{}).Requirement}

	_, _, err := server.submitAgentOperation(t.Context(), "agent", agentv1.SubmitRequest{IdempotencyKey: "credential-denied",
		Operation: "repo.create", Target: json.RawMessage(`{"kind":"repo","type":"dataset","owner":"bob","name":"other"}`), Arguments: json.RawMessage(`{"visibility":"private"}`), Reason: "test"})
	var apiErr *agentapi.Error
	if !errors.As(err, &apiErr) || apiErr.Status != http.StatusForbidden || apiErr.Code != "operation_credential_capability_missing" {
		t.Fatalf("submit error = %#v", err)
	}
	if _, err := server.operations.List("agent", agentv1.ListOptions{}); err != nil {
		t.Fatal(err)
	}
}

func TestCredentialDiscoveryFiltersUnavailableOperations(t *testing.T) {
	server := &Server{credential: testCredentialCeiling(t, "alice/private"), now: func() time.Time { return time.Now().UTC() }}
	discovery := server.discoverAgent("agent")
	if !discovery.Credential.Ready || discovery.Credential.Provider != "huggingface" {
		t.Fatalf("credential discovery = %+v", discovery.Credential)
	}
	containsRead, containsDelete := false, false
	for _, operation := range discovery.Operations {
		containsRead = containsRead || operation == "repo.contents.read"
		containsDelete = containsDelete || operation == "repo.delete"
	}
	if !containsRead || containsDelete {
		t.Fatalf("discovered operations did not reflect read-only credential: read=%v delete=%v", containsRead, containsDelete)
	}
}

func testCredentialCeiling(t *testing.T, resource string) *providercredential.Service {
	t.Helper()
	snapshot, err := providercredential.Normalize(providercredential.Snapshot{Provider: "huggingface", CredentialKind: "fine_grained_user_token",
		Subject: "alice", FingerprintSHA256: strings.Repeat("d", 64), Generation: 1, VerifiedAt: time.Now().UTC(),
		VerificationState: providercredential.VerificationValid,
		Capabilities: []providercredential.Capability{{Domain: "repo", Permission: "repo.content.read", AccessLevel: providercredential.AccessRead,
			Resource: providercredential.ResourceSelector{Kind: "repo", Name: resource}}}})
	if err != nil {
		t.Fatal(err)
	}
	service, err := providercredential.NewService(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	return service
}
