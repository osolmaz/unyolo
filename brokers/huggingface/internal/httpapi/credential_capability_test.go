package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/osolmaz/unyolo/agent/api"
	"github.com/osolmaz/unyolo/agent/v1"
	"github.com/osolmaz/unyolo/authorization/budget"
	"github.com/osolmaz/unyolo/authorization/grants"
	"github.com/osolmaz/unyolo/brokers/huggingface/internal/credentialauth"
	"github.com/osolmaz/unyolo/brokers/huggingface/internal/hfgrant"
	"github.com/osolmaz/unyolo/brokers/huggingface/internal/hfplan"
	hfpolicy "github.com/osolmaz/unyolo/brokers/huggingface/internal/policy"
	"github.com/osolmaz/unyolo/credential/provider"
	"github.com/osolmaz/unyolo/operator/v1"
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

func TestOperationCredentialTargetUsesCatalogResourceKind(t *testing.T) {
	target, err := operationCredentialTarget("discussion.comment.create", json.RawMessage(`{"namespace":"alice","repo":"private"}`))
	if err != nil {
		t.Fatal(err)
	}
	if target["resource"] != "alice/private" || target["resource_kind"] != "repo" {
		t.Fatalf("credential target = %#v", target)
	}
}

func TestScopedCredentialAllowsReusableGrantActivation(t *testing.T) {
	server := newTestHandler(t, t.TempDir(), "http://127.0.0.1:1", &strings.Builder{}, `{"rules":[]}`)
	t.Cleanup(func() { _ = server.Close() })
	snapshot, err := providercredential.Normalize(providercredential.Snapshot{
		Provider: "huggingface", CredentialKind: "fine_grained_user_token", Subject: "alice",
		FingerprintSHA256: strings.Repeat("e", 64), Generation: 1, VerifiedAt: time.Now().UTC(),
		VerificationState: providercredential.VerificationValid,
		Capabilities: []providercredential.Capability{{Domain: "bucket", Permission: "repo.write", AccessLevel: providercredential.AccessWrite,
			Resource: providercredential.ResourceSelector{Kind: "bucket", Name: "alice/artifacts"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	credential, err := providercredential.NewService(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	server.credential = credential
	server.plans.SetCredentialService(credential)
	server.planValidator = hfplan.Validator{Store: server.plans, Credential: credential, Requirement: (credentialauth.Adapter{}).Requirement}
	requested, _, err := hfgrant.Request(server.grants, server.plans, hfgrant.Input{
		Client: "agent", ClientRequestID: "bucket-week", Operation: "bucket.object.write", Mode: hfgrant.ModeWindow,
		PolicyTarget: &hfpolicy.Target{Kind: hfpolicy.KindBucket, Owner: "alice", Name: "artifacts", Keys: []string{"validation/**"}},
		Reason:       "publish artifacts", RequestedDuration: 7 * 24 * time.Hour, MaxUses: 25, MaxUsesSpecified: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	approved, err := server.control.Decisions.Decide(t.Context(), requested.Grant.ID, operatorv1.ActionApprove, "operator", operatorv1.Decision{
		ExpectedRevision: requested.Grant.Revision, IdempotencyKey: "approve-bucket-week",
		Constraints: &operatorv1.Constraints{DurationSeconds: int64((7 * 24 * time.Hour) / time.Second), MaxUses: usebudget.Finite(25)},
	})
	if err != nil || approved.Grant.Status != grants.StatusActive {
		t.Fatalf("approval = %+v, %v", approved, err)
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

func TestDirectOperationRevalidatesCredentialBeforeExecution(t *testing.T) {
	var upstreamCalls int
	upstream := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { upstreamCalls++ })
	upstreamServer := httptest.NewServer(upstream)
	defer upstreamServer.Close()
	policyJSON := `{"rules":[{"id":"read-private","effect":"allow","clients":["agent"],"operations":["repo.contents.read"],"targets":[{"kind":"repo","type":"dataset","owner":"alice","name":"private","paths":["README.md"]}]}]}`
	server := newTestHandler(t, t.TempDir(), upstreamServer.URL, &strings.Builder{}, policyJSON)
	t.Cleanup(func() { _ = server.Close() })
	credential := testCredentialCeiling(t, "alice/private")
	server.credential = credential
	server.plans.SetCredentialService(credential)
	server.planValidator = hfplan.Validator{Store: server.plans, Credential: credential, Requirement: (credentialauth.Adapter{}).Requirement}
	operation, _, err := server.submitAgentOperation(t.Context(), "agent", agentv1.SubmitRequest{IdempotencyKey: "stale-direct",
		Operation: "repo.contents.read", Target: json.RawMessage(`{"kind":"repo","type":"dataset","owner":"alice","name":"private"}`),
		Arguments: json.RawMessage(`{"path":"README.md"}`), Reason: "test stale authority"})
	if err != nil || operation.State != agentv1.StateApproved || operation.ApprovalID != "" {
		t.Fatalf("direct submission = %+v, %v", operation, err)
	}
	snapshot, err := credential.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	snapshot.Generation++
	if err := credential.Replace(snapshot); err != nil {
		t.Fatal(err)
	}
	server.operationRuntime.Advance(t.Context(), operation)
	completed, err := server.operations.GetByID(operation.ID)
	if err != nil || completed.State != agentv1.StateFailed || completed.Error == nil || completed.Error.Code != "invalid_stored_operation" {
		t.Fatalf("stale direct operation = %+v, %v", completed, err)
	}
	if upstreamCalls != 0 {
		t.Fatalf("stale direct operation reached upstream %d times", upstreamCalls)
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
