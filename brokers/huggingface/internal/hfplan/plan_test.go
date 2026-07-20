package hfplan

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/osolmaz/brokerkit/authorization/grants"
	"github.com/osolmaz/brokerkit/authorization/policy"
	"github.com/osolmaz/brokerkit/credential/provider"
	"github.com/osolmaz/brokerkit/internal/storage/state"
	"github.com/osolmaz/brokerkit/operation/digest"
)

func TestStoreBindsDeterministicImmutablePlan(t *testing.T) {
	t.Parallel()
	fixedNow := time.Date(2026, 7, 11, 12, 0, 0, 0, time.UTC)
	plans := newTestPlanStore(t, func() time.Time { return fixedNow })
	request := grants.Request{Client: "bob", ClientRequestID: "request-1", Operation: "git.push.force", Target: policy.Target{Kind: "hf", Fields: map[string][]string{"name": {"dataset/acme/demo"}, "ref": {"refs/heads/main"}}},
		Attrs: map[string][]string{"ref_change": {`"non_fast_forward"`}}, Metadata: map[string]string{"hf_grant_mode": "window"}, Reason: "repair", Duration: 5 * time.Minute, MaxUses: 2}
	if err := plans.Bind(&request); err != nil {
		t.Fatal(err)
	}
	digest := request.Metadata[MetadataDigest]
	if digest == "" || request.Metadata[MetadataSchema] != SchemaV1 {
		t.Fatalf("metadata = %+v", request.Metadata)
	}
	second := request
	second.Metadata = map[string]string{"hf_grant_mode": "window"}
	if err := plans.Bind(&second); err != nil || second.Metadata[MetadataDigest] != digest {
		t.Fatalf("second bind = %+v, %v", second.Metadata, err)
	}

	store := grants.New(t.TempDir()+"/grants.json", grants.Options{})
	created, _, err := store.Request(request)
	if err != nil {
		t.Fatal(err)
	}
	validator := Validator{Store: plans}
	if err := validator.ValidateActivation(t.Context(), created.Grant, grants.ApprovalConstraints{Duration: time.Minute, MaxUses: 1}); err != nil {
		t.Fatal(err)
	}
	if err := validator.ValidateExecution(created.Grant); err != nil {
		t.Fatal(err)
	}
	mutated := created.Grant
	mutated.Operation = "git.push.append"
	if err := validator.ValidateExecution(mutated); err == nil {
		t.Fatal("validator accepted mutated grant")
	}
	mutated = created.Grant
	mutated.Target.Kind = "other"
	if err := validator.ValidateExecution(mutated); err == nil {
		t.Fatal("validator accepted a mutated target kind")
	}
	if err := validator.ValidateActivation(context.Background(), created.Grant, grants.ApprovalConstraints{Duration: 10 * time.Minute}); !errors.Is(err, grants.ErrConstraintExceeded) {
		t.Fatalf("widening error = %v", err)
	}
}

func TestCanonicalPlanDigestFixture(t *testing.T) {
	request := grants.Request{
		Client: "bob", ClientRequestID: "request-1", Operation: "git.push.force",
		Target: policy.Target{Kind: "hf", Fields: map[string][]string{"name": {"dataset/acme/demo"}, "ref": {"refs/heads/main"}}},
		Attrs:  map[string][]string{"ref_change": {`"non_fast_forward"`}}, Metadata: map[string]string{"hf_grant_mode": "window"},
		Duration: 5 * time.Minute, MaxUses: 2,
	}
	encoded, err := encode(FromRequest(request, time.Date(2026, 7, 11, 12, 0, 0, 0, time.UTC)))
	if err != nil {
		t.Fatal(err)
	}
	const expected = "e45fbf6a9cf6e1023026b56b82bbb8d3f2a8716e60297ec4f1760ded8dc5e2b0"
	if got := plandigest.Digest(encoded); got != expected {
		t.Fatalf("canonical digest = %s, want %s\n%s", got, expected, encoded)
	}
}

func TestFromRequestBoundsLongReasonPresentation(t *testing.T) {
	reason := strings.Repeat("a", 499) + "é" + strings.Repeat("b", 1500)
	request := grants.Request{
		Client: "bob", ClientRequestID: "request-1", Operation: "git.push.force",
		Target:   policy.Target{Kind: "hf", Fields: map[string][]string{"name": {"dataset/acme/demo"}}},
		Metadata: map[string]string{"hf_grant_mode": "window"}, Reason: reason,
		Duration: time.Minute, MaxUses: 1,
	}
	plan := FromRequest(request, time.Date(2026, 7, 11, 12, 0, 0, 0, time.UTC))
	if len(plan.Presentation.Summary) > 500 || !strings.HasSuffix(plan.Presentation.Summary, "a") {
		t.Fatalf("summary was not bounded on a UTF-8 boundary: %q", plan.Presentation.Summary)
	}
	if _, err := Prepare(plan); err != nil {
		t.Fatalf("Prepare() rejected a valid 2,000-character reason: %v", err)
	}
}

func TestDecodeRejectsUnknownDuplicateAndSensitiveFields(t *testing.T) {
	valid := `{"api_version":"hf-broker.io/plan/v1","operation":"git.push.force","operation_revision":1,"client_id":"bob","client_request_id":"request-1","target":{"kind":"hf","fields":{"name":["dataset/acme/demo"]}},"arguments":{},"preconditions":{},"credential_selector":{"name":"primary"},"presentation":{"title":"Force push"},"authorization":{"mode":"execution","requested_duration_seconds":300,"requested_max_uses":1,"target":{"kind":"hf","fields":{"name":["dataset/acme/demo"]}}},"created_at":"2026-07-11T12:00:00Z","expires_at":"2026-07-11T12:05:00Z"}`
	for _, value := range []string{
		strings.Replace(valid, `"operation":`, `"unknown":true,"operation":`, 1),
		strings.Replace(valid, `"operation":"git.push.force"`, `"operation":"git.push.force","operation":"repo.delete"`, 1),
		strings.Replace(valid, `"arguments":{}`, `"arguments":{"access_token":"canary"}`, 1),
		strings.Replace(valid, `"operation":"git.push.force"`, `"operation":"unknown.operation"`, 1),
	} {
		if _, err := decode([]byte(value)); err == nil {
			t.Fatalf("decode() accepted invalid plan: %s", value)
		}
	}
	if _, err := decode([]byte(valid)); err != nil {
		t.Fatalf("decode(valid) = %v", err)
	}
}

func FuzzDecodePlan(f *testing.F) {
	f.Add([]byte(`{"api_version":"hf-broker.io/plan/v1","operation":"git.push.force","operation_revision":1,"client_id":"bob","client_request_id":"request-1","target":{"kind":"hf","fields":{"name":["dataset/acme/demo"]}},"arguments":{},"preconditions":{},"credential_selector":{"name":"primary"},"presentation":{"title":"Force push"},"authorization":{"mode":"execution","requested_duration_seconds":300,"requested_max_uses":1,"target":{"kind":"hf","fields":{"name":["dataset/acme/demo"]}}},"created_at":"2026-07-11T12:00:00Z","expires_at":"2026-07-11T12:05:00Z"}`))
	f.Add([]byte(`{"api_version":"unknown"}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		plan, err := decode(data)
		if err != nil {
			return
		}
		encoded, err := encode(plan)
		if err != nil {
			t.Fatalf("encode accepted decoded plan then failed: %v", err)
		}
		if _, err := decode(encoded); err != nil {
			t.Fatalf("canonical round trip: %v", err)
		}
	})
}

func TestStoreRejectsMissingAndCorruptPlans(t *testing.T) {
	t.Parallel()
	plans := newTestPlanStore(t, time.Now)
	request := grants.Request{Client: "bob", ClientRequestID: "request-1", Operation: "git.push.force", Target: policy.Target{Kind: "hf", Fields: map[string][]string{"name": {"model/acme/demo"}}},
		Metadata: map[string]string{"hf_grant_mode": "window"}, Reason: "test", Duration: time.Minute, MaxUses: 1}
	if err := plans.Bind(&request); err != nil {
		t.Fatal(err)
	}
	grant := grants.Grant{Client: request.Client, ClientRequestID: request.ClientRequestID, Operation: request.Operation, Target: request.Target, Metadata: request.Metadata, Duration: request.Duration,
		RequestedDuration: request.Duration, MaxUses: request.MaxUses, RequestedMaxUses: request.MaxUses}
	digest := request.Metadata[MetadataDigest]
	if _, err := plans.database.SQL().ExecContext(t.Context(), "UPDATE plans SET canonical = ? WHERE digest = ?", []byte(`{"api_version":"hf-broker.io/plan/v1"}`), digest); err != nil {
		t.Fatal(err)
	}
	if err := (Validator{Store: plans}).ValidateExecution(grant); err == nil {
		t.Fatal("validator accepted corrupt plan")
	}
	grant.Metadata[MetadataDigest] = "missing"
	if err := (Validator{Store: plans}).ValidateExecution(grant); err == nil {
		t.Fatal("validator accepted missing digest")
	}
	if _, err := NewStore(nil); err == nil {
		t.Fatal("NewStore accepted a nil database")
	}
	if err := (*Store)(nil).Bind(&request); err == nil {
		t.Fatal("nil store accepted binding")
	}
}

func TestStorePutGetAndBindingVariants(t *testing.T) {
	t.Parallel()
	fixedNow := time.Date(2026, 7, 13, 8, 0, 0, 0, time.UTC)
	plans := newTestPlanStore(t, nil)
	plan := validTestPlan(fixedNow)
	digest, err := plans.Put(plan)
	if err != nil {
		t.Fatal(err)
	}
	stored, err := plans.Get(digest)
	if err != nil || stored.Operation != plan.Operation || stored.ClientRequestID != plan.ClientRequestID {
		t.Fatalf("Get() = %#v, %v", stored, err)
	}

	request := validTestRequest()
	prepared, err := plans.PrepareBind(&request)
	if err != nil || prepared.Digest == "" || request.Metadata[MetadataDigest] != prepared.Digest {
		t.Fatalf("PrepareBind() = %#v, %v, metadata = %#v", prepared, err, request.Metadata)
	}
	request = validTestRequest()
	if err := plans.BindAt(&request, fixedNow); err != nil {
		t.Fatal(err)
	}
	if _, err := plans.Get(request.Metadata[MetadataDigest]); err != nil {
		t.Fatalf("bound plan was not stored: %v", err)
	}

	if _, err := (*Store)(nil).Put(plan); err == nil {
		t.Fatal("nil store accepted Put")
	}
	if _, err := (*Store)(nil).Get(digest); err == nil {
		t.Fatal("nil store accepted Get")
	}
	if _, err := (*Store)(nil).PrepareBind(&request); err == nil {
		t.Fatal("nil store accepted PrepareBind")
	}
	if _, err := plans.PrepareBindAt(nil, fixedNow); err == nil {
		t.Fatal("PrepareBindAt accepted nil request")
	}
}

func TestStoreRejectsUnsupportedSchema(t *testing.T) {
	t.Parallel()
	plans := newTestPlanStore(t, time.Now)
	canonical := []byte(`{"value":true}`)
	digest, err := plans.database.PutPlan(t.Context(), "other/v1", canonical, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := plans.Get(digest); err == nil || !strings.Contains(err.Error(), "unsupported") {
		t.Fatalf("Get() error = %v, want unsupported schema", err)
	}
}

func TestPrepareRejectsInvalidPlanVariants(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 13, 8, 0, 0, 0, time.UTC)
	base := validTestPlan(now)
	tests := []struct {
		name   string
		mutate func(*Plan)
	}{
		{"api version", func(plan *Plan) { plan.APIVersion = "other/v1" }},
		{"revision", func(plan *Plan) { plan.OperationRevision = 2 }},
		{"operation", func(plan *Plan) { plan.Operation = "unknown.operation" }},
		{"client", func(plan *Plan) { plan.ClientID = " " }},
		{"request", func(plan *Plan) { plan.ClientRequestID = "" }},
		{"credential", func(plan *Plan) { plan.CredentialSelector.Name = "raw" }},
		{"created", func(plan *Plan) { plan.CreatedAt = time.Time{} }},
		{"expiry", func(plan *Plan) { plan.ExpiresAt = plan.CreatedAt }},
		{"title empty", func(plan *Plan) { plan.Presentation.Title = "" }},
		{"title long", func(plan *Plan) { plan.Presentation.Title = strings.Repeat("x", 161) }},
		{"summary long", func(plan *Plan) { plan.Presentation.Summary = strings.Repeat("x", 501) }},
		{"mode", func(plan *Plan) { plan.Authorization.Mode = "raw" }},
		{"duration", func(plan *Plan) { plan.Authorization.RequestedDurationSeconds = 0 }},
		{"uses negative", func(plan *Plan) { plan.Authorization.RequestedMaxUses = -1 }},
		{"execution uses", func(plan *Plan) { plan.Authorization.RequestedMaxUses = 2 }},
		{"target kind", func(plan *Plan) { plan.Authorization.Target.Kind = "" }},
		{"target fields", func(plan *Plan) { plan.Authorization.Target.Fields = nil }},
		{"empty target", func(plan *Plan) { plan.Target = nil }},
		{"array arguments", func(plan *Plan) { plan.Arguments = json.RawMessage(`[]`) }},
		{"empty preconditions", func(plan *Plan) { plan.Preconditions = json.RawMessage(`{`) }},
		{"raw token", func(plan *Plan) { plan.Arguments = json.RawMessage(`{"nested":[{"api-token":"canary"}]}`) }},
		{"raw password", func(plan *Plan) { plan.Target = json.RawMessage(`{"password":"canary"}`) }},
		{"blank target field", func(plan *Plan) { plan.Authorization.Target.Fields = map[string][]string{"name": {""}} }},
		{"blank attribute", func(plan *Plan) { plan.Authorization.Attributes = map[string][]string{"": {"value"}} }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			plan := base
			test.mutate(&plan)
			if _, err := Prepare(plan); err == nil {
				t.Fatal("Prepare() succeeded, want validation error")
			}
		})
	}
}

func TestValidatorRejectsMissingMetadataAndWidenedUses(t *testing.T) {
	t.Parallel()
	plans := newTestPlanStore(t, time.Now)
	validator := Validator{Store: plans}
	if err := validator.ValidateExecution(grants.Grant{}); err == nil {
		t.Fatal("validator accepted missing schema")
	}
	if err := (Validator{}).ValidateExecution(grants.Grant{}); err == nil {
		t.Fatal("validator without store accepted grant")
	}

	request := validTestRequest()
	if err := plans.Bind(&request); err != nil {
		t.Fatal(err)
	}
	grant := grants.Grant{Client: request.Client, ClientRequestID: request.ClientRequestID, Operation: request.Operation,
		Target: request.Target, Attrs: request.Attrs, Metadata: request.Metadata, Duration: request.Duration,
		RequestedDuration: request.Duration, MaxUses: request.MaxUses, RequestedMaxUses: request.MaxUses}
	if err := validator.ValidateActivation(t.Context(), grant, grants.ApprovalConstraints{MaxUses: 0, MaxUsesSpecified: false}); err != nil {
		t.Fatalf("unspecified use constraint = %v", err)
	}
	if err := validator.ValidateActivation(t.Context(), grant, grants.ApprovalConstraints{MaxUses: 2, MaxUsesSpecified: true}); !errors.Is(err, grants.ErrConstraintExceeded) {
		t.Fatalf("widened use constraint = %v", err)
	}
	grant.Operation = "repo.create"
	if err := validator.ValidateExecution(grant); err == nil {
		t.Fatal("validator accepted grant drift")
	}
}

func TestValidatorChecksCredentialBindingAndTargetAuthority(t *testing.T) {
	now := time.Date(2026, 7, 18, 0, 0, 0, 0, time.UTC)
	snapshot, err := providercredential.Normalize(providercredential.Snapshot{
		Provider: "huggingface", CredentialKind: "fine_grained_user_token", Subject: "alice",
		FingerprintSHA256: strings.Repeat("a", 64), Generation: 2, VerifiedAt: now,
		VerificationState: providercredential.VerificationValid,
		Capabilities: []providercredential.Capability{{Domain: "huggingface", Permission: "repo.content.read", AccessLevel: providercredential.AccessRead,
			Resource: providercredential.ResourceSelector{Kind: "repo", Name: "alice/private"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	credential, err := providercredential.NewService(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	plan := validTestPlan(now)
	plan.Operation = "repo.contents.read"
	plan.Target = json.RawMessage(`{"owner":"alice","name":"private"}`)
	plan.CredentialSelector.Binding = providercredential.Bind(snapshot)
	requirement := func(string) (providercredential.Requirement, bool) {
		return providercredential.Requirement{AllOf: []providercredential.AnyOf{{Alternatives: []providercredential.Need{{
			Domain: "huggingface", Permission: "repo.content.read", MinimumAccessLevel: providercredential.AccessRead, TargetBinding: "resource",
		}}}}}, true
	}
	if err := (Validator{Credential: credential, Requirement: requirement}).ValidateCredential(plan); err != nil {
		t.Fatal(err)
	}
	if err := (Validator{}).ValidateCredential(plan); err != nil {
		t.Fatalf("nil credential = %v", err)
	}
	stale := plan
	stale.CredentialSelector.Binding.Generation++
	if err := (Validator{Credential: credential, Requirement: requirement}).ValidateCredential(stale); err == nil {
		t.Fatal("stale binding was accepted")
	}
	if err := (Validator{Credential: credential}).ValidateCredential(plan); err == nil {
		t.Fatal("missing requirement map was accepted")
	}
	if err := (Validator{Credential: credential, Requirement: func(string) (providercredential.Requirement, bool) {
		return providercredential.Requirement{}, false
	}}).ValidateCredential(plan); err == nil {
		t.Fatal("missing operation requirement was accepted")
	}
	malformed := plan
	malformed.Target = json.RawMessage(`{`)
	if err := (Validator{Credential: credential, Requirement: requirement}).ValidateCredential(malformed); err == nil {
		t.Fatal("malformed target was accepted")
	}
	outside := plan
	outside.Target = json.RawMessage(`{"owner":"alice","name":"other"}`)
	if err := (Validator{Credential: credential, Requirement: requirement}).ValidateCredential(outside); err == nil {
		t.Fatal("target outside credential authority was accepted")
	}
}

func validTestRequest() grants.Request {
	return grants.Request{
		Client: "bob", ClientRequestID: "request-1", Operation: "repo.delete",
		Target: policy.Target{Kind: "hf", Fields: map[string][]string{"name": {"dataset/acme/demo"}}},
		Attrs:  map[string][]string{"visibility": {`"private"`}}, Metadata: map[string]string{"hf_grant_mode": "execution"},
		Reason: "remove obsolete test repository", Duration: 5 * time.Minute, MaxUses: 1,
	}
}

func validTestPlan(now time.Time) Plan {
	return FromRequest(validTestRequest(), now)
}

func newTestPlanStore(t *testing.T, now func() time.Time) *Store {
	t.Helper()
	database, err := state.Open(t.Context(), t.TempDir(), state.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	plans, err := newStore(database, now)
	if err != nil {
		t.Fatal(err)
	}
	return plans
}
