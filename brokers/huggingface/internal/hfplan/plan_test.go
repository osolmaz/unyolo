package hfplan

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/osolmaz/brokerkit/grants"
	"github.com/osolmaz/brokerkit/plandigest"
	"github.com/osolmaz/brokerkit/policy"
	"github.com/osolmaz/brokerkit/state"
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
	const expected = "fd4b6fe4595c07215d1a88949b10ea33d3cab5d6289c7f7112314b13a2cf94df"
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
