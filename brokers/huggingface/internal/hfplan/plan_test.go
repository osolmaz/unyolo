package hfplan

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/osolmaz/brokerkit/grants"
	"github.com/osolmaz/brokerkit/planstore"
	"github.com/osolmaz/brokerkit/policy"
)

func TestStoreBindsDeterministicImmutablePlan(t *testing.T) {
	t.Parallel()
	directory := filepath.Join(t.TempDir(), "plans")
	fixedNow := time.Date(2026, 7, 11, 12, 0, 0, 0, time.UTC)
	plans, err := newStore(directory, func() time.Time { return fixedNow })
	if err != nil {
		t.Fatal(err)
	}
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

	store := grants.New(filepath.Join(t.TempDir(), "grants.json"), grants.Options{})
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
	const expected = "b81f9373519474f5d95ecbebe58f04c86bc651c9b3c810c4e948f07c05107a36"
	if got := planstore.Digest(encoded); got != expected {
		t.Fatalf("canonical digest = %s, want %s\n%s", got, expected, encoded)
	}
}

func TestDecodeRejectsUnknownDuplicateAndSensitiveFields(t *testing.T) {
	valid := `{"schema_version":"hf-broker.io/plan/v1","kind":"capability_window","client_id":"bob","client_request_id":"request-1","operation":"git.push.force","target_kind":"hf","target":{"name":["dataset/acme/demo"]},"constraints":{"mode":"window","requested_duration_seconds":300,"requested_max_uses":1},"credential_selector":"primary","created_at":"2026-07-11T12:00:00Z"}`
	for _, value := range []string{
		strings.Replace(valid, `"kind":`, `"unknown":true,"kind":`, 1),
		strings.Replace(valid, `"kind":"capability_window"`, `"kind":"capability_window","kind":"single_execution"`, 1),
		strings.Replace(valid, `"target":{"name":["dataset/acme/demo"]}`, `"target":{"name":["dataset/acme/demo"],"access_token":["canary"]}`, 1),
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
	f.Add([]byte(`{"schema_version":"hf-broker.io/plan/v1","kind":"capability_window","client_id":"bob","client_request_id":"request-1","operation":"git.push.force","target_kind":"hf","target":{"name":["dataset/acme/demo"]},"constraints":{"mode":"window","requested_duration_seconds":300,"requested_max_uses":1},"credential_selector":"primary","created_at":"2026-07-11T12:00:00Z"}`))
	f.Add([]byte(`{"schema_version":"unknown"}`))
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
	plans, _ := NewStore(filepath.Join(t.TempDir(), "plans"))
	request := grants.Request{Client: "bob", ClientRequestID: "request-1", Operation: "git.push.force", Target: policy.Target{Kind: "hf", Fields: map[string][]string{"name": {"model/acme/demo"}}},
		Metadata: map[string]string{"hf_grant_mode": "window"}, Reason: "test", Duration: time.Minute, MaxUses: 1}
	if err := plans.Bind(&request); err != nil {
		t.Fatal(err)
	}
	grant := grants.Grant{Client: request.Client, ClientRequestID: request.ClientRequestID, Operation: request.Operation, Target: request.Target, Metadata: request.Metadata, Duration: request.Duration,
		RequestedDuration: request.Duration, MaxUses: request.MaxUses, RequestedMaxUses: request.MaxUses}
	digest := request.Metadata[MetadataDigest]
	if err := os.WriteFile(plans.shared.Path(digest), []byte(`{"schema_version":"hf-broker.io/plan/v1"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := (Validator{Store: plans}).ValidateExecution(grant); err == nil {
		t.Fatal("validator accepted corrupt plan")
	}
	grant.Metadata[MetadataDigest] = "missing"
	if err := (Validator{Store: plans}).ValidateExecution(grant); err == nil {
		t.Fatal("validator accepted missing digest")
	}
	if _, err := NewStore(""); err == nil {
		t.Fatal("NewStore accepted empty path")
	}
	if err := (*Store)(nil).Bind(&request); err == nil {
		t.Fatal("nil store accepted binding")
	}
}

func TestStoreCollectsOnlyOldUnreferencedPlans(t *testing.T) {
	t.Parallel()
	directory := filepath.Join(t.TempDir(), "plans")
	plans, _ := newStore(directory, func() time.Time { return time.Date(2026, 7, 11, 12, 0, 0, 0, time.UTC) })
	request := grants.Request{Client: "bob", ClientRequestID: "referenced", Operation: "git.push.force",
		Target:   policy.Target{Kind: "hf", Fields: map[string][]string{"name": {"dataset/acme/demo"}}},
		Metadata: map[string]string{"hf_grant_mode": "window"}, Duration: time.Minute, MaxUses: 1}
	referenced, err := plans.Put(FromRequest(request, time.Date(2026, 7, 11, 12, 0, 0, 0, time.UTC)))
	if err != nil {
		t.Fatal(err)
	}
	request.ClientRequestID = "orphan"
	orphan, err := plans.Put(FromRequest(request, time.Date(2026, 7, 11, 12, 1, 0, 0, time.UTC)))
	if err != nil {
		t.Fatal(err)
	}
	old := time.Date(2026, 7, 10, 0, 0, 0, 0, time.UTC)
	for _, digest := range []string{referenced, orphan} {
		if err := os.Chtimes(plans.shared.Path(digest), old, old); err != nil {
			t.Fatal(err)
		}
	}
	removed, err := plans.CollectOrphans(map[string]bool{referenced: true}, time.Date(2026, 7, 11, 0, 0, 0, 0, time.UTC))
	if err != nil || removed != 1 {
		t.Fatalf("CollectOrphans() = %d, %v", removed, err)
	}
	if _, err := plans.Get(referenced); err != nil {
		t.Fatalf("referenced plan removed: %v", err)
	}
	if _, err := plans.Get(orphan); err == nil {
		t.Fatal("old orphan was retained")
	}
}
