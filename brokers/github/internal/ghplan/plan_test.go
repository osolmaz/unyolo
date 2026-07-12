package ghplan

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/osolmaz/brokerkit/grants"
	"github.com/osolmaz/brokerkit/plandigest"
	"github.com/osolmaz/brokerkit/policy"
)

var fixtureTime = time.Date(2026, 7, 12, 0, 0, 0, 0, time.UTC)

func TestStoreBindsDeterministicImmutablePlan(t *testing.T) {
	t.Parallel()
	plans, err := newStore(filepath.Join(t.TempDir(), "plans"), "github_app", func() time.Time { return fixtureTime })
	if err != nil {
		t.Fatal(err)
	}
	request := testRequest()
	if err := plans.Bind(&request); err != nil {
		t.Fatal(err)
	}
	digest := request.Metadata[MetadataDigest]
	if digest == "" || request.Metadata[MetadataSchema] != SchemaV1 || request.Metadata[MetadataMode] != KindCapabilityWindow {
		t.Fatalf("metadata = %+v", request.Metadata)
	}
	second := testRequest()
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
	mutated.Target.Kind = "installation"
	if err := validator.ValidateExecution(mutated); err == nil {
		t.Fatal("validator accepted mutated target kind")
	}
	mutated = created.Grant
	mutated.ClientRequestID = "other"
	if err := validator.ValidateExecution(mutated); err == nil {
		t.Fatal("validator accepted mutated request identity")
	}
	if err := validator.ValidateActivation(context.Background(), created.Grant, grants.ApprovalConstraints{Duration: 10 * time.Minute}); !errors.Is(err, grants.ErrConstraintExceeded) {
		t.Fatalf("widening error = %v", err)
	}
}

func TestCanonicalPlanDigest(t *testing.T) {
	encoded, err := encode(FromRequest(testRequest(), "github_app", fixtureTime))
	if err != nil {
		t.Fatal(err)
	}
	const expected = "986bf18a493e4dbbeef6bb4a9c701f845f30a9d602dc7506d3fa920163ff9a8c"
	if got := plandigest.Digest(encoded); got != expected {
		t.Fatalf("canonical digest = %s, want %s\n%s", got, expected, encoded)
	}
}

func TestDecodeRejectsUnknownDuplicateSensitiveAndTrailingFields(t *testing.T) {
	valid := `{"schema_version":"gh-broker.io/plan/v1","kind":"capability_window","client_id":"bob","client_request_id":"request-1","operation":"git.push.force","target_kind":"repo","target":{"name":["gh-broker"],"owner":["osolmaz"]},"constraints":{"attributes":{"ref":["refs/heads/main"]},"requested_duration_seconds":300,"requested_max_uses":2},"credential_selector":"github_app","created_at":"2026-07-12T00:00:00Z"}`
	for _, value := range []string{
		strings.Replace(valid, `"kind":`, `"unknown":true,"kind":`, 1),
		strings.Replace(valid, `"kind":"capability_window"`, `"kind":"capability_window","kind":"single_execution"`, 1),
		strings.Replace(valid, `"name":["gh-broker"]`, `"name":["gh-broker"],"access_token":["canary"]`, 1),
		strings.Replace(valid, `"operation":"git.push.force"`, `"operation":"unknown.operation"`, 1),
		valid + `{}`,
	} {
		if _, err := decode([]byte(value)); err == nil {
			t.Fatalf("decode accepted invalid plan: %s", value)
		}
	}
	if _, err := decode([]byte(valid)); err != nil {
		t.Fatalf("decode valid plan: %v", err)
	}
}

func FuzzDecodePlan(f *testing.F) {
	f.Add([]byte(`{"schema_version":"gh-broker.io/plan/v1","kind":"capability_window","client_id":"bob","client_request_id":"request-1","operation":"git.push.force","target_kind":"repo","target":{"name":["gh-broker"],"owner":["osolmaz"]},"constraints":{"attributes":{"ref":["refs/heads/main"]},"requested_duration_seconds":300,"requested_max_uses":2},"credential_selector":"github_app","created_at":"2026-07-12T00:00:00Z"}`))
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

func TestStoreRejectsMissingCorruptAndCrossCredentialPlans(t *testing.T) {
	t.Parallel()
	plans, _ := newStore(filepath.Join(t.TempDir(), "plans"), "github_app", func() time.Time { return fixtureTime })
	request := testRequest()
	if err := plans.Bind(&request); err != nil {
		t.Fatal(err)
	}
	grant := grants.Grant{Client: request.Client, ClientRequestID: request.ClientRequestID, Operation: request.Operation, Target: request.Target, Attrs: request.Attrs, Metadata: request.Metadata,
		Duration: request.Duration, RequestedDuration: request.Duration, MaxUses: request.MaxUses, RequestedMaxUses: request.MaxUses}
	digest := request.Metadata[MetadataDigest]
	if err := os.WriteFile(plans.shared.Path(digest), []byte(`{"schema_version":"gh-broker.io/plan/v1"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := (Validator{Store: plans}).ValidateExecution(grant); err == nil {
		t.Fatal("validator accepted corrupt plan")
	}
	grant.Metadata[MetadataDigest] = "missing"
	if err := (Validator{Store: plans}).ValidateExecution(grant); err == nil {
		t.Fatal("validator accepted missing digest")
	}
	if _, err := NewStore("", "github_app"); err == nil {
		t.Fatal("NewStore accepted empty path")
	}
	if _, err := NewStore(t.TempDir(), "token"); err == nil {
		t.Fatal("NewStore accepted invalid credential selector")
	}
	if err := (*Store)(nil).Bind(&request); err == nil {
		t.Fatal("nil store accepted binding")
	}
}

func TestStoreCollectsOnlyOldUnreferencedPlans(t *testing.T) {
	t.Parallel()
	directory := filepath.Join(t.TempDir(), "plans")
	plans, _ := newStore(directory, "github_app", func() time.Time { return fixtureTime })
	referenced, err := plans.Put(FromRequest(testRequest(), "github_app", fixtureTime))
	if err != nil {
		t.Fatal(err)
	}
	request := testRequest()
	request.ClientRequestID = "orphan"
	orphan, err := plans.Put(FromRequest(request, "github_app", fixtureTime.Add(time.Minute)))
	if err != nil {
		t.Fatal(err)
	}
	old := fixtureTime.Add(-48 * time.Hour)
	for _, digest := range []string{referenced, orphan} {
		if err := os.Chtimes(plans.shared.Path(digest), old, old); err != nil {
			t.Fatal(err)
		}
	}
	removed, err := plans.CollectOrphans(map[string]bool{referenced: true}, fixtureTime.Add(-24*time.Hour))
	if err != nil || removed != 1 {
		t.Fatalf("CollectOrphans = %d, %v", removed, err)
	}
	if _, err := plans.Get(referenced); err != nil {
		t.Fatalf("referenced plan removed: %v", err)
	}
	if _, err := plans.Get(orphan); err == nil {
		t.Fatal("old orphan was retained")
	}
}

func TestKindForOperationAndValidation(t *testing.T) {
	t.Parallel()
	if got, ok := kindForOperation("pr.merge"); !ok || got != KindSingleExecution {
		t.Fatalf("PR kind = %q", got)
	}
	if _, ok := kindForOperation("contents.read"); ok {
		t.Fatal("read operation is grantable")
	}
	plans, _ := newStore(filepath.Join(t.TempDir(), "plans"), "github_app", func() time.Time { return fixtureTime })
	tests := []grants.Request{testRequest(), testRequest(), testRequest()}
	tests[0].Operation = "repo.delete"
	tests[1].Target.Fields["installation"] = []string{"42"}
	tests[2].Attrs["path"] = []string{"README.md"}
	for index := range tests {
		if err := plans.Bind(&tests[index]); err == nil {
			t.Fatalf("case %d was accepted", index)
		}
	}
}

func testRequest() grants.Request {
	return grants.Request{
		Client: "bob", ClientRequestID: "request-1", Operation: "git.push.force",
		Target: policy.Target{Kind: "repo", Fields: map[string][]string{"owner": {"osolmaz"}, "name": {"gh-broker"}}},
		Attrs:  map[string][]string{"ref": {"refs/heads/main"}}, Reason: "repair", Duration: 5 * time.Minute, MaxUses: 2,
	}
}
