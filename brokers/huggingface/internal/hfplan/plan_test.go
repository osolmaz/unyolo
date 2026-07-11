package hfplan

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/osolmaz/brokerkit/grants"
	"github.com/osolmaz/brokerkit/policy"
)

func TestStoreBindsDeterministicImmutablePlan(t *testing.T) {
	t.Parallel()
	directory := filepath.Join(t.TempDir(), "plans")
	plans, err := NewStore(directory)
	if err != nil {
		t.Fatal(err)
	}
	request := grants.Request{Client: "bob", Operation: "git.push.force", Target: policy.Target{Kind: "hf", Fields: map[string][]string{"name": {"dataset/acme/demo"}, "ref": {"refs/heads/main"}}},
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
	if err := validator.ValidateActivation(context.Background(), created.Grant, grants.ApprovalConstraints{Duration: 10 * time.Minute}); !errors.Is(err, grants.ErrConstraintExceeded) {
		t.Fatalf("widening error = %v", err)
	}
}

func TestStoreRejectsMissingAndCorruptPlans(t *testing.T) {
	t.Parallel()
	plans, _ := NewStore(filepath.Join(t.TempDir(), "plans"))
	request := grants.Request{Client: "bob", Operation: "write", Target: policy.Target{Kind: "hf", Fields: map[string][]string{"name": {"model/acme/demo"}}},
		Metadata: map[string]string{"hf_grant_mode": "window"}, Reason: "test", Duration: time.Minute, MaxUses: 1}
	if err := plans.Bind(&request); err != nil {
		t.Fatal(err)
	}
	grant := grants.Grant{Operation: request.Operation, Target: request.Target, Metadata: request.Metadata, Duration: request.Duration,
		RequestedDuration: request.Duration, MaxUses: request.MaxUses, RequestedMaxUses: request.MaxUses}
	digest := request.Metadata[MetadataDigest]
	if err := os.WriteFile(plans.path(digest), []byte(`{"schema":"hf-plan/v1"}`), 0o600); err != nil {
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
