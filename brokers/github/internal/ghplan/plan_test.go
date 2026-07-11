package ghplan

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
	plans, err := NewStore(filepath.Join(t.TempDir(), "plans"), "github_app")
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
	mutated.Attrs = map[string][]string{"ref": {"refs/heads/release"}}
	if err := validator.ValidateExecution(mutated); err == nil {
		t.Fatal("validator accepted mutated grant")
	}
	if err := validator.ValidateActivation(context.Background(), created.Grant, grants.ApprovalConstraints{Duration: 10 * time.Minute}); !errors.Is(err, grants.ErrConstraintExceeded) {
		t.Fatalf("widening error = %v", err)
	}
}

func TestStoreRejectsMissingCorruptAndCrossCredentialPlans(t *testing.T) {
	t.Parallel()
	plans, _ := NewStore(filepath.Join(t.TempDir(), "plans"), "github_app")
	request := testRequest()
	if err := plans.Bind(&request); err != nil {
		t.Fatal(err)
	}
	grant := grants.Grant{Operation: request.Operation, Target: request.Target, Attrs: request.Attrs, Metadata: request.Metadata,
		Duration: request.Duration, RequestedDuration: request.Duration, MaxUses: request.MaxUses, RequestedMaxUses: request.MaxUses}
	digest := request.Metadata[MetadataDigest]
	if err := os.WriteFile(plans.path(digest), []byte(`{"schema":"gh-broker.io/plan/v1"}`), 0o600); err != nil {
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
		t.Fatal("NewStore accepted invalid credential mode")
	}
	if err := (*Store)(nil).Bind(&request); err == nil {
		t.Fatal("nil store accepted binding")
	}
}

func TestKindForOperation(t *testing.T) {
	t.Parallel()
	if got, ok := kindForOperation("pr.merge"); !ok || got != KindSingleExecution {
		t.Fatalf("PR kind = %q", got)
	}
	if got, ok := kindForOperation("git.push.force"); !ok || got != KindCapabilityWindow {
		t.Fatalf("push kind = %q", got)
	}
	if _, ok := kindForOperation("contents.read"); ok {
		t.Fatal("read operation is grantable")
	}
}

func TestStoreRejectsUnknownOperationTargetAndAttributes(t *testing.T) {
	t.Parallel()
	plans, _ := NewStore(filepath.Join(t.TempDir(), "plans"), "github_app")
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
		Client: "bob", Operation: "git.push.force",
		Target: policy.Target{Kind: "repo", Fields: map[string][]string{"owner": {"osolmaz"}, "name": {"gh-broker"}}},
		Attrs:  map[string][]string{"ref": {"refs/heads/main"}}, Reason: "repair", Duration: 5 * time.Minute, MaxUses: 2,
	}
}
