package ghplan

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/osolmaz/brokerkit/agentv1"
	"github.com/osolmaz/brokerkit/grants"
	"github.com/osolmaz/brokerkit/policy"
	"github.com/osolmaz/brokerkit/state"
)

var fixtureTime = time.Date(2026, 7, 12, 0, 0, 0, 0, time.UTC)

func TestStoreBindsDeterministicImmutablePlan(t *testing.T) {
	t.Parallel()
	database := testDatabase(t)
	plans, err := newStore(database, "installation", func() time.Time { return fixtureTime })
	if err != nil {
		t.Fatal(err)
	}
	request := testRequest()
	if err := plans.Bind(&request); err != nil {
		t.Fatal(err)
	}
	digest := request.Metadata[MetadataDigest]
	if digest == "" || request.Metadata[MetadataSchema] != SchemaV1 || request.Metadata["github_grant_mode"] != "window" {
		t.Fatalf("metadata = %+v", request.Metadata)
	}
	second := testRequest()
	if err := plans.Bind(&second); err != nil || second.Metadata[MetadataDigest] != digest {
		t.Fatalf("second bind = %+v, %v", second.Metadata, err)
	}

	store := grants.NewDatabase(database, grants.Options{})
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

func TestCanonicalPlanDigestChangesOnlyWithPlanContent(t *testing.T) {
	first, err := Prepare(testAdapterPlan())
	if err != nil {
		t.Fatal(err)
	}
	second, err := Prepare(testAdapterPlan())
	if err != nil || second.Digest != first.Digest || string(second.Canonical) != string(first.Canonical) {
		t.Fatalf("deterministic plans = %q/%q, %v", first.Digest, second.Digest, err)
	}
	changed := testAdapterPlan()
	changed.Arguments = json.RawMessage(`{"input":{"title":"changed","head":"work","base":"main"}}`)
	third, err := Prepare(changed)
	if err != nil || third.Digest == first.Digest {
		t.Fatalf("changed digest = %q, original %q, %v", third.Digest, first.Digest, err)
	}
}

func TestDecodeRejectsUnknownDuplicateSecretAndTrailingFields(t *testing.T) {
	prepared, err := Prepare(testAdapterPlan())
	if err != nil {
		t.Fatal(err)
	}
	valid := string(prepared.Canonical)
	for _, value := range []string{
		strings.Replace(valid, `"api_version":`, `"unknown":true,"api_version":`, 1),
		strings.Replace(valid, `"operation":`, `"operation":"pull_request.create","operation":`, 1),
		strings.Replace(valid, `"input":{`, `"input":{"token":"canary",`, 1),
		strings.Replace(valid, `"pull_request.create"`, `"github.raw.request"`, 1),
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
	prepared, err := Prepare(testAdapterPlan())
	if err != nil {
		f.Fatal(err)
	}
	f.Add(prepared.Canonical)
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

func TestStoreRejectsMissingCorruptAndInvalidCredentials(t *testing.T) {
	t.Parallel()
	database := testDatabase(t)
	plans, _ := newStore(database, "installation", func() time.Time { return fixtureTime })
	request := testRequest()
	prepared, err := Prepare(testAdapterPlan())
	if err != nil {
		t.Fatal(err)
	}
	digest, err := database.PutPlan(t.Context(), "unsupported.github.plan", prepared.Canonical, fixtureTime)
	if err != nil {
		t.Fatal(err)
	}
	request.Metadata = map[string]string{MetadataSchema: SchemaV1, MetadataDigest: digest, "github_grant_mode": "window"}
	grant := grants.Grant{Client: request.Client, ClientRequestID: request.ClientRequestID, Operation: request.Operation, Target: request.Target, Attrs: request.Attrs, Metadata: request.Metadata,
		Duration: request.Duration, RequestedDuration: request.Duration, MaxUses: request.MaxUses, RequestedMaxUses: request.MaxUses}
	if err := (Validator{Store: plans}).ValidateExecution(grant); err == nil {
		t.Fatal("validator accepted unsupported plan schema")
	}
	grant.Metadata[MetadataDigest] = "missing"
	if err := (Validator{Store: plans}).ValidateExecution(grant); err == nil {
		t.Fatal("validator accepted missing digest")
	}
	if _, err := NewStore(nil, "installation"); err == nil {
		t.Fatal("NewStore accepted nil database")
	}
	if _, err := NewStore(database, "token"); err == nil {
		t.Fatal("NewStore accepted invalid credential selector")
	}
	if err := (*Store)(nil).Bind(&request); err == nil {
		t.Fatal("nil store accepted binding")
	}
}

func testAdapterPlan() Plan {
	return Plan{
		APIVersion: SchemaV1, Operation: "pull_request.create", OperationRevision: 1,
		ClientID: "bob", ClientRequestID: "request-1",
		Target:             json.RawMessage(`{"kind":"repo","owner":"osolmaz","name":"brokerkit"}`),
		Arguments:          json.RawMessage(`{"input":{"title":"work","head":"work","base":"main"}}`),
		Preconditions:      json.RawMessage(`{"kind":"installation","installation_id":42,"permissions":{"pull_requests":"write"},"api_host":"api.github.com"}`),
		CredentialSelector: CredentialSelector{Name: "primary", Kind: "installation"},
		Presentation:       agentv1.Presentation{Title: "Create a pull request", Summary: "pull_request.create on osolmaz/brokerkit"},
		Authorization: Authorization{Mode: "execution", RequestedDurationSeconds: 300, RequestedMaxUses: 1,
			Target:       GrantTarget{Kind: "repo", Fields: map[string][]string{"owner": {"osolmaz"}, "name": {"brokerkit"}}},
			PolicyEffect: "request", PolicyRuleIDs: []string{"request-pr"}},
		CreatedAt: fixtureTime, ExpiresAt: fixtureTime.Add(10 * time.Minute),
	}
}

func testDatabase(t *testing.T) *state.Database {
	t.Helper()
	database, err := state.Open(t.Context(), t.TempDir(), state.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	return database
}

func testRequest() grants.Request {
	return grants.Request{
		Client: "bob", ClientRequestID: "request-1", Operation: "git.push.force",
		Target: policy.Target{Kind: "repo", Fields: map[string][]string{"owner": {"osolmaz"}, "name": {"gh-broker"}}},
		Attrs:  map[string][]string{"ref": {"refs/heads/main"}}, Reason: "repair",
		Duration: 5 * time.Minute, PendingTimeout: time.Minute, MaxUses: 2, MaxUsesSpecified: true,
	}
}
