package ghplan

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/osolmaz/unyolo/agent/v1"
	"github.com/osolmaz/unyolo/authorization/budget"
	"github.com/osolmaz/unyolo/authorization/grants"
	"github.com/osolmaz/unyolo/authorization/policy"
	"github.com/osolmaz/unyolo/brokers/github/internal/githubauth"
	"github.com/osolmaz/unyolo/credential/provider"
	"github.com/osolmaz/unyolo/internal/storage/state"
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
	if digest == "" || request.Metadata[MetadataSchema] != SchemaV1 || request.Metadata[grants.MetadataMode] != "window" {
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
	request.Metadata = map[string]string{MetadataSchema: SchemaV1, MetadataDigest: digest, grants.MetadataMode: "window"}
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

func TestStoreWrapperAPIsPersistAndBindPlans(t *testing.T) {
	database := testDatabase(t)
	store, err := NewStoreWithClock(database, "installation", func() time.Time { return fixtureTime })
	if err != nil {
		t.Fatal(err)
	}
	plan := testAdapterPlan()
	digest, err := store.Put(plan)
	if err != nil || digest == "" {
		t.Fatalf("Put() = %q, %v", digest, err)
	}
	loaded, err := store.Get(digest)
	if err != nil || loaded.Operation != plan.Operation || loaded.ClientRequestID != plan.ClientRequestID {
		t.Fatalf("Get() = %+v, %v", loaded, err)
	}
	request := testRequest()
	prepared, err := store.PrepareBind(&request)
	if err != nil || prepared.Digest == "" || request.Metadata[MetadataDigest] != prepared.Digest {
		t.Fatalf("PrepareBind() = %+v metadata=%+v err=%v", prepared, request.Metadata, err)
	}
	if err := store.BindAt(&request, fixtureTime.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := (*Store)(nil).Put(plan); err == nil {
		t.Fatal("nil store persisted a plan")
	}
	if _, err := (*Store)(nil).Get(digest); err == nil {
		t.Fatal("nil store loaded a plan")
	}
	if _, err := (*Store)(nil).PrepareBind(&request); err == nil {
		t.Fatal("nil store prepared a grant")
	}
}

func TestPlanProjectionAndFallbackBoundaries(t *testing.T) {
	request := testRequest()
	request.PendingTimeout = -request.Duration
	plan := FromRequest(request, fixtureTime)
	if !plan.ExpiresAt.Equal(fixtureTime.Add(request.Duration)) || plan.Authorization.Mode != "window" || plan.CredentialSelector.Kind != "" {
		t.Fatalf("fallback plan = %+v", plan)
	}
	metadataRequest := grants.Request{}
	BindPrepared(&metadataRequest, grants.ImmutablePlan{SchemaName: SchemaV1, Digest: "digest"})
	BindPresentation(&metadataRequest, agentv1.Presentation{Title: strings.Repeat("t", 200), Summary: strings.Repeat("s", 600)})
	if len(metadataRequest.Metadata[MetadataTitle]) != 160 || len(metadataRequest.Metadata[MetadataSummary]) != 500 || metadataRequest.Metadata[MetadataDigest] != "digest" {
		t.Fatalf("bounded metadata = %+v", metadataRequest.Metadata)
	}
	multibyte := strings.Repeat("a", 159) + "é"
	if got := truncateUTF8(multibyte, 160); !json.Valid([]byte(`"`+got+`"`)) || len(got) > 160 {
		t.Fatalf("UTF-8 truncation = %q", got)
	}
	if modeForOperation("repo.delete", "") != "window" || modeForOperation("repo.metadata.read", "execution") != "execution" {
		t.Fatal("operation mode selection drifted")
	}
	if modeCredentialKind("repo.delete", "development-token") != "installation" || modeCredentialKind("git.fetch", "development-token") != "development-token" {
		t.Fatal("credential kind selection drifted")
	}
	if useConstraintExceeds(grants.ApprovalConstraints{}, 1) || !useConstraintExceeds(grants.ApprovalConstraints{MaxUses: usebudget.Unlimited, MaxUsesSpecified: true}, 1) {
		t.Fatal("use constraint boundary drifted")
	}
	duration, uses := requestedGrantBounds(grants.Grant{Duration: time.Minute, RequestedDuration: 0, MaxUses: 2, RequestedMaxUses: -1})
	if duration != time.Minute || uses != 2 {
		t.Fatalf("requested grant fallback = %s, %d", duration, uses)
	}
}

func TestPlanValidationRejectsEachBoundary(t *testing.T) {
	base := testAdapterPlan()
	tests := map[string]func(*Plan){
		"identity":      func(plan *Plan) { plan.ClientID = "" },
		"presentation":  func(plan *Plan) { plan.Presentation.Title = "" },
		"authorization": func(plan *Plan) { plan.Authorization.RequestedMaxUses = 2 },
		"empty object":  func(plan *Plan) { plan.Target = nil },
		"secret":        func(plan *Plan) { plan.Preconditions = json.RawMessage(`{"token":"secret"}`) },
		"target values": func(plan *Plan) { plan.Authorization.Target.Fields = map[string][]string{"": {"bad"}} },
		"attrs":         func(plan *Plan) { plan.Authorization.Attributes = map[string][]string{"ref": {""}} },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			plan := base
			mutate(&plan)
			if _, err := Prepare(plan); err == nil {
				t.Fatal("invalid plan accepted")
			}
		})
	}
	for _, raw := range []json.RawMessage{json.RawMessage(`{`), json.RawMessage(`[]`), json.RawMessage(`{}`), json.RawMessage(strings.Repeat(" ", maxTargetBytes+1))} {
		if _, err := canonicalObject(raw, maxTargetBytes); err == nil && string(raw) != `{}` {
			t.Fatalf("invalid canonical object accepted: %q", raw[:min(len(raw), 20)])
		}
	}
}

func TestValidatorChecksSelectedGitHubCredential(t *testing.T) {
	metadata := githubauth.Metadata{Kind: githubauth.KindInstallation, InstallationID: 42, APIHost: "api.github.com",
		Permissions: map[string]string{"pull_requests": "write"}}
	snapshot, err := githubauth.SnapshotForMetadata(metadata, 3, fixtureTime)
	if err != nil {
		t.Fatal(err)
	}
	plan := testAdapterPlan()
	plan.CredentialSelector.Binding = providercredential.Bind(snapshot)
	requirement := func(string) (providercredential.Requirement, bool) {
		return providercredential.Requirement{AllOf: []providercredential.AnyOf{{Alternatives: []providercredential.Need{{
			Domain: "github", Permission: "pull_requests", MinimumAccessLevel: providercredential.AccessWrite,
		}}}}}, true
	}
	credential := func(Plan) (providercredential.Snapshot, error) { return snapshot, nil }
	validator := Validator{Credential: credential, Requirement: requirement}
	if err := validator.ValidateCredential(plan); err != nil {
		t.Fatal(err)
	}
	if err := (Validator{}).ValidateCredential(plan); err != nil {
		t.Fatalf("nil credential = %v", err)
	}
	unbound := plan
	unbound.CredentialSelector.Binding = providercredential.Binding{}
	if err := validator.ValidateCredential(unbound); err != nil {
		t.Fatalf("unbound development plan = %v", err)
	}
	if err := (Validator{Credential: credential}).ValidateCredential(plan); err == nil {
		t.Fatal("missing requirement map was accepted")
	}
	if err := (Validator{Credential: func(Plan) (providercredential.Snapshot, error) {
		return providercredential.Snapshot{}, errors.New("unavailable")
	}, Requirement: requirement}).ValidateCredential(plan); err == nil {
		t.Fatal("credential lookup failure was accepted")
	}
	if err := (Validator{Credential: credential, Requirement: func(string) (providercredential.Requirement, bool) {
		return providercredential.Requirement{}, false
	}}).ValidateCredential(plan); err == nil {
		t.Fatal("missing operation requirement was accepted")
	}
	stale := plan
	stale.CredentialSelector.Binding.Generation++
	if err := validator.ValidateCredential(stale); err == nil {
		t.Fatal("stale selected credential was accepted")
	}
}

func testAdapterPlan() Plan {
	return Plan{
		APIVersion: SchemaV1, Operation: "pull_request.create", OperationRevision: 1,
		ClientID: "bob", ClientRequestID: "request-1",
		Target:             json.RawMessage(`{"kind":"repo","owner":"osolmaz","name":"unyolo"}`),
		Arguments:          json.RawMessage(`{"input":{"title":"work","head":"work","base":"main"}}`),
		Preconditions:      json.RawMessage(`{"kind":"installation","installation_id":42,"permissions":{"pull_requests":"write"},"api_host":"api.github.com"}`),
		CredentialSelector: CredentialSelector{Name: "primary", Kind: "installation"},
		Presentation:       agentv1.Presentation{Title: "Create a pull request", Summary: "pull_request.create on osolmaz/unyolo"},
		Authorization: Authorization{Mode: "execution", RequestedDurationSeconds: 300, RequestedMaxUses: 1,
			Target:       GrantTarget{Kind: "repo", Fields: map[string][]string{"owner": {"osolmaz"}, "name": {"unyolo"}}},
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
