package authorization

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/osolmaz/unyolo/authorization/budget"
	"github.com/osolmaz/unyolo/authorization/grants"
	"github.com/osolmaz/unyolo/authorization/policy"
	"github.com/osolmaz/unyolo/internal/storage/state"
	"github.com/osolmaz/unyolo/operation/digest"
)

func TestCoordinatorAuthorizeOrRequest(t *testing.T) {
	now := time.Date(2026, 7, 13, 0, 0, 0, 0, time.UTC)
	registry := testRegistry()
	pol, err := policy.Parse([]byte(`{"rules":[
		{"id":"allow-read","effect":"allow","clients":["bob"],"operations":["repo.read"],"targets":[{"kind":"repo","name":"demo"}]},
		{"id":"request-write","effect":"request","clients":["bob"],"operations":["repo.write"],"targets":[{"kind":"repo","name":"demo"}],"grant_policy":{"mode":"window","default_minutes":5,"max_minutes":10,"request_ttl_minutes":5,"default_max_uses":1,"max_uses":2}}
	]}`), registry)
	if err != nil {
		t.Fatal(err)
	}
	database, err := state.Open(context.Background(), t.TempDir(), state.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	store := grants.NewDatabase(database, grants.Options{Now: func() time.Time { return now }, NewID: testIDSource()})
	coordinator, err := New(Options{Registry: registry, Decide: pol.Decide, Grants: store, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}

	read := policy.Request{Client: "bob", Operation: "repo.read", Target: policy.Target{Kind: "repo", Fields: map[string][]string{"name": {"demo"}}}}
	allowed, err := coordinator.Authorize(read, nil)
	if err != nil || !allowed.Decision.Allowed || allowed.Request.Grant.ID != "" {
		t.Fatalf("allow = %+v, %v", allowed, err)
	}

	write := policy.Request{Client: "bob", Operation: "repo.write", Target: read.Target}
	intent := testIntent(now, write)
	requested, err := coordinator.Authorize(write, fixedIntent(intent))
	if err != nil || !requested.Created || requested.Request.Grant.Status != grants.StatusPending {
		t.Fatalf("request = %+v, %v", requested, err)
	}
	replayed, err := coordinator.Authorize(write, fixedIntent(intent))
	if err != nil || replayed.Created || replayed.Request.Grant.ID != requested.Request.Grant.ID {
		t.Fatalf("replay = %+v, %v", replayed, err)
	}
}

func TestCoordinatorRejectsInvalidRequests(t *testing.T) {
	coordinator, closeStore := testCoordinator(t)
	missing := policy.Request{Client: "bob", Operation: "missing", Target: policy.Target{Kind: "repo", Fields: map[string][]string{"name": {"demo"}}}}
	if _, err := coordinator.Authorize(missing, nil); !errors.Is(err, ErrNoMatch) {
		t.Fatalf("missing operation error = %v", err)
	}
	unmatched := policy.Request{Client: "alice", Operation: "repo.write", Target: missing.Target}
	if _, err := coordinator.Authorize(unmatched, nil); !errors.Is(err, ErrNoMatch) {
		t.Fatalf("unmatched policy error = %v", err)
	}
	write := policy.Request{Client: "bob", Operation: "repo.write", Target: missing.Target}
	if _, err := coordinator.Authorize(write, nil); !errors.Is(err, ErrInvalidGrantIntent) {
		t.Fatalf("missing intent error = %v", err)
	}
	intent := testIntent(time.Now().UTC(), write)
	intent.Request.MaxUses = 3
	if _, err := coordinator.Authorize(write, fixedIntent(intent)); !errors.Is(err, ErrInvalidGrantIntent) {
		t.Fatalf("wide intent error = %v", err)
	}
	closeStore()
	if _, err := coordinator.Authorize(write, fixedIntent(intent)); err == nil {
		t.Fatal("closed grant store was accepted")
	}
}

func TestCoordinatorExplicitRequestIgnoresActiveGrant(t *testing.T) {
	coordinator, closeStore := testCoordinator(t)
	defer closeStore()
	request := policy.Request{Client: "bob", Operation: "repo.write", Target: policy.Target{Kind: "repo", Fields: map[string][]string{"name": {"demo"}}}}
	intent := testIntent(time.Now().UTC(), request)
	first, err := coordinator.RequestApproval(request, fixedIntent(intent))
	if err != nil || !first.Created {
		t.Fatalf("first request = %+v, %v", first, err)
	}
	if _, err := coordinator.grants.Approve(first.Request.Grant.ID, first.Request.DecisionToken, "operator"); err != nil {
		t.Fatal(err)
	}
	second, err := coordinator.RequestApproval(request, fixedIntent(intent))
	if err != nil || second.Created || second.Request.Grant.ID != first.Request.Grant.ID {
		t.Fatalf("second request = %+v, %v", second, err)
	}
}

func TestCoordinatorActiveGrantModeFiltersReusableAuthority(t *testing.T) {
	coordinator, closeStore := testCoordinator(t)
	defer closeStore()
	request := policy.Request{Client: "bob", Operation: "repo.write", Target: policy.Target{Kind: "repo", Fields: map[string][]string{"name": {"demo"}}}}
	create := func(requestID string, mode policy.GrantMode, maxUses int) grants.Grant {
		result, _, err := coordinator.grants.Request(grants.Request{Client: request.Client, ClientRequestID: requestID,
			Operation: request.Operation, Target: request.Target, Metadata: map[string]string{grants.MetadataMode: string(mode)},
			Reason: "test mode filtering", Duration: time.Minute, PendingTimeout: time.Minute, MaxUses: usebudget.Limit(maxUses)})
		if err != nil {
			t.Fatal(err)
		}
		approved, err := coordinator.grants.Approve(result.Grant.ID, result.DecisionToken, "operator")
		if err != nil {
			t.Fatal(err)
		}
		return approved
	}
	execution := create("execution-authority", policy.GrantModeExecution, 1)
	window := create("window-authority", policy.GrantModeWindow, 2)
	decision, found, err := coordinator.ActiveGrant(request)
	if err != nil || !found || decision.GrantID != execution.ID {
		t.Fatalf("ActiveGrant() = %+v, %v, %v", decision, found, err)
	}
	decision, found, err = coordinator.ActiveGrantMode(request, policy.GrantModeWindow)
	if err != nil || !found || decision.GrantID != window.ID {
		t.Fatalf("window ActiveGrantMode() = %+v, %v, %v", decision, found, err)
	}
	decision, found, err = coordinator.ActiveGrantMode(request, policy.GrantModeExecution)
	if err != nil || !found || decision.GrantID != execution.ID {
		t.Fatalf("execution ActiveGrantMode() = %+v, %v, %v", decision, found, err)
	}
}

func TestGrantBoundValidation(t *testing.T) {
	bounds := &policy.GrantPolicy{Mode: string(policy.GrantModeWindow), MaxMinutes: 10, RequestTTLMinutes: 5, MaxUses: 2}
	valid := testIntent(time.Now().UTC(), policy.Request{Client: "bob", Operation: "repo.write", Target: policy.Target{Kind: "repo"}})
	for name, mutate := range map[string]func(*GrantIntent){
		"duration": func(intent *GrantIntent) { intent.Request.Duration = 11 * time.Minute },
		"pending":  func(intent *GrantIntent) { intent.Request.PendingTimeout = 6 * time.Minute },
		"uses":     func(intent *GrantIntent) { intent.Request.MaxUses = 3 },
		"mode":     func(intent *GrantIntent) { intent.Mode = policy.GrantModeExecution },
	} {
		t.Run(name, func(t *testing.T) {
			intent := valid
			mutate(&intent)
			if err := validateGrantBounds(&intent, bounds); err == nil {
				t.Fatal("invalid bounds were accepted")
			}
		})
	}
	if err := validateGrantBounds(&valid, nil); err == nil {
		t.Fatal("missing bounds were accepted")
	}
	execution := valid
	execution.Mode = policy.GrantModeExecution
	execution.Request.MaxUses = 2
	executionBounds := *bounds
	executionBounds.Mode = string(policy.GrantModeExecution)
	if err := validateGrantBounds(&execution, &executionBounds); err == nil {
		t.Fatal("multi-use execution approval was accepted")
	}
}

func testCoordinator(t *testing.T) (*Coordinator, func()) {
	t.Helper()
	registry := testRegistry()
	pol, err := policy.Parse([]byte(`{"rules":[{"id":"request-write","effect":"request","clients":["bob"],"operations":["repo.write"],"targets":[{"kind":"repo","name":"demo"}],"grant_policy":{"mode":"window","default_minutes":5,"max_minutes":10,"request_ttl_minutes":5,"default_max_uses":1,"max_uses":2}}]}`), registry)
	if err != nil {
		t.Fatal(err)
	}
	database, err := state.Open(context.Background(), t.TempDir(), state.Options{})
	if err != nil {
		t.Fatal(err)
	}
	store := grants.NewDatabase(database, grants.Options{NewID: testIDSource()})
	coordinator, err := New(Options{Registry: registry, Decide: pol.Decide, Grants: store})
	if err != nil {
		t.Fatal(err)
	}
	return coordinator, func() { _ = database.Close() }
}

func testRegistry() policy.Registry {
	return policy.Registry{
		Operations: map[string]policy.OperationSpec{
			"repo.read": {TargetKinds: []string{"repo"}},
			"repo.write": {TargetKinds: []string{"repo"}, Grantable: true, GrantMode: policy.GrantModeWindow,
				GrantModes: []policy.GrantMode{policy.GrantModeWindow, policy.GrantModeExecution}, MaxGrantUses: 2},
		},
		Targets: map[string]policy.TargetSpec{"repo": {Fields: map[string]policy.FieldSpec{"name": {Required: true}}}},
	}
}

func testIntent(now time.Time, request policy.Request) GrantIntent {
	canonical := []byte(`{"operation":"repo.write"}`)
	digest := plandigest.Digest(canonical)
	return GrantIntent{Mode: policy.GrantModeWindow, Authorization: request, Request: grants.Request{
		Client: request.Client, ClientRequestID: "request-1", Operation: request.Operation,
		Target: request.Target, Attrs: request.Attrs, Metadata: map[string]string{"test_plan_digest": digest, grants.MetadataMode: string(policy.GrantModeWindow)},
		Reason: "test", Duration: 5 * time.Minute, PendingTimeout: 5 * time.Minute, MaxUses: 1,
	}, Plan: grants.ImmutablePlan{Digest: digest, SchemaName: "test/v1", Canonical: canonical, CreatedAt: now}}
}

func fixedIntent(intent GrantIntent) IntentBuilder {
	return func(policy.Decision) (GrantIntent, error) { return intent, nil }
}

func testIDSource() func(int) (string, error) {
	sequence := 0
	return func(int) (string, error) {
		sequence++
		return "id-" + string(rune('0'+sequence)), nil
	}
}
