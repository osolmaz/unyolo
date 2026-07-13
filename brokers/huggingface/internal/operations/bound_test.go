package operations

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/hubclient"
)

type boundFake struct {
	identity  string
	observed  json.RawMessage
	absent    bool
	executed  string
	arguments json.RawMessage
}

func (f *boundFake) WhoAmI(context.Context) (hubclient.Identity, error) {
	return hubclient.Identity{Name: f.identity}, nil
}

func (f *boundFake) ExecuteBound(_ context.Context, operation string, _ json.RawMessage, arguments json.RawMessage) error {
	f.executed = operation
	f.arguments = arguments
	return nil
}

func (f *boundFake) ObserveBound(context.Context, string, json.RawMessage) (json.RawMessage, bool, error) {
	return f.observed, f.absent, nil
}

func TestBoundAdapterLifecycle(t *testing.T) {
	client := &boundFake{identity: "operator"}
	adapters, err := NewBoundAdapters(client)
	if err != nil {
		t.Fatal(err)
	}
	registry, err := NewRegistry(adapters...)
	if err != nil {
		t.Fatal(err)
	}
	adapter, found := registry.Lookup("webhook.enable")
	if !found {
		t.Fatal("webhook.enable is not registered")
	}
	input, err := adapter.Decode(json.RawMessage(`{"webhookId":"hook-1"}`), json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	plan, err := adapter.Resolve(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	if request := adapter.Authorize(Plan{Target: plan.Target, Arguments: plan.Arguments, Preconditions: plan.Preconditions}); request.Operation != "webhook.enable" {
		t.Fatalf("Authorize() = %+v", request)
	}
	if presentation := adapter.Present(Plan{Target: plan.Target, Arguments: plan.Arguments, Preconditions: plan.Preconditions}); presentation.Title == "" {
		t.Fatal("Present() returned an empty title")
	}
	outcome, err := adapter.Execute(context.Background(), plan)
	if err != nil || !outcome.Proven || client.executed != "webhook.enable" {
		t.Fatalf("Execute() = %+v, %v; operation=%q", outcome, err, client.executed)
	}
	if outcome, err = adapter.Reconcile(context.Background(), plan); err != nil || outcome.Proven {
		t.Fatalf("Reconcile() = %+v, %v", outcome, err)
	}
	client.identity = "different"
	if _, err = adapter.Execute(context.Background(), plan); err == nil || err.Error() != "operation_precondition_failed" {
		t.Fatalf("stale identity error = %v", err)
	}
}

func TestBoundAdapterObservedLifecycle(t *testing.T) {
	client := &boundFake{identity: "operator", observed: json.RawMessage(`{"enabled":true}`)}
	adapters, err := NewBoundAdapters(client)
	if err != nil {
		t.Fatal(err)
	}
	registry, err := NewRegistry(adapters...)
	if err != nil {
		t.Fatal(err)
	}
	adapter, found := registry.Lookup("collection.delete")
	if !found {
		t.Fatal("collection.delete is not registered")
	}
	input, err := adapter.Decode(json.RawMessage(`{"namespace":"acme","slug":"review","id":"123"}`), json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	plan, err := adapter.Resolve(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = adapter.Execute(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	client.absent = true
	outcome, err := adapter.Reconcile(context.Background(), plan)
	if err != nil || !outcome.Proven {
		t.Fatalf("Reconcile() = %+v, %v", outcome, err)
	}
}

func TestBoundAdapterReconcileRequiresRequestedState(t *testing.T) {
	client := &boundFake{identity: "operator", observed: json.RawMessage(`{"labels":{"stage":"old"}}`)}
	adapters, err := NewBoundAdapters(client)
	if err != nil {
		t.Fatal(err)
	}
	registry, err := NewRegistry(adapters...)
	if err != nil {
		t.Fatal(err)
	}
	adapter, found := registry.Lookup("job.labels.update")
	if !found {
		t.Fatal("job.labels.update is not registered")
	}
	input, err := adapter.Decode(json.RawMessage(`{"namespace":"acme","jobId":"job-1"}`), json.RawMessage(`{"labels":{"stage":"prod"}}`))
	if err != nil {
		t.Fatal(err)
	}
	plan, err := adapter.Resolve(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	if outcome, reconcileErr := adapter.Reconcile(context.Background(), plan); reconcileErr != nil || outcome.Proven {
		t.Fatalf("mismatched state reconciled = %+v, %v", outcome, reconcileErr)
	}
	client.observed = json.RawMessage(`{"id":"job-1","labels":{"stage":"prod"},"status":"RUNNING"}`)
	if outcome, reconcileErr := adapter.Reconcile(context.Background(), plan); reconcileErr != nil || !outcome.Proven {
		t.Fatalf("matching state did not reconcile = %+v, %v", outcome, reconcileErr)
	}
}

func TestBoundPolicyIdentityIncludesEverySubresourceIdentifier(t *testing.T) {
	owner, name := policyIdentity(map[string]any{"name": "acme", "username": "bob"}, "operator", "organization")
	if owner != "acme" || name != "name=acme&username=bob" {
		t.Fatalf("member identity = %q/%q", owner, name)
	}
	_, other := policyIdentity(map[string]any{"name": "acme", "username": "alice"}, "operator", "organization")
	if other == name || !strings.Contains(other, "username=alice") {
		t.Fatalf("distinct member identity collapsed to %q", other)
	}
	repoOwner, repoName := policyIdentity(map[string]any{"owner": "acme", "repo": "data"}, "operator", "repo")
	if repoOwner != "acme" || repoName != "data" {
		t.Fatalf("repository identity = %q/%q", repoOwner, repoName)
	}
	fallbackOwner, fallbackName := policyIdentity(map[string]any{"sequence": float64(7)}, "operator", "resource")
	if fallbackOwner != "operator" || fallbackName != "sequence=7" {
		t.Fatalf("fallback identity = %q/%q", fallbackOwner, fallbackName)
	}
	emptyOwner, emptyName := policyIdentity(map[string]any{}, "operator", "resource")
	if emptyOwner != "operator" || emptyName != "resource" {
		t.Fatalf("empty identity = %q/%q", emptyOwner, emptyName)
	}
}

func TestBoundAdaptersExcludeSpecializedOperations(t *testing.T) {
	client := &boundFake{identity: "operator"}
	bound, err := NewBoundAdapters(client)
	if err != nil {
		t.Fatal(err)
	}
	specialized := map[string]bool{}
	for _, operation := range []string{
		"repo.create", "repo.delete", "repo.gating.update", "repo.move", "repo.visibility.update",
		"repo.branch.create", "repo.branch.delete", "repo.tag.create", "repo.tag.delete",
		"space.dev_mode.disable", "space.dev_mode.enable", "space.hardware.update", "space.pause", "space.restart", "space.sleep_time.update", "space.variable.delete", "space.variable.set",
		"bucket.batch.apply", "bucket.move", "bucket.object.delete", "bucket.sync.apply",
		"repo.commit.create", "repo.file.copy", "repo.file.delete", "repo.file.upload", "space.hot_reload.apply",
	} {
		specialized[operation] = true
	}
	for _, adapter := range bound {
		if specialized[adapter.Descriptor().Name] {
			t.Fatalf("generic bound adapter duplicates specialized operation %q", adapter.Descriptor().Name)
		}
	}
}
