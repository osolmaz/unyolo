package operations

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/hubclient"
	"github.com/osolmaz/brokerkit/internal/storage/sealed"
)

func TestOperationLifecycleHelpers(t *testing.T) {
	if got := policyRepoType(map[string]any{"repoType": "datasets"}); got != "dataset" {
		t.Fatalf("policyRepoType() = %q", got)
	}
	var response map[string]any
	if err := decodeResponse([]byte(`{"result":true} trailing`), &response); err == nil {
		t.Fatal("trailing response JSON accepted")
	}
	if host := firstRunningSandboxHost([]hubclient.SandboxState{{Stage: "SCHEDULING"}, {Stage: "RUNNING"}}); host == nil || host.Stage != "RUNNING" {
		t.Fatalf("firstRunningSandboxHost() = %+v", host)
	}
	if host := firstRunningSandboxHost(nil); host != nil {
		t.Fatalf("empty pool host = %+v", host)
	}
	if merged, err := mergeSandboxEnvironment(map[string]string{"MODE": "test"}, map[string]string{"TOKEN": "secret"}); err != nil || len(merged) != 2 {
		t.Fatalf("mergeSandboxEnvironment() = %+v, %v", merged, err)
	}
	if _, err := mergeSandboxEnvironment(map[string]string{"MODE": "test"}, map[string]string{"MODE": "secret"}); err == nil {
		t.Fatal("overlapping sandbox environment accepted")
	}
	if _, err := sandboxConfigFromStates(nil); err == nil {
		t.Fatal("empty sandbox pool accepted")
	}
	if _, err := sandboxConfigFromStates([]hubclient.SandboxState{{Image: "a", Flavor: "cpu-basic", Capacity: 1, MaxHosts: 2}, {Image: "b", Flavor: "cpu-basic", Capacity: 1, MaxHosts: 2}}); err == nil {
		t.Fatal("inconsistent sandbox pool accepted")
	}
	for _, stage := range []string{"COMPLETED", "CANCELED", "ERROR", "DELETED"} {
		if !terminalSandboxStage(stage) {
			t.Fatalf("terminal stage %q rejected", stage)
		}
	}
	if terminalSandboxStage("RUNNING") {
		t.Fatal("running sandbox classified terminal")
	}
	notFound := &hubclient.Error{Code: hubclient.CodeNotFound}
	if nonNotFound(notFound) != nil || nonNotFound(errors.New("failure")) == nil {
		t.Fatal("nonNotFound classification mismatch")
	}
}

func TestCleanupAndReconciliationHelpers(t *testing.T) {
	store, err := sealedstore.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	reference, err := store.Put("bob", "space.secret.set", []byte(`{"value":"secret"}`), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	client := &sealedBoundFake{identity: "operator", observed: json.RawMessage(`{"key":"OTHER"}`)}
	adapters, err := NewSealedBoundAdapters(client, store)
	if err != nil {
		t.Fatal(err)
	}
	registry, _ := NewRegistry(adapters...)
	adapter, _ := registry.Lookup("space.secret.set")
	arguments, _ := json.Marshal(sealedBoundArguments{Public: json.RawMessage(`{"key":"TOKEN"}`), SealedPayload: &reference})
	input, err := adapter.Decode(json.RawMessage(`{"namespace":"acme","repo":"demo"}`), arguments)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := adapter.Resolve(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	if outcome, err := adapter.Reconcile(context.Background(), plan); err != nil || outcome.Proven {
		t.Fatalf("mismatched sealed Reconcile() = %+v, %v", outcome, err)
	}
	client.observed = json.RawMessage(`{"key":"TOKEN"}`)
	if outcome, err := adapter.Reconcile(context.Background(), plan); err != nil || outcome.Proven {
		t.Fatalf("secret-only sealed Reconcile() = %+v, %v", outcome, err)
	}
	if err := adapter.(PlanCleaner).Cleanup(plan); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Get(reference); err == nil {
		t.Fatal("cleanup retained sealed payload")
	}
	content := &repositoryContentAdapter{}
	if outcome, err := content.Reconcile(context.Background(), Plan{}); err != nil || outcome.Proven {
		t.Fatalf("content Reconcile() = %+v, %v", outcome, err)
	}
}

func TestCredentialExtractionAndSealedObjectHelpers(t *testing.T) {
	secret, metadata, err := extractCredentialOutput("provisioning.resource.credentials.rotate", json.RawMessage(`{"status":"complete","id":"resource-1","complete":{"access_configuration":{"token":"secret","endpoint":"https://example.test"}}}`))
	if err != nil || !json.Valid(secret) || metadata["resource_id"] != "resource-1" {
		t.Fatalf("provisioning credential = %s, %+v, %v", secret, metadata, err)
	}
	for _, raw := range []json.RawMessage{
		json.RawMessage(`{"status":"pending","id":"resource-1","complete":{"access_configuration":{}}}`),
		json.RawMessage(`{"token":"","tokenInfo":{"_id":"id","displayName":"name","createdAt":"now"}}`),
	} {
		if _, _, err := extractCredentialOutput("service_account.token.rotate", raw); err == nil {
			t.Fatalf("invalid credential output accepted: %s", raw)
		}
	}
	destination := map[string]any{"nested": map[string]any{"public": "value"}}
	if err := mergeObjects(destination, map[string]any{"nested": map[string]any{"secret": "value"}}); err != nil {
		t.Fatal(err)
	}
	if err := mergeObjects(destination, map[string]any{"nested": "overlap"}); err == nil {
		t.Fatal("scalar sealed overlap accepted")
	}
	if !onlySecretPaths(map[string]any{"model": map[string]any{"secrets": map[string]any{"TOKEN": "secret"}}}, []string{"model.secrets"}, "") {
		t.Fatal("nested sealed path rejected")
	}
	if onlySecretPaths(map[string]any{"public": "value"}, []string{"model.secrets"}, "") {
		t.Fatal("unapproved sealed path accepted")
	}
}
