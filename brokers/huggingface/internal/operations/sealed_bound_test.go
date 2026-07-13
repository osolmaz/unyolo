package operations

import (
	"bytes"
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/hubclient"
	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/opcatalog"
	"github.com/osolmaz/brokerkit/sealedstore"
)

type sealedBoundFake struct {
	identity  string
	operation string
	target    json.RawMessage
	arguments json.RawMessage
	observed  json.RawMessage
	absent    bool
}

func (f *sealedBoundFake) WhoAmI(context.Context) (hubclient.Identity, error) {
	return hubclient.Identity{Name: f.identity}, nil
}

func (f *sealedBoundFake) ExecuteBound(_ context.Context, operation string, target, arguments json.RawMessage) error {
	f.operation, f.target, f.arguments = operation, target, arguments
	return nil
}

func (f *sealedBoundFake) ObserveBound(context.Context, string, json.RawMessage) (json.RawMessage, bool, error) {
	return f.observed, f.absent, nil
}

func TestSealedBoundAdapterKeepsSecretOutsidePlanAndConsumesOnce(t *testing.T) {
	store, _ := sealedstore.Open(t.TempDir())
	reference, err := store.PutForRequest("bob", "space.secret.set", "secret-request", []byte(`{"value":"canary-secret"}`), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	client := &sealedBoundFake{identity: "operator"}
	adapters, err := NewSealedBoundAdapters(client, store)
	if err != nil {
		t.Fatal(err)
	}
	registry, _ := NewRegistry(adapters...)
	adapter, _ := registry.Lookup("space.secret.set")
	argumentJSON, _ := json.Marshal(sealedBoundArguments{Public: json.RawMessage(`{"key":"TOKEN"}`), SealedPayload: &reference})
	input, err := adapter.Decode(json.RawMessage(`{"namespace":"acme","repo":"demo"}`), argumentJSON)
	if err != nil {
		t.Fatal(err)
	}
	if err := adapter.(ClientBoundAdapter).ValidateClient(input, "bob", "secret-request"); err != nil {
		t.Fatal(err)
	}
	plan, err := adapter.Resolve(context.Background(), input)
	if err != nil || bytes.Contains(plan.Arguments, []byte("canary-secret")) || strings.Contains(plan.Presentation.Summary, "canary-secret") {
		t.Fatalf("Resolve() plan=%+v err=%v", plan, err)
	}
	assertPlanReconstruction(t, adapter, plan)
	outcome, err := adapter.Execute(context.Background(), plan)
	if err != nil || !outcome.Proven || client.operation != "space.secret.set" || !bytes.Contains(client.arguments, []byte("canary-secret")) {
		t.Fatalf("Execute() = %+v, %v; arguments=%s", outcome, err, client.arguments)
	}
	if _, err := store.Get(reference); err == nil {
		t.Fatal("sealed payload remained after execution")
	}
}

func TestSealedBoundAdapterRejectsOwnershipLeaksAndSecretSmuggling(t *testing.T) {
	store, _ := sealedstore.Open(t.TempDir())
	reference, _ := store.PutForRequest("bob", "space.secret.set", "secret-request", []byte(`{"value":"secret"}`), time.Now().Add(time.Hour))
	adapters, _ := NewSealedBoundAdapters(&sealedBoundFake{identity: "operator"}, store)
	registry, _ := NewRegistry(adapters...)
	adapter, _ := registry.Lookup("space.secret.set")
	target := json.RawMessage(`{"namespace":"acme","repo":"demo"}`)
	missingSecret, _ := json.Marshal(sealedBoundArguments{Public: json.RawMessage(`{"key":"TOKEN"}`)})
	if _, err := adapter.Decode(target, missingSecret); err == nil {
		t.Fatal("mandatory sealed payload was omitted")
	}
	publicSecret, _ := json.Marshal(sealedBoundArguments{Public: json.RawMessage(`{"key":"TOKEN","value":"leak"}`), SealedPayload: &reference})
	if _, err := adapter.Decode(target, publicSecret); err == nil {
		t.Fatal("secret in public arguments accepted")
	}
	arguments, _ := json.Marshal(sealedBoundArguments{Public: json.RawMessage(`{"key":"TOKEN"}`), SealedPayload: &reference})
	if _, err := adapter.Decode(json.RawMessage(`{}`), arguments); err == nil {
		t.Fatal("invalid sealed operation target was accepted")
	}
	input, _ := adapter.Decode(target, arguments)
	if err := adapter.(ClientBoundAdapter).ValidateClient(input, "alice", "secret-request"); err == nil {
		t.Fatal("cross-client sealed reference accepted")
	}
	if err := adapter.(ClientBoundAdapter).ValidateClient(input, "bob", "other-request"); err == nil {
		t.Fatal("cross-request sealed reference accepted")
	}
	badReference, _ := store.PutForRequest("bob", "webhook.create", "secret-request", []byte(`{"secret":"secret"}`), time.Now().Add(time.Hour))
	wrongPurpose, _ := json.Marshal(sealedBoundArguments{Public: json.RawMessage(`{"key":"TOKEN"}`), SealedPayload: &badReference})
	input, _ = adapter.Decode(target, wrongPurpose)
	if err := adapter.(ClientBoundAdapter).ValidateClient(input, "bob", "secret-request"); err == nil {
		t.Fatal("cross-operation sealed reference accepted")
	}
}

func TestSealedBoundAdapterRejectsMissingRequiredSealedInput(t *testing.T) {
	store, _ := sealedstore.Open(t.TempDir())
	adapters, err := NewSealedBoundAdapters(&sealedBoundFake{identity: "operator"}, store)
	if err != nil {
		t.Fatal(err)
	}
	registry, _ := NewRegistry(adapters...)
	adapter, found := registry.Lookup("organization.member.token.revoke")
	if !found {
		t.Fatal("organization.member.token.revoke adapter is missing")
	}
	input, err := adapter.Decode(json.RawMessage(`{"name":"acme"}`), json.RawMessage(`{"public":{}}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := adapter.Resolve(t.Context(), input); err == nil {
		t.Fatal("required sealed token was omitted")
	}
}

func TestSealedBoundAdapterDoesNotReconcileSecretStateFromPublicArguments(t *testing.T) {
	store, _ := sealedstore.Open(t.TempDir())
	reference, _ := store.PutForRequest("bob", "space.secret.set", "secret-request", []byte(`{"value":"secret"}`), time.Now().Add(time.Hour))
	client := &sealedBoundFake{identity: "operator", observed: json.RawMessage(`{"key":"TOKEN"}`)}
	adapters, _ := NewSealedBoundAdapters(client, store)
	registry, _ := NewRegistry(adapters...)
	adapter, _ := registry.Lookup("space.secret.set")
	arguments, _ := json.Marshal(sealedBoundArguments{Public: json.RawMessage(`{"key":"TOKEN"}`), SealedPayload: &reference})
	input, _ := adapter.Decode(json.RawMessage(`{"namespace":"acme","repo":"demo"}`), arguments)
	plan, err := adapter.Resolve(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	outcome, err := adapter.Reconcile(context.Background(), plan)
	if err != nil || outcome.Proven {
		t.Fatalf("Reconcile() = %+v, %v; want unproven secret state", outcome, err)
	}
}

func TestSealedBoundAdapterLeavesCredentialOutputsToDedicatedAdapter(t *testing.T) {
	store, _ := sealedstore.Open(t.TempDir())
	client := &sealedBoundFake{identity: "operator"}
	adapters, _ := NewSealedBoundAdapters(client, store)
	registry, _ := NewRegistry(adapters...)
	if _, found := registry.Lookup("service_account.token.create"); found {
		t.Fatal("credential output operation used generic sealed adapter")
	}
}

func TestSecretBearingAdministrativeOperationsUseSealedInput(t *testing.T) {
	tests := map[string][]string{
		"organization.member.token.revoke": {"token"},
		"provisioning.account.request":     {"confirmation_secret"},
		"repo.duplicate":                   {"secrets"},
	}
	for operation, paths := range tests {
		descriptor, found := opcatalog.ByName(operation)
		if !found || !descriptor.Sealed || descriptor.AuthorizationMode != opcatalog.ModeExecution {
			t.Fatalf("%s descriptor = %+v, %v", operation, descriptor, found)
		}
		if got := SealedInputPaths(operation); !reflect.DeepEqual(got, paths) {
			t.Fatalf("SealedInputPaths(%s) = %v, want %v", operation, got, paths)
		}
	}
}
