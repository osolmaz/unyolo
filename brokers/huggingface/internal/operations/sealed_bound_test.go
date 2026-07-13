package operations

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/hubclient"
	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/sealedstore"
)

type sealedBoundFake struct {
	identity  string
	operation string
	target    json.RawMessage
	arguments json.RawMessage
}

func (f *sealedBoundFake) WhoAmI(context.Context) (hubclient.Identity, error) {
	return hubclient.Identity{Name: f.identity}, nil
}

func (f *sealedBoundFake) ExecuteBound(_ context.Context, operation string, target, arguments json.RawMessage) error {
	f.operation, f.target, f.arguments = operation, target, arguments
	return nil
}

func (f *sealedBoundFake) ObserveBound(context.Context, string, json.RawMessage) (json.RawMessage, bool, error) {
	return nil, false, nil
}

func TestSealedBoundAdapterKeepsSecretOutsidePlanAndConsumesOnce(t *testing.T) {
	store, _ := sealedstore.Open(t.TempDir())
	reference, err := store.Put("bob", "space.secret.set", []byte(`{"value":"canary-secret"}`), time.Now().Add(time.Hour))
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
	if err := adapter.(ClientBoundAdapter).ValidateClient(input, "bob"); err != nil {
		t.Fatal(err)
	}
	plan, err := adapter.Resolve(context.Background(), input)
	if err != nil || bytes.Contains(plan.Arguments, []byte("canary-secret")) || strings.Contains(plan.Presentation.Summary, "canary-secret") {
		t.Fatalf("Resolve() plan=%+v err=%v", plan, err)
	}
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
	reference, _ := store.Put("bob", "space.secret.set", []byte(`{"value":"secret"}`), time.Now().Add(time.Hour))
	adapters, _ := NewSealedBoundAdapters(&sealedBoundFake{identity: "operator"}, store)
	registry, _ := NewRegistry(adapters...)
	adapter, _ := registry.Lookup("space.secret.set")
	target := json.RawMessage(`{"namespace":"acme","repo":"demo"}`)
	publicSecret, _ := json.Marshal(sealedBoundArguments{Public: json.RawMessage(`{"key":"TOKEN","value":"leak"}`), SealedPayload: &reference})
	if _, err := adapter.Decode(target, publicSecret); err == nil {
		t.Fatal("secret in public arguments accepted")
	}
	arguments, _ := json.Marshal(sealedBoundArguments{Public: json.RawMessage(`{"key":"TOKEN"}`), SealedPayload: &reference})
	input, _ := adapter.Decode(target, arguments)
	if err := adapter.(ClientBoundAdapter).ValidateClient(input, "alice"); err == nil {
		t.Fatal("cross-client sealed reference accepted")
	}
	badReference, _ := store.Put("bob", "webhook.create", []byte(`{"secret":"secret"}`), time.Now().Add(time.Hour))
	wrongPurpose, _ := json.Marshal(sealedBoundArguments{Public: json.RawMessage(`{"key":"TOKEN"}`), SealedPayload: &badReference})
	input, _ = adapter.Decode(target, wrongPurpose)
	if err := adapter.(ClientBoundAdapter).ValidateClient(input, "bob"); err == nil {
		t.Fatal("cross-operation sealed reference accepted")
	}
}

func TestSealedBoundAdapterSupportsOutputSensitiveOperationWithoutInput(t *testing.T) {
	store, _ := sealedstore.Open(t.TempDir())
	client := &sealedBoundFake{identity: "operator"}
	adapters, _ := NewSealedBoundAdapters(client, store)
	registry, _ := NewRegistry(adapters...)
	adapter, _ := registry.Lookup("service_account.token.create")
	input, err := adapter.Decode(json.RawMessage(`{"name":"acme","serviceAccountId":"0123456789abcdef01234567"}`),
		json.RawMessage(`{"public":{"permissions":["repo.content.read"]}}`))
	if err != nil || adapter.(ClientBoundAdapter).ValidateClient(input, "bob") != nil {
		t.Fatalf("Decode() = %+v, %v", input, err)
	}
	plan, err := adapter.Resolve(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := adapter.Execute(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
}
