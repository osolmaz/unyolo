package operationruntime

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/osolmaz/brokerkit/agent/v1"
	"github.com/osolmaz/brokerkit/operation/capability"
)

type contractAdapter struct{ descriptor capability.Descriptor }

func (a contractAdapter) Descriptor() capability.Descriptor { return a.descriptor }
func (contractAdapter) Decode(target, arguments json.RawMessage) (json.RawMessage, error) {
	return append(append(json.RawMessage{}, target...), arguments...), nil
}
func (contractAdapter) Resolve(context.Context, json.RawMessage) (json.RawMessage, error) {
	return json.RawMessage(`{}`), nil
}
func (contractAdapter) Authorize(json.RawMessage) string { return "request" }
func (contractAdapter) Present(json.RawMessage) agentv1.Presentation {
	return agentv1.Presentation{Title: "test"}
}
func (contractAdapter) Execute(context.Context, json.RawMessage) (Outcome, error) {
	return Outcome{Proven: true, Result: json.RawMessage(`{"ok":true}`)}, nil
}
func (contractAdapter) Reconcile(context.Context, json.RawMessage) (Outcome, error) {
	return Outcome{Proven: true}, nil
}

func TestRegistryEnforcesProviderCatalogContract(t *testing.T) {
	descriptor := capability.Descriptor{Name: "repo.create", OperationRevision: 1, AuthorizationMode: capability.ModeExecution}
	lookup := func(name string) (capability.Descriptor, bool) { return descriptor, name == descriptor.Name }
	registry, err := NewRegistry(RegistryOptions{Provider: "test", Descriptor: lookup}, contractAdapter{descriptor: descriptor})
	if err != nil || len(registry.Names()) != 1 {
		t.Fatalf("registry = %#v, %v", registry, err)
	}
	if _, err := NewRegistry(RegistryOptions{Provider: "test", Descriptor: lookup}, contractAdapter{descriptor: descriptor}, contractAdapter{descriptor: descriptor}); err == nil {
		t.Fatal("duplicate adapter was accepted")
	}
	drifted := descriptor
	drifted.OperationRevision = 2
	if _, err := NewRegistry(RegistryOptions{Provider: "test", Descriptor: lookup}, contractAdapter{descriptor: drifted}); err == nil {
		t.Fatal("catalog drift was accepted")
	}
	implemented := descriptor
	implemented.Implementation = capability.StatusImplemented
	if err := registry.ValidateCoverage("test", []capability.Descriptor{implemented}); err != nil {
		t.Fatal(err)
	}
	missing := implemented
	missing.Name = "repo.delete"
	if err := registry.ValidateCoverage("test", []capability.Descriptor{missing}); err == nil || !strings.Contains(err.Error(), "repo.delete") {
		t.Fatalf("missing coverage error = %v", err)
	}
}

func TestPossiblePartialErrorContract(t *testing.T) {
	cause := errors.New("uncertain")
	err := &PossiblePartialError{Err: cause}
	if !IsPossiblePartial(err) || !errors.Is(err, cause) {
		t.Fatalf("partial error contract failed: %v", err)
	}
}

func TestStableRuntimeHelpers(t *testing.T) {
	if !EqualJSONObject([]byte(`{"n":1}`), []byte(`{"n":1}`)) || EqualJSONObject([]byte(`{"n":1}`), []byte(`{"n":2}`)) {
		t.Fatal("JSON equality drifted")
	}
	result := NormalizedResult("repo.create", nil)
	if !strings.Contains(string(result), `"reconciled":true`) {
		t.Fatalf("normalized result = %s", result)
	}
}
