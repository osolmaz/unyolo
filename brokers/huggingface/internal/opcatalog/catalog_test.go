package opcatalog

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestCatalogIsCompleteAndSecurityMetadataIsCoherent(t *testing.T) {
	values, err := All()
	if err != nil {
		t.Fatal(err)
	}
	if len(values) != ExpectedCount || values[0].Name != "auth.permission.check" || values[len(values)-1].Name != "webhook.update" {
		t.Fatalf("catalog bounds = %d, %q, %q", len(values), values[0].Name, values[len(values)-1].Name)
	}
	deleteRepo, ok := ByName("repo.delete")
	if !ok || deleteRepo.AuthorizationMode != ModeExecution || !deleteRepo.ExplicitOnly || deleteRepo.MaxUses != 1 || deleteRepo.MCPTool == nil {
		t.Fatalf("repo.delete = %+v, %v", deleteRepo, ok)
	}
	secret, ok := ByName("space.secret.set")
	if !ok || !secret.Sealed || secret.Risk != RiskCritical {
		t.Fatalf("space.secret.set = %+v, %v", secret, ok)
	}
	internal, ok := ByName("sandbox.port.proxy")
	if !ok || !internal.Internal || internal.AgentFacing || internal.MCPTool != nil {
		t.Fatalf("sandbox.port.proxy = %+v, %v", internal, ok)
	}
}

func TestValidateRejectsCatalogDrift(t *testing.T) {
	values := MustAll()
	tests := map[string]func([]Descriptor){
		"duplicate":        func(items []Descriptor) { items[1] = items[0] },
		"missing name":     func(items []Descriptor) { items[0].Name = "" },
		"invalid mode":     func(items []Descriptor) { items[0].AuthorizationMode = "other" },
		"invalid status":   func(items []Descriptor) { items[0].Implementation = "other" },
		"missing risk":     func(items []Descriptor) { items[0].Risk = "" },
		"missing target":   func(items []Descriptor) { items[0].TargetKind = "" },
		"invalid ttl":      func(items []Descriptor) { items[0].RequestTTLSeconds = 0 },
		"family glob":      func(items []Descriptor) { item := find(items, "repo.delete"); item.FamilyGlobAllowed = true },
		"execution uses":   func(items []Descriptor) { item := find(items, "repo.create"); item.MaxUses = 2 },
		"sealed window":    func(items []Descriptor) { item := find(items, "space.secret.set"); item.AuthorizationMode = ModeWindow },
		"internal exposed": func(items []Descriptor) { item := find(items, "sandbox.port.proxy"); item.AgentFacing = true },
		"missing MCP":      func(items []Descriptor) { item := find(items, "repo.create"); item.MCPTool = nil },
		"duplicate CLI": func(items []Descriptor) {
			item := find(items, "repo.delete")
			other := find(items, "repo.create")
			item.CLICommand = other.CLICommand
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			copy := append([]Descriptor(nil), values...)
			mutate(copy)
			if err := Validate(copy); err == nil {
				t.Fatal("Validate() accepted drift")
			}
		})
	}
}

func TestCatalogLookupMissesUnknownOperation(t *testing.T) {
	if _, found := ByName("http.request"); found {
		t.Fatal("unknown operation found")
	}
}

func TestEmbeddedCatalogUsesClosedDescriptorShape(t *testing.T) {
	decoder := json.NewDecoder(strings.NewReader(string(catalogJSON)))
	decoder.DisallowUnknownFields()
	var values []Descriptor
	if err := decoder.Decode(&values); err != nil {
		t.Fatal(err)
	}
}

func TestGeneratedCapabilityReferenceMatchesCatalog(t *testing.T) {
	generated, err := os.ReadFile("../../docs/generated/capabilities.json")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(bytes.TrimSpace(generated), bytes.TrimSpace(catalogJSON)) {
		t.Fatal("generated capability reference is stale")
	}
}

func find(values []Descriptor, name string) *Descriptor {
	for index := range values {
		if values[index].Name == name {
			return &values[index]
		}
	}
	panic(name)
}
