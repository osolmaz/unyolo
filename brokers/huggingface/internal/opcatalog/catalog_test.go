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
	if deleteRepo.DefaultPolicyEffect != DefaultEffectRequest {
		t.Fatalf("repo.delete default effect = %q", deleteRepo.DefaultPolicyEffect)
	}
	secret, ok := ByName("space.secret.set")
	if !ok || !secret.Sealed || secret.Risk != RiskCritical {
		t.Fatalf("space.secret.set = %+v, %v", secret, ok)
	}
	internal, ok := ByName("sandbox.port.proxy")
	if !ok || !internal.Internal || internal.AgentFacing || internal.MCPTool != nil {
		t.Fatalf("sandbox.port.proxy = %+v, %v", internal, ok)
	}
	if internal.DefaultPolicyEffect != DefaultEffectDeny {
		t.Fatalf("sandbox.port.proxy default effect = %q", internal.DefaultPolicyEffect)
	}
	read, ok := ByName("repo.contents.read")
	if !ok || read.DefaultPolicyEffect != DefaultEffectAllow {
		t.Fatalf("repo.contents.read = %+v, %v", read, ok)
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
		"missing effect":   func(items []Descriptor) { items[0].DefaultPolicyEffect = "" },
		"missing target":   func(items []Descriptor) { items[0].TargetKind = "" },
		"missing executor": func(items []Descriptor) { find(items, "repo.create").ExecutorKind = "" },
		"invalid executor": func(items []Descriptor) { find(items, "repo.create").ExecutorKind = "shell" },
		"executor without implementation": func(items []Descriptor) {
			find(items, "bucket.list").ExecutorKind = "inline"
		},
		"inline credential executor": func(items []Descriptor) {
			find(items, "service_account.token.create").ExecutorKind = "inline"
		},
		"credential executor without output": func(items []Descriptor) {
			find(items, "repo.create").ExecutorKind = "credential"
		},
		"native executor on execution operation": func(items []Descriptor) {
			find(items, "repo.create").ExecutorKind = "native-protocol"
		},
		"invalid ttl":       func(items []Descriptor) { items[0].RequestTTLSeconds = 0 },
		"family glob":       func(items []Descriptor) { item := find(items, "repo.delete"); item.FamilyGlobAllowed = true },
		"execution uses":    func(items []Descriptor) { item := find(items, "repo.create"); item.MaxUses = 2 },
		"sealed window":     func(items []Descriptor) { item := find(items, "space.secret.set"); item.AuthorizationMode = ModeWindow },
		"disposition drift": func(items []Descriptor) { item := find(items, "repo.delete"); item.ExplicitOnly = false },
		"sealed nonexecution": func(items []Descriptor) {
			item := find(items, "space.secret.set")
			item.AuthorizationMode = ModeWindow
			item.Disposition = strings.Replace(item.Disposition, "E", "W", 1)
		},
		"credential output kind": func(items []Descriptor) {
			item := find(items, "service_account.token.create")
			invalid := "INVALID"
			item.CredentialOutputKind = &invalid
		},
		"internal exposed": func(items []Descriptor) { item := find(items, "sandbox.port.proxy"); item.AgentFacing = true },
		"internal allowed": func(items []Descriptor) {
			item := find(items, "sandbox.port.proxy")
			item.DefaultPolicyEffect = DefaultEffectAllow
		},
		"critical allowed": func(items []Descriptor) {
			item := find(items, "repo.delete")
			item.DefaultPolicyEffect = DefaultEffectAllow
		},
		"missing MCP": func(items []Descriptor) { item := find(items, "repo.create"); item.MCPTool = nil },
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

func TestImplementedOperationsHaveExplicitExecutorBindings(t *testing.T) {
	bound, native := 0, 0
	for _, value := range MustAll() {
		if value.Implementation != StatusImplemented {
			continue
		}
		switch value.ExecutorKind {
		case "inline", "credential":
			bound++
		case "native-protocol":
			native++
		default:
			t.Fatalf("%s executor = %q", value.Name, value.ExecutorKind)
		}
	}
	if bound != 144 || native != 3 {
		t.Fatalf("agent bound = %d, native = %d", bound, native)
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
