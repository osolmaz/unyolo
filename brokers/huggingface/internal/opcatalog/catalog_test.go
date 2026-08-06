package opcatalog

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/osolmaz/unyolo/authorization/budget"
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
	if !ok || deleteRepo.DefaultAuthorizationMode != ModeWindow || !deleteRepo.AllowsAuthorizationMode(ModeExecution) ||
		!deleteRepo.ExplicitOnly || deleteRepo.MaxUses != int(usebudget.MaxFiniteUses) || deleteRepo.MCPTool == nil {
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
	bucketWrite, ok := ByName("bucket.object.write")
	if !ok || bucketWrite.MaxUses != int(usebudget.MaxFiniteUses) || bucketWrite.ApprovalTTLSeconds != 7*24*60*60 {
		t.Fatalf("bucket.object.write = %+v, %v", bucketWrite, ok)
	}
	for _, descriptor := range values {
		if descriptor.DefaultAuthorizationMode != ModeWindow || !descriptor.AllowsAuthorizationMode(ModeWindow) ||
			!descriptor.AllowsAuthorizationMode(ModeExecution) || descriptor.MaxUses != int(usebudget.MaxFiniteUses) ||
			descriptor.ApprovalTTLSeconds != 7*24*60*60 {
			t.Fatalf("universal reusable operation %s = %+v", descriptor.Name, descriptor)
		}
	}
}

func TestValidateRejectsCatalogDrift(t *testing.T) {
	values := MustAll()
	tests := map[string]func([]Descriptor){
		"duplicate":            func(items []Descriptor) { items[1] = items[0] },
		"missing name":         func(items []Descriptor) { items[0].Name = "" },
		"invalid default mode": func(items []Descriptor) { items[0].DefaultAuthorizationMode = "other" },
		"missing execution mode": func(items []Descriptor) {
			items[0].AuthorizationModes = []AuthorizationMode{ModeWindow}
		},
		"invalid status":   func(items []Descriptor) { items[0].Implementation = "other" },
		"missing risk":     func(items []Descriptor) { items[0].Risk = "" },
		"missing effect":   func(items []Descriptor) { items[0].DefaultPolicyEffect = "" },
		"missing target":   func(items []Descriptor) { items[0].TargetKind = "" },
		"missing executor": func(items []Descriptor) { find(items, "repo.create").ExecutorKind = "" },
		"invalid executor": func(items []Descriptor) { find(items, "repo.create").ExecutorKind = "shell" },
		"executor without implementation": func(items []Descriptor) {
			find(items, "auth.permission.check").ExecutorKind = "inline"
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
		"window uses":       func(items []Descriptor) { item := find(items, "repo.create"); item.MaxUses = 1 },
		"disposition drift": func(items []Descriptor) { item := find(items, "repo.delete"); item.ExplicitOnly = false },
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

func TestValidateExecutorBindingRejectsInvalidDispositions(t *testing.T) {
	t.Parallel()
	valid := *find(MustAll(), "bucket.object.write")
	cases := []Descriptor{
		{Name: "protocol", Implementation: StatusProtocol},
		{Name: "blocked", Implementation: StatusBlockedUpstream, ExecutorKind: "inline"},
		{Name: "bounded", Implementation: StatusImplemented, ExecutorKind: "bounded-stream", Disposition: "E",
			AuthorizationModes: []AuthorizationMode{ModeWindow, ModeExecution}},
		{Name: "unknown", Implementation: StatusImplemented, ExecutorKind: "shell"},
	}
	for _, descriptor := range cases {
		if err := validateExecutorBinding(descriptor); err == nil {
			t.Fatalf("validateExecutorBinding(%+v) succeeded", descriptor)
		}
	}
	if err := validateExecutorBinding(valid); err != nil {
		t.Fatalf("validateExecutorBinding(valid) error = %v", err)
	}
}

func TestImplementedOperationsHaveExplicitExecutorBindings(t *testing.T) {
	bound, native := 0, 0
	for _, value := range MustAll() {
		if value.Implementation != StatusImplemented {
			continue
		}
		switch value.ExecutorKind {
		case "inline", "credential", "bounded-stream":
			bound++
		case "native-protocol":
			native++
		default:
			t.Fatalf("%s executor = %q", value.Name, value.ExecutorKind)
		}
	}
	if bound != 149 || native != 7 {
		t.Fatalf("agent bound = %d, native = %d", bound, native)
	}
}

func TestCatalogHasNoUnresolvedProtocolPlaceholders(t *testing.T) {
	bound, native, blocked := 0, 0, 0
	for _, descriptor := range MustAll() {
		if descriptor.Implementation == StatusProtocol {
			t.Fatalf("%s retains an unresolved protocol placeholder", descriptor.Name)
		}
		if !descriptor.AgentFacing {
			continue
		}
		switch {
		case descriptor.Implementation == StatusBlockedUpstream && descriptor.ExecutorKind == "":
			blocked++
		case descriptor.Implementation == StatusImplemented && descriptor.ExecutorKind == "native-protocol":
			native++
		case descriptor.Implementation == StatusImplemented && descriptor.ExecutorKind != "":
			bound++
		default:
			t.Fatalf("agent-facing operation %s has unresolved binding: %+v", descriptor.Name, descriptor)
		}
	}
	if bound != 149 || native != 7 || blocked != 101 {
		t.Fatalf("catalog bindings = bound:%d native:%d blocked:%d", bound, native, blocked)
	}
}

func TestGitPushAppendUsesNativeProtocolBinding(t *testing.T) {
	descriptor, found := ByName("git.push.append")
	if !found || descriptor.Implementation != StatusImplemented || descriptor.ExecutorKind != "native-protocol" {
		t.Fatalf("git.push.append descriptor = %+v, found = %t", descriptor, found)
	}
}

func TestGitFetchUsesNativeProtocolBinding(t *testing.T) {
	descriptor, found := ByName("git.fetch")
	if !found || descriptor.Implementation != StatusImplemented || descriptor.ExecutorKind != "native-protocol" {
		t.Fatalf("git.fetch descriptor = %+v, found = %t", descriptor, found)
	}
	if descriptor.DefaultPolicyEffect != DefaultEffectRequest {
		t.Fatalf("git.fetch default policy effect = %q, want request", descriptor.DefaultPolicyEffect)
	}
}

func TestOpenAICompatibleInferenceUsesNativeProtocolBinding(t *testing.T) {
	for _, name := range []string{"inference.models.list", "inference.chat.complete"} {
		descriptor, found := ByName(name)
		if !found || descriptor.Implementation != StatusImplemented || descriptor.ExecutorKind != "native-protocol" {
			t.Fatalf("%s descriptor = %+v, found = %t", name, descriptor, found)
		}
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
