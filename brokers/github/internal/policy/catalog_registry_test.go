package policy

import (
	"testing"

	"github.com/osolmaz/brokerkit/brokers/github/internal/opcatalog"
	corepolicy "github.com/osolmaz/brokerkit/policy"
)

func TestGeneratedPolicyRegistryCoversCatalog(t *testing.T) {
	registry, err := CatalogRegistry()
	if err != nil {
		t.Fatal(err)
	}
	for _, descriptor := range opcatalog.MustAll() {
		spec, registered := registry.Operations[descriptor.Name]
		if !registered {
			t.Fatalf("catalog operation %q missing", descriptor.Name)
		}
		if spec.Grantable != descriptor.AgentFacing {
			t.Fatalf("operation %q grantable=%t, want %t", descriptor.Name, spec.Grantable, descriptor.AgentFacing)
		}
	}
	if len(registry.Operations) != opcatalog.ExpectedCount+len(protocolOperationSpecs()) {
		t.Fatalf("registry=%d catalog=%d", len(registry.Operations), opcatalog.ExpectedCount)
	}
	for _, forbidden := range []string{"method", "url", "body", "graphql", "caller", "headers", "credential"} {
		if _, found := registry.Attrs[forbidden]; found {
			t.Fatalf("unsafe policy attr %q", forbidden)
		}
	}
}

func TestGeneratedPolicyRegistryAcceptsCreatedResourceIdentity(t *testing.T) {
	registry, err := CatalogRegistry()
	if err != nil {
		t.Fatal(err)
	}
	request := corepolicy.Request{
		Client:    "bob",
		Operation: "organization.repos_create_in_org",
		Target: corepolicy.Target{Kind: "organization", Fields: map[string][]string{
			"name": {"osolmaz"},
		}},
		Attrs: map[string][]string{
			"resource_name":  {"brokerkit-next"},
			"resource_owner": {"osolmaz"},
		},
	}
	if err := registry.ValidateRequest(request); err != nil {
		t.Fatalf("created resource identity rejected: %v", err)
	}
}
