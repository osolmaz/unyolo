package policy

import (
	"testing"

	"github.com/osolmaz/brokerkit/brokers/github/internal/opcatalog"
	corepolicy "github.com/osolmaz/brokerkit/policy"
)

func TestGeneratedPolicyRegistryCoversAgentCatalog(t *testing.T) {
	registry, err := CatalogRegistry()
	if err != nil {
		t.Fatal(err)
	}
	agentCount := 0
	for _, descriptor := range opcatalog.MustAll() {
		_, registered := registry.Operations[descriptor.Name]
		if descriptor.AgentFacing {
			agentCount++
			if !registered {
				t.Fatalf("agent operation %q missing", descriptor.Name)
			}
		} else if registered {
			t.Fatalf("non-agent operation %q registered", descriptor.Name)
		}
	}
	if len(registry.Operations) != agentCount+len(protocolOperationSpecs()) || len(registry.Operations) > 1420 {
		t.Fatalf("registry=%d agent=%d", len(registry.Operations), agentCount)
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
