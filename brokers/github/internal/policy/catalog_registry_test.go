package policy

import (
	"testing"

	"github.com/osolmaz/brokerkit/brokers/github/internal/opcatalog"
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
