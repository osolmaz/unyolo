package policy

import (
	"testing"

	corepolicy "github.com/osolmaz/brokerkit/authorization/policy"
	"github.com/osolmaz/brokerkit/brokers/github/internal/opcatalog"
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

func TestOperationAndAuthorizationWrappers(t *testing.T) {
	if !IsOperation(string(OperationGitFetch)) || !IsOperation("organization.repos_create_in_org") || IsOperation("not.an.operation") {
		t.Fatal("operation classification drifted")
	}
	if operations := familyOperations("git.push."); len(operations) == 0 {
		t.Fatal("Git push family did not expand")
	}
	var unavailable *Policy
	if decision := unavailable.DecideAuthorization(corepolicy.Request{}, corepolicy.DecisionOptions{}); decision.Effect != corepolicy.EffectNoMatch {
		t.Fatalf("nil policy decision = %q", decision.Effect)
	}
	policy, err := New(Scope{Rules: []Rule{{
		ID: "allow-fetch", Effect: EffectAllow, Clients: []string{"agent-a"},
		Operations: []Operation{OperationGitFetch}, Targets: []Target{{Kind: "repo", Owner: "example", Name: "repo"}},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	request := AuthorizationRequest("agent-a", string(OperationGitFetch), "repo", map[string][]string{"owner": {"example"}, "name": {"repo"}}, nil)
	if decision := policy.DecideAuthorization(request, corepolicy.DecisionOptions{}); decision.Effect != corepolicy.EffectAllow {
		t.Fatalf("authorization decision = %q", decision.Effect)
	}
}
