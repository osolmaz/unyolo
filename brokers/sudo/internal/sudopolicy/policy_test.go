package sudopolicy

import (
	"fmt"
	"os"
	"runtime"
	"testing"

	corepolicy "github.com/osolmaz/unyolo/authorization/policy"
	"github.com/osolmaz/unyolo/brokers/sudo/internal/catalog"
)

func TestShippedPoliciesRespectOperationBounds(t *testing.T) {
	t.Parallel()
	if runtime.GOOS != "linux" {
		t.Skip("the shipped sudo catalog targets Linux systemd")
	}
	catalogData, err := os.ReadFile("../../deployment/files/sudo/catalog.json")
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := catalog.Parse(catalogData)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"../../deployment/files/sudo/policy.json", "../../policy.example.json"} {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := corepolicy.Parse(data, Registry(snapshot)); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
	}
}

func TestRegistryAndRequest(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	snapshot, err := catalog.Parse([]byte(fmt.Sprintf(`{"version":1,"commands":[{
		"id":"scale","executable":"/usr/bin/printf","arguments":[{"slot":"replicas","type":"integer","minimum":1,"maximum":4}],
		"target_users":["root"],"working_directory":%q,"timeout_seconds":5,"max_output_bytes":100}]}`, directory)))
	if err != nil {
		t.Fatal(err)
	}
	policy, err := corepolicy.Parse([]byte(`{"rules":[{
		"id":"bob-scale","effect":"request","clients":["bob"],"operations":["exec.command"],
		"targets":[{"kind":"user","name":"root"}],"attrs":{"command_id":["scale"],"argument.replicas":["2"]},
		"grant_policy":{"mode":"execution","default_minutes":1,"max_minutes":5,"request_ttl_minutes":1,"default_max_uses":1,"max_uses":1}
	}]}`), Registry(snapshot))
	if err != nil {
		t.Fatal(err)
	}
	request := Request("bob", catalog.Resolved{CommandID: "scale", TargetUser: "root", SlotValues: map[string]string{"replicas": "2"}})
	decision := policy.Decide(request, corepolicy.DecisionOptions{ForGrantRequest: true})
	if decision.Effect != corepolicy.EffectRequest || decision.GrantPolicy == nil {
		t.Fatalf("decision = %+v", decision)
	}
	request.Attrs[ArgumentPrefix+"unknown"] = []string{"value"}
	if decision := policy.Decide(request, corepolicy.DecisionOptions{}); decision.Effect != corepolicy.EffectNoMatch {
		t.Fatalf("unknown attr decision = %+v", decision)
	}
}
