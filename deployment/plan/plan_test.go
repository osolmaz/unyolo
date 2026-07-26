package plan

import (
	"crypto/sha256"
	"fmt"
	"testing"

	"github.com/osolmaz/brokerkit/deployment/api"
	"github.com/osolmaz/brokerkit/deployment/profile"
	"github.com/osolmaz/brokerkit/internal/host/bundle"
)

func TestBuildIsStableAndOrdersDependencies(t *testing.T) {
	snapshot := profile.Snapshot{
		Deployment: profile.Deployment{Name: "host"}, Digest: testDigest("pack"),
		Manifest: bundle.Manifest{BundleID: "bundle"},
	}
	responses := []api.Response{{
		APIVersion: api.APIVersion, ComponentID: "github", Status: "planned", PlanDigest: testDigest("component"),
		Actions: []api.PlannedAction{
			{ID: "service", Type: "start", Risk: "medium", Resource: api.Resource{Kind: "service", ID: "gh-broker"}, DependsOn: []string{"policy"}},
			{ID: "policy", Type: "replace", Risk: "medium", Resource: api.Resource{Kind: "file", ID: "policy", Path: "/etc/gh-broker/scope.json"}},
		},
	}}
	first, err := Build(snapshot, testDigest("observed"), responses, "bundle")
	if err != nil {
		t.Fatal(err)
	}
	second, err := Build(snapshot, testDigest("observed"), responses, "bundle")
	if err != nil {
		t.Fatal(err)
	}
	if first.Digest != second.Digest || first.Actions[0].ID != "github.policy" || first.Kind != KindReconcile {
		t.Fatalf("unexpected plans: %#v %#v", first, second)
	}
	if err := first.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
}

func testDigest(value string) string { return fmt.Sprintf("sha256:%x", sha256.Sum256([]byte(value))) }
