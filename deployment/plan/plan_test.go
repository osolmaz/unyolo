package plan

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/osolmaz/unyolo/deployment/api"
	"github.com/osolmaz/unyolo/deployment/profile"
	"github.com/osolmaz/unyolo/internal/host/bundle"
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

func TestBuildKindsCyclesAndMarshal(t *testing.T) {
	snapshot := profile.Snapshot{Deployment: profile.Deployment{Name: "host"}, Digest: testDigest("pack"), Manifest: bundle.Manifest{BundleID: "bundle"}}
	for _, test := range []struct {
		active string
		kind   Kind
	}{
		{"", KindInstall},
		{"bundle", KindNoop},
	} {
		value, err := Build(snapshot, testDigest("observed"), nil, test.active)
		if err != nil || value.Kind != test.kind {
			t.Fatalf("Build(%q) = %#v, %v", test.active, value, err)
		}
		data, err := Marshal(value)
		if err != nil || !json.Valid(data) || data[len(data)-1] != '\n' {
			t.Fatalf("Marshal() = %q, %v", data, err)
		}
	}
	actions := []Action{
		{ID: "one", DependsOn: []string{"two"}},
		{ID: "two", DependsOn: []string{"one"}},
	}
	if _, err := orderActions(actions); err == nil {
		t.Fatal("dependency cycle was accepted")
	}
	if _, err := orderActions([]Action{{ID: "one", DependsOn: []string{"missing"}}}); err == nil {
		t.Fatal("missing dependency was accepted")
	}
	invalid := Plan{APIVersion: APIVersion, Digest: "bad"}
	if err := invalid.Validate(); err == nil {
		t.Fatal("invalid plan was accepted")
	}
}

func testDigest(value string) string { return fmt.Sprintf("sha256:%x", sha256.Sum256([]byte(value))) }
