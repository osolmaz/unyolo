package mcpgrant

import (
	"encoding/json"
	"testing"

	usebudget "github.com/osolmaz/unyolo/authorization/budget"
)

func TestProjectReturnsClosedGrantDocument(t *testing.T) {
	t.Parallel()
	grant, err := Project(Input{
		ID: "grant-1", RequestID: "request-1", Status: "active", Operation: "bucket.object.write",
		Target: map[string]any{"kind": "bucket", "owner": "acme", "name": "artifacts", "keys": []string{"runs/**"}},
		Attrs:  map[string]any{}, Mode: "window", Minutes: 10080, MaxUses: usebudget.Unlimited,
		UsesRemaining: -1,
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}
	data, err := json.Marshal(grant)
	if err != nil {
		t.Fatal(err)
	}
	var value map[string]any
	if err := json.Unmarshal(data, &value); err != nil {
		t.Fatal(err)
	}
	if value["api_version"] != APIVersion || value["max_uses"] != nil {
		t.Fatalf("projection = %s", data)
	}
	for _, forbidden := range []string{"client", "reason", "decision_token"} {
		if _, found := value[forbidden]; found {
			t.Fatalf("projection contains %q", forbidden)
		}
	}
}

func TestProjectRejectsInvalidProviderData(t *testing.T) {
	t.Parallel()
	if _, err := Project(Input{ID: "grant-1", Status: "future", Operation: "repo.create", Target: map[string]any{}, Attrs: map[string]any{}, Mode: "window", Minutes: 5}); err == nil {
		t.Fatal("Project() accepted invalid status")
	}
}
