package profile

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMaterializeComponentsNamesAndLocksSelectedPack(t *testing.T) {
	source := testPack(t)
	if err := Lock(source, false); err != nil {
		t.Fatal(err)
	}
	snapshot, err := Load(source)
	if err != nil {
		t.Fatal(err)
	}
	parent := t.TempDir()
	if err := os.Chmod(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(parent, "chosen-host")
	path, err := MaterializeComponents(snapshot, destination, "chosen-host", []string{"fake"})
	if err != nil {
		t.Fatal(err)
	}
	selected, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if selected.Deployment.Name != "chosen-host" || len(selected.Deployment.Components) != 1 || selected.Deployment.Components[0].ID != "fake" {
		t.Fatalf("selected deployment = %+v", selected.Deployment)
	}
	original, err := Load(source)
	if err != nil || original.Deployment.Name != "test-host" {
		t.Fatalf("source changed = %+v, %v", original.Deployment, err)
	}
	if again, err := MaterializeComponents(snapshot, destination, "chosen-host", []string{"fake"}); err != nil || again != destination {
		t.Fatalf("idempotent materialization = %q, %v", again, err)
	}
}

func TestSelectedDeploymentFiltersComponentsAndAgentBindings(t *testing.T) {
	deployment := Deployment{
		APIVersion: APIVersion, Name: "template",
		Components: []Component{{ID: "github"}, {ID: "huggingface"}},
		Agents: []Agent{
			{ID: "both", ComponentIDs: []string{"github", "huggingface"}},
			{ID: "hf-only", ComponentIDs: []string{"huggingface"}},
		},
		Integrations: []Integration{{ID: "openclaw", Kind: "openclaw", AgentID: "both"}, {ID: "other", Kind: "other", AgentID: "hf-only"}},
	}
	selected, err := selectedDeployment(deployment, "chosen", []string{"github"})
	if err != nil {
		t.Fatal(err)
	}
	if selected.Name != "chosen" || len(selected.Components) != 1 || selected.Components[0].ID != "github" {
		t.Fatalf("components = %+v", selected.Components)
	}
	if len(selected.Agents) != 1 || selected.Agents[0].ID != "both" || len(selected.Agents[0].ComponentIDs) != 1 || selected.Agents[0].ComponentIDs[0] != "github" {
		t.Fatalf("agents = %+v", selected.Agents)
	}
	if len(selected.Integrations) != 1 || selected.Integrations[0].ID != "openclaw" {
		t.Fatalf("integrations = %+v", selected.Integrations)
	}
	if len(deployment.Agents[0].ComponentIDs) != 2 {
		t.Fatal("source deployment was mutated")
	}
}

func TestMaterializeComponentsRejectsMissingProvider(t *testing.T) {
	source := testPack(t)
	if err := Lock(source, false); err != nil {
		t.Fatal(err)
	}
	snapshot, err := Load(source)
	if err != nil {
		t.Fatal(err)
	}
	parent := t.TempDir()
	if err := os.Chmod(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(parent, "chosen-host")
	if _, err := MaterializeComponents(snapshot, destination, "chosen-host", []string{"github"}); err == nil {
		t.Fatal("missing provider was accepted")
	}
	if _, err := os.Lstat(destination); !os.IsNotExist(err) {
		t.Fatalf("destination exists after rejection: %v", err)
	}
}
