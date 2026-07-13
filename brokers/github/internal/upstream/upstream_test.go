package upstream

import (
	"encoding/json"
	"testing"
)

func TestPinnedSnapshotsValidate(t *testing.T) {
	if err := Validate(); err != nil {
		t.Fatal(err)
	}
	paths, err := ArtifactPaths()
	if err != nil || len(paths) != 11 || paths[0] != "github-app-permissions-2026-03-10.json" {
		t.Fatalf("paths=%v err=%v", paths, err)
	}
}

func TestPinnedWebhookMetadataCoversReconciliationSignals(t *testing.T) {
	expected := map[string][]string{
		"webhooks/github_app_authorization.json":  {"revoked"},
		"webhooks/installation.json":              {"created", "deleted", "suspend", "unsuspend"},
		"webhooks/installation_repositories.json": {"added", "removed"},
		"webhooks/repository.json":                {"deleted", "renamed", "transferred"},
		"webhooks/workflow_run.json":              {"completed", "in_progress", "requested"},
	}
	for file, actions := range expected {
		data, err := Read(file)
		if err != nil {
			t.Fatal(err)
		}
		var values map[string]json.RawMessage
		if json.Unmarshal(data, &values) != nil {
			t.Fatalf("invalid webhook metadata %s", file)
		}
		for _, action := range actions {
			if _, found := values[action]; !found {
				t.Fatalf("%s missing %s", file, action)
			}
		}
	}
}

func TestGraphQLSnapshotIsFullIntrospection(t *testing.T) {
	data, err := Read("graphql-introspection-2026-07-14.json")
	if err != nil {
		t.Fatal(err)
	}
	var response struct {
		Data struct {
			Schema struct {
				Types        []json.RawMessage `json:"types"`
				Directives   []json.RawMessage `json:"directives"`
				QueryType    map[string]any    `json:"queryType"`
				MutationType map[string]any    `json:"mutationType"`
			} `json:"__schema"`
		} `json:"data"`
	}
	if json.Unmarshal(data, &response) != nil || len(response.Data.Schema.Types) != 1790 || len(response.Data.Schema.Directives) == 0 || response.Data.Schema.QueryType == nil || response.Data.Schema.MutationType == nil {
		t.Fatalf("incomplete introspection: types=%d directives=%d", len(response.Data.Schema.Types), len(response.Data.Schema.Directives))
	}
}

func TestReadRejectsTraversal(t *testing.T) {
	if _, err := Read("../provenance.json"); err == nil {
		t.Fatal("Read accepted traversal")
	}
}
