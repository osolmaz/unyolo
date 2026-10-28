package main

import (
	"encoding/json"
	"os"
	"slices"
	"testing"
)

func TestProjectFieldReadbackUsesPinnedSchemaAndOnlyOrganizationReads(t *testing.T) {
	data, err := os.ReadFile("../../internal/upstream/snapshots/rest-api-2026-03-10.json")
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Components map[string]any `json:"components"`
	}
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatal(err)
	}
	for _, operation := range []string{"project.projects_get_field_for_org", "project.projects_list_fields_for_org"} {
		t.Run(operation, func(t *testing.T) {
			schema := closeOpenAPISchema(map[string]any{"$ref": "#/components/schemas/projects-v2-field"}, document.Components, map[string]bool{}, 0)
			if operation == "project.projects_list_fields_for_org" {
				schema = map[string]any{"type": "array", "items": schema, "maxItems": 100}
			}
			projection := responseProjection(operation, schema)
			want := []string{"created_at", "data_type", "id", "name", "node_id", "options.id", "options.name.raw", "updated_at"}
			if !slices.Equal(projection, want) || !slices.IsSorted(projection) {
				t.Fatalf("projection = %v", projection)
			}
			projected := projectedResponseSchema(schema, projection)
			assertFieldObjectsClosed(t, projected)
			item := projected
			if projected["type"] == "array" {
				item = projected["items"].(map[string]any)
			}
			properties := item["properties"].(map[string]any)
			if len(properties) != 7 {
				t.Fatalf("root property count = %d", len(properties))
			}
			options := properties["options"].(map[string]any)
			if options["maxItems"] != float64(100) {
				t.Fatalf("options not bounded: %v", options)
			}
			option := options["items"].(map[string]any)["properties"].(map[string]any)
			if len(option) != 2 {
				t.Fatalf("option properties = %v", option)
			}
			display := option["name"].(map[string]any)["properties"].(map[string]any)
			if len(display) != 1 || display["raw"] == nil {
				t.Fatalf("display properties = %v", display)
			}
			for _, leaf := range []map[string]any{option["id"].(map[string]any), display["raw"].(map[string]any), properties["data_type"].(map[string]any)} {
				if leaf["type"] != "string" || leaf["maxLength"] == nil {
					t.Errorf("unbounded or untyped leaf: %v", leaf)
				}
			}
		})
	}
	// New leaf names must not be granted to user reads, mutations or other ops.
	for _, operation := range []string{"project.projects_get_field_for_user", "project.projects_list_fields_for_user", "project.projects_create_field_for_org", "project.projects_update_field_for_org", "project.projects_delete_field_for_org", "issue.issues_get"} {
		schema := closeOpenAPISchema(map[string]any{"$ref": "#/components/schemas/projects-v2-field"}, document.Components, map[string]bool{}, 0)
		want := []string{"created_at", "id", "name", "node_id", "updated_at"}
		if operation == "issue.issues_get" {
			want = []string{"created_at", "id", "name", "node_id", "pull_request.url", "updated_at"}
		}
		if got := responseProjection(operation, schema); !slices.Equal(got, want) {
			t.Errorf("unselected operation changed: %s = %v", operation, got)
		}
	}
}
