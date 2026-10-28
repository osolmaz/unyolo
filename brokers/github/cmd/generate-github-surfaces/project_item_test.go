package main

import (
	"encoding/json"
	"os"
	"reflect"
	"slices"
	"testing"
)

func TestProjectItemReadbackUsesOnlyOrganizationOperations(t *testing.T) {
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
	for _, operation := range []string{"project.projects_list_items_for_org", "project.projects_get_org_item", "project.projects_update_item_for_org"} {
		t.Run(operation, func(t *testing.T) {
			// Resolve the pinned official component in the same way as the
			// production response schema; it leaves content/fields open.
			schema := closeOpenAPISchema(map[string]any{"$ref": "#/components/schemas/projects-v2-item-with-content"}, document.Components, map[string]bool{}, 0)
			if operation == "project.projects_list_items_for_org" {
				schema = map[string]any{"type": "array", "items": schema}
			}
			schema = projectItemResponseSchema(operation, schema)
			projection := responseProjection(operation, schema)
			if !slices.Equal(projection, projectItemResponseProjection()) || !slices.IsSorted(projection) {
				t.Fatalf("projection = %v", projection)
			}
			projected := projectedResponseSchema(schema, projection)
			encoded, err := json.Marshal(projected)
			if err != nil {
				t.Fatal(err)
			}
			var closed map[string]any
			if err := json.Unmarshal(encoded, &closed); err != nil {
				t.Fatal(err)
			}
			assertProjectObjectsClosed(t, closed)
		})
	}
	for _, operation := range []string{"project.projects_list_items_for_user", "project.projects_get_user_item", "project.projects_update_item_for_user", "project.projects_add_item_to_org", "member.users_get_authenticated"} {
		schema := map[string]any{"type": "object", "properties": map[string]any{"id": map[string]any{"type": "integer"}}}
		before, err := json.Marshal(schema)
		if err != nil {
			t.Fatal(err)
		}
		after, err := json.Marshal(projectItemResponseSchema(operation, schema))
		if err != nil {
			t.Fatal(err)
		}
		if organizationProjectItemReadback(operation) || !reflect.DeepEqual(before, after) || !slices.Equal(responseProjection(operation, schema), []string{"id"}) {
			t.Errorf("unselected operation changed: %s", operation)
		}
	}
}

func assertProjectObjectsClosed(t *testing.T, value any) {
	t.Helper()
	switch node := value.(type) {
	case map[string]any:
		if node["type"] == "object" && node["additionalProperties"] != false {
			t.Errorf("open object: %v", node)
		}
		for _, child := range node {
			assertProjectObjectsClosed(t, child)
		}
	case []any:
		for _, child := range node {
			assertProjectObjectsClosed(t, child)
		}
	}
}
