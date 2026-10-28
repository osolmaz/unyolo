package opbinding

import (
	"slices"
	"testing"
)

func TestOrganizationProjectItemProjectionRegistry(t *testing.T) {
	operations := []string{"project.projects_list_items_for_org", "project.projects_get_org_item", "project.projects_update_item_for_org"}
	want := []string{
		"content.html_url", "content.id", "content.node_id", "content.number", "content.url",
		"content_type", "created_at", "fields.data_type", "fields.id", "fields.name",
		"fields.value.id", "fields.value.name.raw", "id", "node_id", "updated_at",
	}
	for _, operation := range operations {
		t.Run(operation, func(t *testing.T) {
			bindings := ByOperation(operation)
			if len(bindings) != 1 || !slices.Equal(bindings[0].ResponseProjection, want) {
				t.Fatalf("unexpected projection: %+v", bindings)
			}
			for _, field := range want {
				if !safeResponseField(operation, field) {
					t.Errorf("reviewed path rejected: %s", field)
				}
			}
			for _, field := range []string{
				"content", "fields", "fields.value", "fields.value.name", "content.body", "content.token",
				"fields.value.token", "fields.value.name.html", "fields.value.name.token", "unknown.id", "token.id",
				"fields.unknown.id", "archived_at", "item_url", "project_url", "fields..id", "fields.*.id",
			} {
				if safeResponseField(operation, field) {
					t.Errorf("unreviewed path accepted: %s", field)
				}
				values := slices.Clone(mustBindings(t))
				for i := range values {
					if values[i].Operation == operation {
						values[i].ResponseProjection = []string{field}
					}
				}
				if err := Validate(values); err == nil {
					t.Errorf("registry accepted unreviewed path: %s", field)
				}
			}
		})
	}
	// No special-leaf allowance for user counterparts or unrelated operations.
	for _, operation := range []string{"project.projects_list_items_for_user", "project.projects_get_user_item", "project.projects_update_item_for_user", "issue.issues_get", "project.projects_add_item_to_org"} {
		for _, field := range []string{"content_type", "content.html_url", "fields.data_type", "fields.value.name.raw"} {
			if safeResponseField(operation, field) {
				t.Errorf("special path %s accepted for %s", field, operation)
			}
		}
	}
}
