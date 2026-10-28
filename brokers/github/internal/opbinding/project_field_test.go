package opbinding

import (
	"slices"
	"testing"
)

func TestOrganizationProjectFieldProjectionRegistry(t *testing.T) {
	want := []string{"created_at", "data_type", "id", "name", "node_id", "options.id", "options.name.raw", "updated_at"}
	for _, operation := range []string{"project.projects_get_field_for_org", "project.projects_list_fields_for_org"} {
		t.Run(operation, func(t *testing.T) {
			bindings := ByOperation(operation)
			if len(bindings) != 1 || !slices.Equal(bindings[0].ResponseProjection, want) {
				t.Fatalf("unexpected projection: %+v", bindings)
			}
			for _, field := range want {
				if !safeResponseField(operation, field) {
					t.Errorf("reviewed field rejected: %s", field)
				}
			}
			for _, field := range []string{"options", "options.name", "options.name.html", "options.description.raw", "options.color", "options.token.id", "token.id", "unknown.id", "configuration.iterations.id", "options.*.id", "options..id", "project_url"} {
				if safeResponseField(operation, field) {
					t.Errorf("unreviewed field accepted: %s", field)
				}
				values := slices.Clone(mustBindings(t))
				for i := range values {
					if values[i].Operation == operation {
						values[i].ResponseProjection = []string{field}
					}
				}
				if err := Validate(values); err == nil {
					t.Errorf("registry accepted field: %s", field)
				}
			}
		})
	}
	for _, operation := range []string{"project.projects_get_field_for_user", "project.projects_list_fields_for_user", "project.projects_create_field_for_org", "project.projects_update_field_for_org", "project.projects_delete_field_for_org", "issue.issues_get"} {
		for _, field := range []string{"data_type", "options.name.raw"} {
			if safeResponseField(operation, field) {
				t.Errorf("special field %s accepted for %s", field, operation)
			}
		}
	}
}
