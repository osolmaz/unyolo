package schemaregistry

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestOrganizationProjectFieldResultBounds(t *testing.T) {
	for _, operation := range []string{"project.projects_get_field_for_org", "project.projects_list_fields_for_org"} {
		t.Run(operation, func(t *testing.T) {
			validate := func(field map[string]any) error {
				var value any = field
				if operation == "project.projects_list_fields_for_org" {
					value = []any{field}
				}
				raw, err := json.Marshal(value)
				if err != nil {
					t.Fatal(err)
				}
				return ValidateResult(operation, raw)
			}
			option := func() map[string]any {
				return map[string]any{"id": "offline-option", "name": map[string]any{"raw": "Done"}}
			}
			for _, tc := range []struct {
				name   string
				mutate func(map[string]any, map[string]any)
			}{
				{"root extra", func(f, o map[string]any) { f["token"] = "excluded-canary" }},
				{"option extra", func(f, o map[string]any) { o["token"] = "excluded-canary" }},
				{"name extra", func(f, o map[string]any) { o["name"].(map[string]any)["html"] = "excluded-canary" }},
				{"scalar name", func(f, o map[string]any) { o["name"] = "Done" }},
				{"numeric option id", func(f, o map[string]any) { o["id"] = 1 }},
				{"long id", func(f, o map[string]any) { o["id"] = strings.Repeat("x", (1<<20)+1) }},
				{"long raw", func(f, o map[string]any) { o["name"].(map[string]any)["raw"] = strings.Repeat("x", (1<<20)+1) }},
				{"unknown type", func(f, o map[string]any) { f["data_type"] = "unknown" }},
				{"too many options", func(f, o map[string]any) {
					options := make([]any, 101)
					for i := range options {
						options[i] = o
					}
					f["options"] = options
				}},
			} {
				t.Run(tc.name, func(t *testing.T) {
					o := option()
					f := map[string]any{"data_type": "single_select", "options": []any{o}}
					if err := validate(f); err != nil {
						t.Fatalf("valid field refused: %v", err)
					}
					tc.mutate(f, o)
					if err := validate(f); err == nil {
						t.Error("invalid field accepted")
					} else if strings.Contains(err.Error(), "excluded-canary") {
						t.Error("validation error exposed value")
					}
				})
			}
			options := make([]any, 100)
			for i := range options {
				options[i] = option()
			}
			if err := validate(map[string]any{"data_type": "single_select", "options": options}); err != nil {
				t.Fatalf("100 options refused: %v", err)
			}
			if err := validate(map[string]any{"data_type": "text"}); err != nil {
				t.Fatalf("text field refused: %v", err)
			}
		})
	}
}
