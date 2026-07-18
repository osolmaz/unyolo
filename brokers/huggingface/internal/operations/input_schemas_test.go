package operations

import (
	"reflect"
	"testing"
)

func TestCustomInputSchemasAreClosedAndComplete(t *testing.T) {
	if len(customInputSchemaExamples) != 39 {
		t.Fatalf("custom schema count = %d, want 39", len(customInputSchemaExamples))
	}
	for operation := range customInputSchemaExamples {
		schemas, found := CustomInputSchemas(operation)
		if !found || schemas.Target["additionalProperties"] != false || schemas.Arguments["additionalProperties"] != false {
			t.Fatalf("custom schemas for %q are not closed: %#v", operation, schemas)
		}
	}
	if _, found := CustomInputSchemas("http.request"); found {
		t.Fatal("unknown custom operation has schemas")
	}
}

func TestStructuralSchemaCoversJSONFieldShapes(t *testing.T) {
	type nested struct {
		Enabled bool `json:"enabled"`
	}
	type example struct {
		Name     string            `json:"name"`
		Optional *int              `json:"optional,omitempty"`
		Items    []nested          `json:"items"`
		Aliases  [2]string         `json:"aliases"`
		Metadata map[string]string `json:"metadata"`
		Ratio    float64           `json:"ratio"`
		Default  uint              `json:""`
		Ignored  string            `json:"-"`
		_        string
	}

	schema := structuralSchema(example{})
	properties := schema["properties"].(map[string]any)
	for _, name := range []string{"name", "optional", "items", "aliases", "metadata", "ratio", "Default"} {
		if properties[name] == nil {
			t.Fatalf("property %q is missing from %#v", name, properties)
		}
	}
	if properties["Ignored"] != nil || properties["unexported"] != nil {
		t.Fatalf("hidden fields are exposed: %#v", properties)
	}
	if got := structuralSchemaType(reflect.TypeOf(complex64(0)))["type"]; got != "string" {
		t.Fatalf("fallback schema type = %v", got)
	}
	if WindowTargetSchema()["additionalProperties"] != false || optionalStructuralSchema(nil) != nil {
		t.Fatal("window or optional schema is not closed")
	}
}
