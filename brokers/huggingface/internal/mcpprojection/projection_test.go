package mcpprojection

import (
	"encoding/json"
	"testing"

	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/opcatalog"
	"github.com/osolmaz/brokerkit/capability"
)

func TestRequiredHFProjections(t *testing.T) {
	for operation, name := range map[string]string{
		"space.variable.set": "variable_name", "space.variable.delete": "variable_name",
		"space.secret.set": "secret_name", "space.secret.delete": "secret_name",
	} {
		descriptor, found := opcatalog.ByName(operation)
		if !found {
			t.Fatalf("missing descriptor %s", operation)
		}
		projection := ForOperation(descriptor)
		schema, err := projection.Arguments.MCPSchema(map[string]any{
			"type": "object", "additionalProperties": false, "required": []any{"key"},
			"properties": map[string]any{"key": map[string]any{"type": "string"}},
		})
		if err != nil || schema["properties"].(map[string]any)[name] == nil || len(capability.AuditMCPPublicSchema(schema)) != 0 {
			t.Fatalf("%s projection = %#v, %v", operation, schema, err)
		}
	}
}

func TestRequiredHFArrayProjections(t *testing.T) {
	for operation, paths := range map[string][2]string{
		"repo.duplicate":   {"variables", "variable_name"},
		"sql_embed.create": {"views", "view_name"},
	} {
		descriptor, found := opcatalog.ByName(operation)
		if !found {
			t.Fatalf("missing descriptor %s", operation)
		}
		projection := ForOperation(descriptor).Arguments
		schema, err := projection.MCPSchema(map[string]any{
			"type": "object", "properties": map[string]any{paths[0]: map[string]any{
				"type": "array", "items": map[string]any{
					"type": "object", "additionalProperties": false, "required": []any{"key"},
					"properties": map[string]any{"key": map[string]any{"type": "string"}},
				},
			}},
		})
		if err != nil {
			t.Fatalf("%s projection: %v", operation, err)
		}
		item := schema["properties"].(map[string]any)[paths[0]].(map[string]any)["items"].(map[string]any)
		if item["properties"].(map[string]any)[paths[1]] == nil || len(capability.AuditMCPPublicSchema(schema)) != 0 {
			t.Fatalf("%s projection = %#v", operation, schema)
		}
	}
}

func TestProjectionPayloadHelpers(t *testing.T) {
	descriptor, found := opcatalog.ByName("space.variable.set")
	if !found {
		t.Fatal("missing variable descriptor")
	}
	arguments, err := ArgumentsToCanonical(descriptor, json.RawMessage(`{"variable_name":"MODE","value":"test"}`))
	if err != nil || string(arguments) != `{"key":"MODE","value":"test"}` {
		t.Fatalf("arguments = %s, %v", arguments, err)
	}
	attrs, err := AttrsToCanonical(descriptor, map[string]any{"object_path": "README.md"})
	if err != nil || attrs["key"] != "README.md" {
		t.Fatalf("attrs = %#v, %v", attrs, err)
	}
	if _, err := AttrsToCanonical(descriptor, map[string]any{"object_path": "README.md", "key": "collision"}); err == nil {
		t.Fatal("attribute collision accepted")
	}
	cyclic := map[string]any{}
	cyclic["self"] = cyclic
	if _, err := AttrsToCanonical(descriptor, cyclic); err == nil {
		t.Fatal("cyclic attributes accepted")
	}
	empty, err := AttrsToCanonical(descriptor, nil)
	if err != nil || len(empty) != 0 {
		t.Fatalf("omitted attrs = %#v, %v", empty, err)
	}
	raw := json.RawMessage(`{"ok":true}`)
	if projected, err := ResultToMCP(descriptor.Name, raw); err != nil || string(projected) != string(raw) {
		t.Fatalf("result = %s, %v", projected, err)
	}
}
