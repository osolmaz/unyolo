package mcpprojection

import (
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
