package main

import "testing"

func TestSplitSealedArgumentsSchemaHandlesComposedObjects(t *testing.T) {
	schema := map[string]any{
		"anyOf": []any{
			map[string]any{"type": "object", "properties": map[string]any{"kind": map[string]any{"type": "string"}}},
			map[string]any{"type": "object", "properties": map[string]any{
				"kind":   map[string]any{"type": "string"},
				"secret": map[string]any{"type": "string"},
			}, "required": []any{"kind", "secret"}},
		},
	}
	public, sealed := splitSealedArgumentsSchema(schema, []string{"secret"})
	branches := schemaBranches(public["anyOf"])
	secondProperties := branches[1]["properties"].(map[string]any)
	sealedProperties := sealed["properties"].(map[string]any)
	if secondProperties["secret"] != nil || sealedProperties["secret"] == nil {
		t.Fatalf("split schemas = public %#v, sealed %#v", public, sealed)
	}
}

func TestEmbeddedOperationSchemaRejectsBadLocalReferences(t *testing.T) {
	assertPanics(t, func() {
		embeddedOperationSchema(map[string]any{"$ref": "#/$defs/missing"})
	})
	assertPanics(t, func() {
		embeddedOperationSchema(map[string]any{
			"$ref":  "#/$defs/loop",
			"$defs": map[string]any{"loop": map[string]any{"$ref": "#/$defs/loop"}},
		})
	})
	if _, found := resolveSchemaPointer(map[string]any{}, "#/missing"); found {
		t.Fatal("missing JSON pointer resolved")
	}
}

func TestEmbeddedOperationSchemaKeepsReferenceSiblings(t *testing.T) {
	schema := embeddedOperationSchema(map[string]any{
		"$ref":        "#/$defs/value",
		"description": "kept",
		"$defs":       map[string]any{"value": map[string]any{"type": "string"}},
	})
	if schema["type"] != "string" || schema["description"] != "kept" || schema["$defs"] != nil {
		t.Fatalf("embedded schema = %#v", schema)
	}
}

func assertPanics(t *testing.T, call func()) {
	t.Helper()
	defer func() {
		if recover() == nil {
			t.Fatal("call did not panic")
		}
	}()
	call()
}
