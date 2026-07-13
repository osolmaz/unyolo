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
	if secondProperties["secret"] != nil || sealedProperties["secret"] == nil || !schemaRequiresProperty(sealed, "secret") {
		t.Fatalf("split schemas = public %#v, sealed %#v", public, sealed)
	}
}

func TestSplitSealedArgumentsSchemaKeepsNestedRequirements(t *testing.T) {
	schema := map[string]any{"type": "object", "properties": map[string]any{
		"config": map[string]any{"type": "object", "properties": map[string]any{
			"token": map[string]any{"type": "string"},
		}, "required": []any{"token"}},
	}, "required": []any{"config"}}
	_, sealed := splitSealedArgumentsSchema(schema, []string{"config.token"})
	config := sealed["properties"].(map[string]any)["config"].(map[string]any)
	if !schemaRequiresProperty(sealed, "config") || !schemaRequiresProperty(config, "token") {
		t.Fatalf("sealed requirements = %#v", sealed)
	}
}

func TestSchemaRequirementLookupRejectsMissingPaths(t *testing.T) {
	schema := map[string]any{"type": "object"}
	if _, found := schemaPathRequirements(schema, schema, nil); found {
		t.Fatal("empty schema path was found")
	}
	if _, found := schemaPathRequirements(schema, schema, []string{"missing"}); found {
		t.Fatal("missing schema path was found")
	}
	if !schemaRequiresProperty(map[string]any{"required": []string{"value"}}, "value") {
		t.Fatal("string requirements were ignored")
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
