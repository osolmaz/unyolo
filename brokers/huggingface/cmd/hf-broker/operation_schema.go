package main

import (
	"encoding/json"
	"strings"
)

func splitSealedArgumentsSchema(schema map[string]any, paths []string) (map[string]any, map[string]any) {
	public := cloneSchema(schema)
	sealed := map[string]any{"type": "object", "properties": map[string]any{}, "additionalProperties": false}
	if definitions, ok := schema["$defs"]; ok {
		sealed["$defs"] = cloneSchemaValue(definitions)
	}
	for _, value := range paths {
		path := strings.Split(value, ".")
		leaf, found := schemaProperty(schema, schema, path)
		if !found {
			panic("sealed argument path is absent from operation schema: " + value)
		}
		insertSchemaPath(sealed, path, leaf)
		removeSchemaPath(public, public, path)
	}
	return public, sealed
}

func cloneSchema(schema map[string]any) map[string]any {
	encoded, err := json.Marshal(schema)
	if err != nil {
		panic(err)
	}
	var cloned map[string]any
	if json.Unmarshal(encoded, &cloned) != nil {
		panic("could not clone operation schema")
	}
	return cloned
}

func cloneSchemaValue(value any) any {
	encoded, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	var cloned any
	if json.Unmarshal(encoded, &cloned) != nil {
		panic("could not clone operation schema value")
	}
	return cloned
}

func schemaProperty(root, current map[string]any, path []string) (map[string]any, bool) {
	if len(path) == 0 {
		return nil, false
	}
	current = resolveLocalSchemaReference(root, current)
	properties, ok := current["properties"].(map[string]any)
	if !ok {
		return schemaPropertyInBranches(root, current, path)
	}
	next, ok := properties[path[0]].(map[string]any)
	if !ok {
		return nil, false
	}
	if len(path) == 1 {
		return cloneSchema(next), true
	}
	return schemaProperty(root, next, path[1:])
}

func schemaPropertyInBranches(root, current map[string]any, path []string) (map[string]any, bool) {
	for _, keyword := range []string{"anyOf", "oneOf", "allOf"} {
		for _, branch := range schemaBranches(current[keyword]) {
			if value, found := schemaProperty(root, branch, path); found {
				return value, true
			}
		}
	}
	return nil, false
}

func resolveLocalSchemaReference(root, schema map[string]any) map[string]any {
	reference, _ := schema["$ref"].(string)
	if !strings.HasPrefix(reference, "#/") {
		return schema
	}
	resolved, found := resolveSchemaPointer(root, reference)
	if !found {
		panic("operation schema contains an unresolved local reference: " + reference)
	}
	return resolved
}

func embeddedOperationSchema(schema map[string]any) map[string]any {
	if schema == nil {
		return nil
	}
	root := cloneSchema(schema)
	inlined, ok := inlineSchemaReferences(root, root, map[string]bool{}).(map[string]any)
	if !ok {
		panic("operation schema root is not an object")
	}
	delete(inlined, "$schema")
	delete(inlined, "$defs")
	delete(inlined, "components")
	return inlined
}

func inlineSchemaReferences(root map[string]any, value any, resolving map[string]bool) any {
	switch typed := value.(type) {
	case map[string]any:
		return inlineSchemaMap(root, typed, resolving)
	case []any:
		return inlineSchemaArray(root, typed, resolving)
	default:
		return value
	}
}

func inlineSchemaMap(root, schema map[string]any, resolving map[string]bool) any {
	reference, local := schema["$ref"].(string)
	if !local || !strings.HasPrefix(reference, "#/") {
		for key, child := range schema {
			schema[key] = inlineSchemaReferences(root, child, resolving)
		}
		return schema
	}
	if resolving[reference] {
		panic("operation schema contains a recursive local reference: " + reference)
	}
	resolved, found := resolveSchemaPointer(root, reference)
	if !found {
		panic("operation schema contains an unresolved local reference: " + reference)
	}
	replacement := cloneSchema(resolved)
	for key, sibling := range schema {
		if key != "$ref" {
			replacement[key] = sibling
		}
	}
	return inlineSchemaReferences(root, replacement, withResolvedReference(resolving, reference))
}

func inlineSchemaArray(root map[string]any, values []any, resolving map[string]bool) []any {
	for index, child := range values {
		values[index] = inlineSchemaReferences(root, child, resolving)
	}
	return values
}

func withResolvedReference(resolving map[string]bool, reference string) map[string]bool {
	result := make(map[string]bool, len(resolving)+1)
	for key, present := range resolving {
		result[key] = present
	}
	result[reference] = true
	return result
}

func resolveSchemaPointer(root map[string]any, reference string) (map[string]any, bool) {
	var current any = root
	for _, token := range strings.Split(strings.TrimPrefix(reference, "#/"), "/") {
		token = strings.ReplaceAll(strings.ReplaceAll(token, "~1", "/"), "~0", "~")
		object, ok := current.(map[string]any)
		if !ok {
			return nil, false
		}
		current, ok = object[token]
		if !ok {
			return nil, false
		}
	}
	resolved, ok := current.(map[string]any)
	return resolved, ok
}

func insertSchemaPath(root map[string]any, path []string, leaf map[string]any) {
	current := root
	for index, name := range path {
		properties := current["properties"].(map[string]any)
		if index == len(path)-1 {
			properties[name] = leaf
			return
		}
		next, ok := properties[name].(map[string]any)
		if !ok {
			next = map[string]any{"type": "object", "properties": map[string]any{}, "additionalProperties": false}
			properties[name] = next
		}
		current = next
	}
}

func removeSchemaPath(root, current map[string]any, path []string) {
	current = resolveLocalSchemaReference(root, current)
	properties, ok := current["properties"].(map[string]any)
	if len(path) == 0 {
		return
	}
	if !ok {
		for _, keyword := range []string{"anyOf", "oneOf", "allOf"} {
			for _, branch := range schemaBranches(current[keyword]) {
				removeSchemaPath(root, branch, path)
			}
		}
		return
	}
	if len(path) == 1 {
		delete(properties, path[0])
		removeRequiredProperty(current, path[0])
		return
	}
	next, _ := properties[path[0]].(map[string]any)
	if next != nil {
		removeSchemaPath(root, next, path[1:])
	}
}

func schemaBranches(value any) []map[string]any {
	values, _ := value.([]any)
	result := make([]map[string]any, 0, len(values))
	for _, value := range values {
		if branch, ok := value.(map[string]any); ok {
			result = append(result, branch)
		}
	}
	return result
}

func removeRequiredProperty(schema map[string]any, name string) {
	required, ok := schema["required"].([]any)
	if !ok {
		return
	}
	filtered := required[:0]
	for _, value := range required {
		if value != name {
			filtered = append(filtered, value)
		}
	}
	if len(filtered) == 0 {
		delete(schema, "required")
		return
	}
	schema["required"] = filtered
}
