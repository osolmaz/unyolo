package main

import (
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/osolmaz/brokerkit/capability"
)

var pathParameterPattern = regexp.MustCompile(`\{([^}]+)\}`)

func targetSchemas() map[string]map[string]any {
	result := make(map[string]map[string]any, len(targetKinds))
	for _, kind := range targetKinds {
		properties := map[string]any{
			"kind":    map[string]any{"const": kind},
			"id":      map[string]any{"type": "integer", "minimum": 1},
			"node_id": map[string]any{"type": "string", "minLength": 1, "maxLength": 256},
			"owner":   nameSchema(), "name": nameSchema(), "number": map[string]any{"type": "integer", "minimum": 1},
		}
		required := []string{"kind"}
		switch kind {
		case "repo":
			required = append(required, "owner", "name")
		case "organization", "enterprise", "user":
			required = append(required, "name")
		default:
			required = append(required, "id")
		}
		result[kind] = map[string]any{"$schema": "https://json-schema.org/draft/2020-12/schema", "type": "object", "properties": properties, "required": required, "additionalProperties": false}
	}
	return result
}

func nameSchema() map[string]any {
	return map[string]any{"type": "string", "minLength": 1, "maxLength": 255, "pattern": `^[^/\x00-\x1f]+$`}
}

func targetDescriptors(schemas map[string]map[string]any) []targetDescriptor {
	result := make([]targetDescriptor, 0, len(schemas))
	for kind := range schemas {
		fields := []string{"id", "node_id", "owner", "name", "number"}
		result = append(result, targetDescriptor{Kind: kind, Schema: "target." + kind + ".v1", PolicyFields: fields})
	}
	slices.SortFunc(result, func(a, b targetDescriptor) int { return strings.Compare(a.Kind, b.Kind) })
	return result
}

//nolint:cyclop // OpenAPI projection branches are intentionally visible for audit.
func schemasForREST(name, method, path string, operation restOperation, targetKind string, components map[string]any) operationSchemas {
	properties := map[string]any{}
	required := []string{}
	for _, parameter := range operation.Parameters {
		parameter = resolveOpenAPIObject(parameter, components, map[string]bool{})
		location, _ := parameter["in"].(string)
		parameterName, _ := parameter["name"].(string)
		if location == "header" || parameterName == "per_page" || parameterName == "page" {
			continue
		}
		if location == "path" && pathParameterComesFromTarget(parameterName, targetKind) {
			continue
		}
		schema, _ := parameter["schema"].(map[string]any)
		properties[parameterName] = closeOpenAPISchema(schema, components, map[string]bool{}, 0)
		if value, _ := parameter["required"].(bool); value {
			required = append(required, parameterName)
		}
	}
	if len(operation.RequestBody) > 0 {
		requestBody := resolveOpenAPIObject(operation.RequestBody, components, map[string]bool{})
		if schema := mediaSchema(requestBody, components); schema != nil {
			properties["input"] = schema
			if value, _ := requestBody["required"].(bool); value {
				required = append(required, "input")
			}
		}
	}
	slices.Sort(required)
	arguments := map[string]any{"$schema": "https://json-schema.org/draft/2020-12/schema", "type": "object", "properties": properties, "additionalProperties": false}
	if len(required) > 0 {
		arguments["required"] = required
	}
	result := projectedResponseSchema(responseSchema(operation, components), responseProjection(operation))
	if runnerCredentialOutput(operation.OperationID) != nil {
		result = map[string]any{
			"$schema": "https://json-schema.org/draft/2020-12/schema", "type": "object", "additionalProperties": false,
			"properties": map[string]any{
				"stored": map[string]any{"const": true}, "slot": nameSchema(), "kind": map[string]any{"const": "github-runner-token"},
			},
			"required": []string{"stored", "slot", "kind"},
		}
	}
	return operationSchemas{Target: "target." + targetKind + ".v1", Arguments: arguments, Result: result}
}

func projectedResponseSchema(schema map[string]any, projection []string) map[string]any {
	if len(projection) == 0 {
		return schema
	}
	if schema["type"] == "array" {
		if items, ok := schema["items"].(map[string]any); ok {
			copy := cloneSchema(schema)
			copy["items"] = projectedResponseSchema(items, projection)
			return copy
		}
		return schema
	}
	properties, ok := schema["properties"].(map[string]any)
	if !ok {
		return schema
	}
	selected := map[string]any{}
	for _, name := range projection {
		if value, found := properties[name]; found {
			selected[name] = value
		}
	}
	return map[string]any{"$schema": "https://json-schema.org/draft/2020-12/schema", "type": "object", "properties": selected, "additionalProperties": false}
}

func cloneSchema(value map[string]any) map[string]any {
	encoded, _ := json.Marshal(value)
	var result map[string]any
	_ = json.Unmarshal(encoded, &result)
	return result
}

func mediaSchema(container map[string]any, components map[string]any) map[string]any {
	content, _ := container["content"].(map[string]any)
	for _, media := range []string{"application/json", "application/vnd.github+json", "application/scim+json"} {
		entry, _ := content[media].(map[string]any)
		schema, _ := entry["schema"].(map[string]any)
		if schema != nil {
			return closeOpenAPISchema(schema, components, map[string]bool{}, 0)
		}
	}
	return nil
}

func responseSchema(operation restOperation, components map[string]any) map[string]any {
	keys := make([]string, 0, len(operation.Responses))
	for status := range operation.Responses {
		if strings.HasPrefix(status, "2") {
			keys = append(keys, status)
		}
	}
	slices.Sort(keys)
	for _, status := range keys {
		response, _ := operation.Responses[status].(map[string]any)
		response = resolveOpenAPIObject(response, components, map[string]bool{})
		if schema := mediaSchema(response, components); schema != nil {
			schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
			return schema
		}
	}
	return map[string]any{"$schema": "https://json-schema.org/draft/2020-12/schema", "type": "object", "properties": map[string]any{}, "additionalProperties": false, "maxProperties": 0}
}

func resolveOpenAPIObject(value map[string]any, components map[string]any, resolving map[string]bool) map[string]any {
	reference, _ := value["$ref"].(string)
	if !strings.HasPrefix(reference, "#/components/") {
		return value
	}
	if resolving[reference] {
		return map[string]any{"type": "object", "properties": map[string]any{}, "additionalProperties": false, "maxProperties": 0}
	}
	resolved, ok := resolveComponentPointer(components, strings.TrimPrefix(reference, "#/components/"))
	if !ok {
		panic("unresolved OpenAPI reference: " + reference)
	}
	return resolved
}

func resolveComponentPointer(components map[string]any, pointer string) (map[string]any, bool) {
	var current any = components
	for _, token := range strings.Split(pointer, "/") {
		object, ok := current.(map[string]any)
		if !ok {
			return nil, false
		}
		current, ok = object[strings.ReplaceAll(strings.ReplaceAll(token, "~1", "/"), "~0", "~")]
		if !ok {
			return nil, false
		}
	}
	result, ok := current.(map[string]any)
	return result, ok
}

//nolint:cyclop // Recursive reference closure must handle every schema shape explicitly.
func closeOpenAPISchema(schema map[string]any, components map[string]any, resolving map[string]bool, depth int) map[string]any {
	reference, _ := schema["$ref"].(string)
	if strings.HasPrefix(reference, "#/components/") {
		if resolving[reference] || depth > 12 {
			return map[string]any{"type": "object", "properties": map[string]any{}, "additionalProperties": false, "maxProperties": 0}
		}
		resolved, ok := resolveComponentPointer(components, strings.TrimPrefix(reference, "#/components/"))
		if !ok {
			panic("unresolved OpenAPI schema: " + reference)
		}
		next := make(map[string]bool, len(resolving)+1)
		for key, value := range resolving {
			next[key] = value
		}
		next[reference] = true
		return closeOpenAPISchema(resolved, components, next, depth+1)
	}
	closed := closeSchema(schema, depth)
	for key, value := range closed {
		switch typed := value.(type) {
		case map[string]any:
			closed[key] = closeOpenAPISchema(typed, components, resolving, depth+1)
		case []any:
			for index, item := range typed {
				if child, ok := item.(map[string]any); ok {
					typed[index] = closeOpenAPISchema(child, components, resolving, depth+1)
				}
			}
		}
	}
	delete(closed, "nullable")
	return closed
}

//nolint:cyclop // Closed-schema hardening is clearer as explicit keyword checks.
func closeSchema(schema map[string]any, depth int) map[string]any {
	if schema == nil {
		return map[string]any{"type": "string", "maxLength": 4096}
	}
	data, _ := json.Marshal(schema)
	var result map[string]any
	_ = json.Unmarshal(data, &result)
	delete(result, "example")
	if depth > 8 {
		return map[string]any{"type": "string", "maxLength": 4096}
	}
	if result["type"] == "object" {
		if _, present := result["additionalProperties"]; !present {
			result["additionalProperties"] = false
		} else if result["additionalProperties"] == true {
			result["additionalProperties"] = map[string]any{"type": []any{"string", "number", "integer", "boolean", "null"}}
			result["maxProperties"] = 100
			result["propertyNames"] = map[string]any{"type": "string", "minLength": 1, "maxLength": 255}
		}
		if properties, ok := result["properties"].(map[string]any); ok {
			for name, value := range properties {
				if child, ok := value.(map[string]any); ok {
					properties[name] = closeSchema(child, depth+1)
				}
			}
		}
	}
	if result["type"] == "array" {
		if child, ok := result["items"].(map[string]any); ok {
			result["items"] = closeSchema(child, depth+1)
		}
		if _, present := result["maxItems"]; !present {
			result["maxItems"] = 100
		}
	}
	if result["type"] == "string" {
		if _, present := result["maxLength"]; !present {
			result["maxLength"] = 1 << 20
		}
	}
	return result
}

func bindingForREST(name, method, path string, operation restOperation, descriptor capability.Descriptor, components map[string]any) restBinding {
	pathParameters := pathParameterNames(path)
	arguments := []parameterBinding{}
	pagination := "none"
	conditional := false
	for _, parameter := range operation.Parameters {
		parameter = resolveOpenAPIObject(parameter, components, map[string]bool{})
		location, _ := parameter["in"].(string)
		parameterName, _ := parameter["name"].(string)
		if location != "query" {
			continue
		}
		if parameterName == "page" || parameterName == "per_page" {
			pagination = "link"
			continue
		}
		arguments = append(arguments, parameterBinding{Name: parameterName, In: location})
	}
	if method == "GET" || method == "HEAD" {
		conditional = true
	}
	responseLimit := int64(4 << 20)
	if descriptor.ExecutorKind == "bounded-stream" {
		responseLimit = 256 << 20
	}
	projection := responseProjection(operation)
	projection = filterResponseProjection(responseSchema(operation, components), projection)
	return restBinding{
		ID: "rest:" + operation.OperationID + ":" + name, Operation: name, UpstreamOperationID: operation.OperationID,
		Method: method, PathTemplate: path, CredentialKind: descriptor.CredentialKind, APIVersion: apiVersion,
		MediaType: "application/vnd.github+json", TargetPathParameters: pathParameters, ArgumentParameters: arguments,
		RequestSchema: descriptor.ArgumentSchema, ResponseSchema: descriptor.ResultSchema, ResponseProjection: projection,
		RequestBytesLimit: 2 << 20, ResponseBytesLimit: responseLimit, Pagination: pagination, ConditionalRequest: conditional,
		RedirectPolicy: redirectPolicy(descriptor.ExecutorKind), Reconciliation: descriptor.ReconcilerKind,
	}
}

func filterResponseProjection(schema map[string]any, projection []string) []string {
	if schema["type"] == "array" {
		schema, _ = schema["items"].(map[string]any)
	}
	properties, _ := schema["properties"].(map[string]any)
	result := make([]string, 0, len(projection))
	for _, name := range projection {
		if _, found := properties[name]; found {
			result = append(result, name)
		}
	}
	return result
}

func pathParameterComesFromTarget(name, targetKind string) bool {
	if targetKind == "repo" && (name == "owner" || name == "repo") {
		return true
	}
	if (targetKind == "organization" && name == "org") || (targetKind == "enterprise" && name == "enterprise") ||
		(targetKind == "user" && (name == "username" || name == "user")) {
		return true
	}
	if strings.HasSuffix(name, "_number") || name == "number" {
		return true
	}
	return name == targetKind+"_id" || (name == targetKind+"_name" && targetKind != "repo")
}

func pathParameterNames(path string) []string {
	matches := pathParameterPattern.FindAllStringSubmatch(path, -1)
	result := make([]string, 0, len(matches))
	for _, match := range matches {
		result = append(result, match[1])
	}
	return result
}

func responseProjection(operation restOperation) []string {
	// Projection is intentionally conservative until the typed executors land.
	// These fields are safe metadata shared by GitHub resource responses.
	return []string{"id", "node_id", "name", "number", "state", "status", "sha", "url", "created_at", "updated_at"}
}

func redirectPolicy(executor string) string {
	if executor == "bounded-stream" {
		return "github-download-host-allowlist"
	}
	return "disabled"
}

//nolint:cyclop // GraphQL kind handling is an exhaustive schema conversion switch.
func schemaForGraphQLInput(ref typeRef, types map[string]introspectionType, resolving map[string]bool) map[string]any {
	if ref.Kind == "NON_NULL" && ref.OfType != nil {
		return schemaForGraphQLInput(*ref.OfType, types, resolving)
	}
	if ref.Kind == "LIST" && ref.OfType != nil {
		return map[string]any{"type": "array", "items": schemaForGraphQLInput(*ref.OfType, types, resolving), "maxItems": 100}
	}
	switch ref.Kind {
	case "SCALAR":
		switch ref.Name {
		case "Int":
			return map[string]any{"type": "integer"}
		case "Float":
			return map[string]any{"type": "number"}
		case "Boolean":
			return map[string]any{"type": "boolean"}
		default:
			return map[string]any{"type": "string", "maxLength": 1 << 20}
		}
	case "ENUM":
		typeInfo := types[ref.Name]
		values := make([]string, 0, len(typeInfo.EnumValues))
		for _, value := range typeInfo.EnumValues {
			values = append(values, value.Name)
		}
		return map[string]any{"type": "string", "enum": values}
	case "INPUT_OBJECT":
		if resolving[ref.Name] {
			return map[string]any{"type": "object", "maxProperties": 0, "additionalProperties": false}
		}
		next := make(map[string]bool, len(resolving)+1)
		for name, value := range resolving {
			next[name] = value
		}
		next[ref.Name] = true
		typeInfo := types[ref.Name]
		properties := map[string]any{}
		required := []string{}
		for _, field := range typeInfo.InputFields {
			properties[field.Name] = schemaForGraphQLInput(field.Type, types, next)
			if field.Type.Kind == "NON_NULL" && field.DefaultValue == nil {
				required = append(required, field.Name)
			}
		}
		result := map[string]any{"type": "object", "properties": properties, "additionalProperties": false}
		if len(required) > 0 {
			result["required"] = required
		}
		return result
	default:
		panic(fmt.Sprintf("unsupported GraphQL input type %s %s", ref.Kind, ref.Name))
	}
}
