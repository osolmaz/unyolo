package main

import (
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/osolmaz/brokerkit/capability"
	"github.com/osolmaz/brokerkit/internal/copyx"
	"github.com/osolmaz/brokerkit/schemautil"
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

func schemasForREST(name, method, path string, operation restOperation, targetKind string, components map[string]any) operationSchemas {
	arguments := argumentsSchemaForREST(method, path, operation, targetKind, components)
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
	if streamDirection(operation.OperationID) == "download" {
		result = streamResultSchema()
	}
	return operationSchemas{Target: "target." + targetKind + ".v1", Arguments: arguments, Result: result}
}

//nolint:cyclop // OpenAPI parameter and request-body forms require explicit handling.
func argumentsSchemaForREST(_ string, path string, operation restOperation, targetKind string, components map[string]any) map[string]any {
	properties := map[string]any{}
	required := []string{}
	for _, parameter := range operation.Parameters {
		parameter = resolveOpenAPIObject(parameter, components, map[string]bool{})
		location, _ := parameter["in"].(string)
		parameterName, _ := parameter["name"].(string)
		if location == "header" {
			continue
		}
		if location == "path" {
			if _, owned := targetPathField(parameterName, targetKind, path); owned {
				continue
			}
		}
		schema, _ := parameter["schema"].(map[string]any)
		closedParameter := closeOpenAPISchema(schema, components, map[string]bool{}, 0)
		switch parameterName {
		case "page":
			closedParameter["minimum"], closedParameter["maximum"] = 1, 10_000
		case "per_page":
			closedParameter["minimum"], closedParameter["maximum"] = 1, 100
		}
		properties[parameterName] = closedParameter
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
	return arguments
}

func sensitiveTopLevelPaths(schema map[string]any) []string {
	return schemautil.SensitiveTopLevelFields(schema)
}

func streamResultSchema() map[string]any {
	return map[string]any{
		"$schema": "https://json-schema.org/draft/2020-12/schema", "type": "object", "additionalProperties": false,
		"properties": map[string]any{
			"stream": map[string]any{
				"type": "object", "additionalProperties": false,
				"properties": map[string]any{
					"id": nameSchema(), "owner": nameSchema(), "purpose": nameSchema(), "request_key": nameSchema(),
					"digest":     map[string]any{"type": "string", "pattern": "^[a-f0-9]{64}$"},
					"size":       map[string]any{"type": "integer", "minimum": 1},
					"media_type": map[string]any{"type": "string", "minLength": 1, "maxLength": 255},
					"expires_at": map[string]any{"type": "integer", "minimum": 1},
				},
				"required": []string{"id", "owner", "purpose", "request_key", "digest", "size", "media_type", "expires_at"},
			},
		},
		"required": []string{"stream"},
	}
}

func projectedResponseSchema(schema map[string]any, projection []string) map[string]any {
	allowed := make(map[string]bool, len(projection))
	for _, name := range projection {
		allowed[name] = true
	}
	return projectResponseSchema(schema, allowed, true)
}

func projectResponseSchema(schema map[string]any, allowed map[string]bool, root bool) map[string]any {
	result := copyx.JSONMap(schema)
	for _, keyword := range []string{"oneOf", "anyOf", "allOf"} {
		if alternatives, ok := result[keyword].([]any); ok {
			for index, alternative := range alternatives {
				if child, childOK := alternative.(map[string]any); childOK {
					alternatives[index] = projectResponseSchema(child, allowed, false)
				}
			}
		}
	}
	if items, ok := result["items"].(map[string]any); ok {
		result["items"] = projectResponseSchema(items, allowed, false)
	}
	properties, object := result["properties"].(map[string]any)
	if object {
		selected := map[string]any{}
		for name, value := range properties {
			if allowed[name] {
				selected[name] = value
			}
		}
		result["properties"] = selected
		result["additionalProperties"] = false
		delete(result, "required")
	}
	if root {
		result["$schema"] = "https://json-schema.org/draft/2020-12/schema"
	}
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
		if resolving[reference] || depth > 32 {
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
	for _, keyword := range []string{"properties", "$defs"} {
		if values, ok := closed[keyword].(map[string]any); ok {
			for name, value := range values {
				if child, childOK := value.(map[string]any); childOK {
					values[name] = closeOpenAPISchema(child, components, resolving, depth+1)
				}
			}
		}
	}
	for _, keyword := range []string{"items", "additionalProperties", "not", "if", "then", "else", "contains", "propertyNames"} {
		if child, ok := closed[keyword].(map[string]any); ok {
			closed[keyword] = closeOpenAPISchema(child, components, resolving, depth+1)
		}
	}
	for _, keyword := range []string{"oneOf", "anyOf", "allOf"} {
		if branches, ok := closed[keyword].([]any); ok {
			for index, value := range branches {
				if child, childOK := value.(map[string]any); childOK {
					branches[index] = closeOpenAPISchema(child, components, resolving, depth+1)
				}
			}
		}
	}
	delete(closed, "nullable")
	normalizeComposedObjectProperties(closed)
	return closed
}

func normalizeComposedObjectProperties(schema map[string]any) {
	if schema["type"] != "object" || schema["additionalProperties"] != false {
		return
	}
	properties, _ := schema["properties"].(map[string]any)
	if properties == nil {
		properties = map[string]any{}
	}
	for _, keyword := range []string{"oneOf", "anyOf", "allOf"} {
		if branches, ok := schema[keyword].([]any); ok {
			for _, value := range branches {
				branch, _ := value.(map[string]any)
				branchProperties, _ := branch["properties"].(map[string]any)
				for name, child := range branchProperties {
					if _, found := properties[name]; !found {
						properties[name] = child
					}
				}
			}
		}
	}
	schema["properties"] = properties
}

func closeSchema(schema map[string]any, depth int) map[string]any {
	if schema == nil {
		return map[string]any{"type": "string", "maxLength": 4096}
	}
	data, _ := json.Marshal(schema)
	var result map[string]any
	_ = json.Unmarshal(data, &result)
	delete(result, "example")
	if depth > 32 {
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
	}
	if result["type"] == "array" {
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

//nolint:cyclop // Binding projection keeps transport, pagination, and streaming decisions auditable together.
func bindingForREST(name, method, path string, operation restOperation, descriptor capability.Descriptor, components map[string]any) restBinding {
	pathParameters := pathParameterNames(path)
	targetParameters := []targetParameter{}
	for _, parameter := range pathParameters {
		if field, owned := targetPathField(parameter, descriptor.TargetKind, path); owned {
			targetParameters = append(targetParameters, targetParameter{Name: parameter, Field: field})
		}
	}
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
		}
		arguments = append(arguments, parameterBinding{Name: parameterName, In: location})
	}
	if method == "GET" || method == "HEAD" {
		conditional = true
	}
	responseLimit := int64(4 << 20)
	requestLimit := int64(2 << 20)
	if descriptor.ExecutorKind == "bounded-stream" {
		responseLimit = 256 << 20
		if streamDirection(operation.OperationID) == "upload" {
			requestLimit = 256 << 20
		}
	}
	projection := responseProjection(operation)
	return restBinding{
		ID: "rest:" + operation.OperationID + ":" + name, Operation: name, UpstreamOperationID: operation.OperationID,
		Method: method, PathTemplate: path, CredentialKind: descriptor.CredentialKind, APIVersion: apiVersion,
		MediaType: "application/vnd.github+json", PathParameters: pathParameters, TargetPathParameters: targetParameters, ArgumentParameters: arguments,
		RequestSchema: descriptor.ArgumentSchema, ResponseSchema: descriptor.ResultSchema, ResponseProjection: projection,
		RequestBytesLimit: requestLimit, ResponseBytesLimit: responseLimit, Pagination: pagination, ConditionalRequest: conditional,
		RedirectPolicy: redirectPolicy(descriptor.ExecutorKind), Reconciliation: descriptor.ReconcilerKind,
		StreamDirection: streamDirection(operation.OperationID),
	}
}

//nolint:cyclop // Target ownership is an explicit closed mapping from official path templates.
func targetPathField(name, targetKind, path string) (string, bool) {
	if strings.HasPrefix(path, "/repos/{owner}/{repo}") || strings.HasPrefix(path, "/agents/repos/{owner}/{repo}") {
		switch name {
		case "owner":
			return "owner", true
		case "repo":
			return "name", true
		}
	}
	if strings.HasPrefix(path, "/orgs/{org}") && name == "org" {
		if targetKind == "organization" {
			return "name", true
		}
		return "owner", true
	}
	if targetKind == "enterprise" && name == "enterprise" || targetKind == "user" && (name == "username" || name == "user") {
		return "name", true
	}
	nameParameters := map[string]string{"team": "team_slug", "environment": "environment_name", "package": "package_name",
		"codespace": "codespace_name", "advisory": "ghsa_id", "ref": "ref"}
	if nameParameters[targetKind] == name {
		return "name", true
	}
	idParameters := map[string]string{"check": "check_run_id", "pull_request": "pull_number", "issue": "issue_number", "alert": "alert_number"}
	if name == targetKind+"_id" || idParameters[targetKind] == name {
		return "id", true
	}
	numberParameters := map[string]string{"pull_request": "pull_number", "issue": "issue_number", "project": "project_number", "discussion": "discussion_number"}
	if name == targetKind+"_number" || numberParameters[targetKind] == name {
		return "number", true
	}
	return "", false
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
	return []string{"id", "node_id", "name", "number", "state", "status", "type", "sha", "url", "created_at", "updated_at"}
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
