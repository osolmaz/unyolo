package main

import (
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strconv"
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
			"owner":   nameSchema(), "repo": nameSchema(), "name": nameSchema(), "number": map[string]any{"type": "integer", "minimum": 1},
		}
		required := []string{"kind"}
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
		fields := []string{"id", "node_id", "owner", "repo", "name", "number"}
		result = append(result, targetDescriptor{Kind: kind, Schema: "target." + kind + ".v1", PolicyFields: fields})
	}
	slices.SortFunc(result, func(a, b targetDescriptor) int { return strings.Compare(a.Kind, b.Kind) })
	return result
}

func schemasForREST(name, method, path string, operation restOperation, descriptor capability.Descriptor, components map[string]any) operationSchemas {
	arguments := argumentsSchemaForREST(method, path, operation, descriptor.TargetKind, components)
	arguments = projectReviewedRequestFields(name, arguments)
	upstreamResult := responseSchema(operation, components)
	result := projectedResponseSchema(upstreamResult, responseProjection(name, upstreamResult))
	alignProjectedResultLimits(name, result, responseLimit(descriptor))
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
	return operationSchemas{Target: "target." + descriptor.TargetKind + ".v1", Arguments: arguments, Result: result}
}

func alignProjectedResultLimits(operation string, schema map[string]any, limit int64) {
	if operation != "repo.contents.read" {
		return
	}
	if properties, ok := schema["properties"].(map[string]any); ok {
		if content, ok := properties["content"].(map[string]any); ok {
			content["maxLength"] = limit
		}
		for _, value := range properties {
			if child, ok := value.(map[string]any); ok {
				alignProjectedResultLimits(operation, child, limit)
			}
		}
	}
	if items, ok := schema["items"].(map[string]any); ok {
		alignProjectedResultLimits(operation, items, limit)
	}
	for _, keyword := range []string{"oneOf", "anyOf", "allOf"} {
		for _, value := range schemaArray(schema[keyword]) {
			if child, ok := value.(map[string]any); ok {
				alignProjectedResultLimits(operation, child, limit)
			}
		}
	}
}

func schemaArray(value any) []any {
	values, _ := value.([]any)
	return values
}

func projectReviewedRequestFields(operation string, arguments map[string]any) map[string]any {
	fields, found := reviewedOverrides.RESTOperationRequestFields[operation]
	if !found {
		return arguments
	}
	properties, ok := arguments["properties"].(map[string]any)
	if !ok {
		panic(fmt.Sprintf("reviewed request projection %q has no argument properties", operation))
	}
	input, ok := properties["input"].(map[string]any)
	if !ok {
		panic(fmt.Sprintf("reviewed request projection %q has no input body", operation))
	}
	inputProperties, ok := input["properties"].(map[string]any)
	if !ok {
		panic(fmt.Sprintf("reviewed request projection %q has no input properties", operation))
	}
	selected := make(map[string]any, len(fields))
	for _, field := range fields {
		value, present := inputProperties[field]
		if !present {
			panic(fmt.Sprintf("reviewed request projection %q names unknown field %q", operation, field))
		}
		selected[field] = value
	}
	projected := copyx.JSONMap(arguments)
	projectedProperties := projected["properties"].(map[string]any)
	projectedInput := projectedProperties["input"].(map[string]any)
	projectedInput["properties"] = selected
	if required, present := projectedInput["required"].([]any); present {
		projectedInput["required"] = retainedRequired(required, selected)
	}
	return projected
}

func retainedRequired(required []any, properties map[string]any) []any {
	result := make([]any, 0, len(required))
	for _, value := range required {
		name, _ := value.(string)
		if _, found := properties[name]; found {
			result = append(result, name)
		}
	}
	return result
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
	result, _ := projectResponseSchema(schema, allowed, "", true)
	return result
}

func projectResponseSchema(schema map[string]any, allowed map[string]bool, prefix string, root bool) (map[string]any, bool) {
	result := copyx.JSONMap(schema)
	flattenComposedObjectForProjection(result)
	retained := projectResponseBranches(result, allowed, prefix)
	if projectResponseProperties(result, allowed, prefix) {
		retained = true
	}
	if root {
		result["$schema"] = "https://json-schema.org/draft/2020-12/schema"
	}
	return result, retained
}

func projectResponseBranches(result map[string]any, allowed map[string]bool, prefix string) bool {
	retained := false
	for _, keyword := range []string{"oneOf", "anyOf", "allOf"} {
		if alternatives, ok := result[keyword].([]any); ok {
			for index, alternative := range alternatives {
				if child, childOK := alternative.(map[string]any); childOK {
					projected, keep := projectResponseSchema(child, allowed, prefix, false)
					alternatives[index] = projected
					retained = retained || keep
				}
			}
		}
	}
	if items, ok := result["items"].(map[string]any); ok {
		projected, keep := projectResponseSchema(items, allowed, prefix, false)
		result["items"] = projected
		retained = retained || keep
	}
	return retained
}

func projectResponseProperties(result map[string]any, allowed map[string]bool, prefix string) bool {
	properties, object := result["properties"].(map[string]any)
	if !object {
		return false
	}
	selected := map[string]any{}
	for name, value := range properties {
		path := name
		if prefix != "" {
			path = prefix + "." + name
		}
		child, childOK := value.(map[string]any)
		projected, childRetained := child, false
		if childOK {
			projected, childRetained = projectResponseSchema(child, allowed, path, false)
		}
		if allowed[path] {
			selected[name] = value
		} else if childRetained {
			selected[name] = projected
		}
	}
	result["properties"] = selected
	result["additionalProperties"] = false
	delete(result, "required")
	return len(selected) > 0
}

func flattenComposedObjectForProjection(schema map[string]any) {
	if hasNonObjectCompositionBranch(schema) {
		return
	}
	properties, _ := schema["properties"].(map[string]any)
	if properties == nil {
		properties = map[string]any{}
	}
	object := schema["type"] == "object"
	for _, keyword := range []string{"oneOf", "anyOf", "allOf"} {
		branches, _ := schema[keyword].([]any)
		for _, value := range branches {
			branch, _ := value.(map[string]any)
			branchProperties, _ := branch["properties"].(map[string]any)
			if branch["type"] == "object" || branchProperties != nil {
				object = true
			}
			for name, child := range branchProperties {
				if _, found := properties[name]; !found {
					properties[name] = child
				}
			}
		}
	}
	if !object {
		return
	}
	schema["type"] = "object"
	schema["properties"] = properties
	schema["additionalProperties"] = false
	delete(schema, "oneOf")
	delete(schema, "anyOf")
	delete(schema, "allOf")
	delete(schema, "required")
}

func hasNonObjectCompositionBranch(schema map[string]any) bool {
	for _, keyword := range []string{"oneOf", "anyOf", "allOf"} {
		branches, _ := schema[keyword].([]any)
		for _, value := range branches {
			branch, _ := value.(map[string]any)
			if branch["type"] != "object" {
				if _, object := branch["properties"].(map[string]any); !object {
					return true
				}
			}
		}
	}
	return false
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
	nullable, _ := schema["nullable"].(bool)
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
	applyNullable(closed, nullable)
	normalizeComposedObjectProperties(closed)
	return closed
}

func applyNullable(schema map[string]any, nullable bool) {
	delete(schema, "nullable")
	if !nullable {
		return
	}
	if value, found := schema["type"]; found {
		types, ok := value.([]any)
		if !ok {
			types = []any{value}
		}
		if !slices.Contains(types, any("null")) {
			types = append(types, "null")
		}
		schema["type"] = types
		return
	}
	branch := copyx.JSONMap(schema)
	for key := range schema {
		delete(schema, key)
	}
	schema["anyOf"] = []any{branch, map[string]any{"type": "null"}}
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
	authorizationParameters := pathAuthorizationParameters(pathParameters, targetParameters)
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
	responseLimit := responseLimit(descriptor)
	requestLimit := int64(2 << 20)
	if descriptor.ExecutorKind == "bounded-stream" {
		if streamDirection(operation.OperationID) == "upload" {
			requestLimit = 256 << 20
		}
	}
	projection := responseProjection(name, responseSchema(operation, components))
	rootType := responseRootType(responseSchema(operation, components))
	return restBinding{
		ID: "rest:" + operation.OperationID + ":" + name, Operation: name, UpstreamOperationID: operation.OperationID,
		Method: method, PathTemplate: path, CredentialKind: descriptor.CredentialKind, APIVersion: apiVersion,
		MediaType: "application/vnd.github+json", PathParameters: pathParameters, TargetPathParameters: targetParameters,
		AuthorizationParameters: authorizationParameters, ArgumentParameters: arguments,
		AuthenticatedUserTarget: authenticatedUserTarget(operation.OperationID, descriptor.TargetKind, descriptor.CredentialKind, path, targetParameters),
		RequestSchema:           descriptor.ArgumentSchema, ResponseSchema: descriptor.ResultSchema, ResponseProjection: projection,
		ResponseRootType: rootType, ServerRole: serverRole(operation),
		RequestBytesLimit: requestLimit, ResponseBytesLimit: responseLimit, SuccessStatusCodes: successStatusCodes(operation, streamDirection(operation.OperationID)),
		Pagination: pagination, ConditionalRequest: conditional,
		RedirectPolicy: redirectPolicy(descriptor.ExecutorKind), Reconciliation: descriptor.ReconcilerKind,
		StreamDirection: streamDirection(operation.OperationID),
	}
}

func responseLimit(descriptor capability.Descriptor) int64 {
	if descriptor.ExecutorKind == "bounded-stream" {
		return 256 << 20
	}
	return 4 << 20
}

func pathAuthorizationParameters(pathParameters []string, targetParameters []targetParameter) []authorizationParameter {
	targetOwned := make(map[string]bool, len(targetParameters))
	for _, parameter := range targetParameters {
		targetOwned[parameter.Name] = true
	}
	result := make([]authorizationParameter, 0, len(pathParameters))
	for _, name := range pathParameters {
		if !targetOwned[name] {
			result = append(result, authorizationParameter{Name: name, Attribute: "selector_" + strings.ReplaceAll(name, "-", "_")})
		}
	}
	return result
}

func successStatusCodes(operation restOperation, direction string) []int {
	result := documentedStatusCodes(operation, 200, 300)
	if len(result) == 0 && direction == "download" {
		return documentedStatusCodes(operation, 300, 400)
	}
	return result
}

func documentedStatusCodes(operation restOperation, minimum, maximum int) []int {
	result := make([]int, 0, len(operation.Responses))
	for value := range operation.Responses {
		status, err := strconv.Atoi(value)
		if err == nil && status >= minimum && status < maximum {
			result = append(result, status)
		}
	}
	slices.Sort(result)
	return result
}

func authenticatedUserTarget(operationID, targetKind, credentialKind, path string, targetParameters []targetParameter) bool {
	if targetKind != "user" || len(targetParameters) != 0 {
		return false
	}
	if !strings.HasPrefix(path, "/user") {
		return credentialKind == "user" && len(pathParameterNames(path)) == 0
	}
	normalized := strings.ReplaceAll(operationID, "_", "-")
	return strings.Contains(normalized, "authenticated-user") || strings.HasSuffix(normalized, "authenticated")
}

func responseRootType(schema map[string]any) string {
	if value, _ := schema["type"].(string); value == "object" || value == "array" {
		return value
	}
	for _, keyword := range []string{"anyOf", "oneOf", "allOf"} {
		branches, _ := schema[keyword].([]any)
		root := ""
		for _, value := range branches {
			branch, _ := value.(map[string]any)
			kind := responseRootType(branch)
			if kind == "" || root != "" && root != kind {
				return "object"
			}
			root = kind
		}
		if root != "" {
			return root
		}
	}
	return "object"
}

func serverRole(operation restOperation) string {
	for _, server := range operation.Servers {
		if server.URL == "https://uploads.github.com" {
			return "uploads"
		}
	}
	return "api"
}

//nolint:cyclop // Target ownership is an explicit closed mapping from official path templates.
func targetPathField(name, targetKind, path string) (string, bool) {
	if targetKind == "organization" && name == "org" {
		return "name", true
	}
	if strings.Contains(path, "{owner}") && strings.Contains(path, "{repo}") {
		switch name {
		case "owner":
			return "owner", true
		case "repo":
			if targetKind != "repo" {
				return "repo", true
			}
			return "name", true
		}
	}
	if targetKind == "enterprise" && name == "enterprise" || targetKind == "user" && (name == "username" || name == "user") {
		return "name", true
	}
	nameParameters := map[string]string{"team": "team_slug", "environment": "environment_name", "package": "package_name",
		"codespace": "codespace_name", "advisory": "ghsa_id", "ref": "ref"}
	if nameParameters[targetKind] == name {
		return "name", true
	}
	idParameters := map[string]string{"check": "check_run_id"}
	if targetKind == "user" && name == "account_id" {
		return "id", true
	}
	if name == targetKind+"_id" || idParameters[targetKind] == name {
		return "id", true
	}
	numberParameters := map[string]string{"pull_request": "pull_number", "issue": "issue_number", "alert": "alert_number",
		"project": "project_number", "discussion": "discussion_number"}
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

func responseProjection(operation string, schema map[string]any) []string {
	allowed := map[string]bool{"id": true, "node_id": true, "name": true, "number": true, "state": true, "status": true,
		"type": true, "sha": true, "url": true, "created_at": true, "updated_at": true}
	if operation == "repo.contents.read" {
		allowed["content"], allowed["encoding"], allowed["path"] = true, true, true
	}
	paths := map[string]bool{}
	collectResponseProjection(schema, allowed, "", paths, 0)
	result := make([]string, 0, len(paths))
	for path := range paths {
		result = append(result, path)
	}
	if len(result) == 0 {
		return []string{"$none"}
	}
	slices.Sort(result)
	return result
}

//nolint:cyclop // Projection traversal covers every bounded JSON Schema composition shape.
func collectResponseProjection(schema map[string]any, allowed map[string]bool, prefix string, paths map[string]bool, depth int) {
	if depth > 32 {
		return
	}
	projectable := copyx.JSONMap(schema)
	flattenComposedObjectForProjection(projectable)
	properties, _ := projectable["properties"].(map[string]any)
	hasDirectProjection := false
	for name := range properties {
		hasDirectProjection = hasDirectProjection || allowed[name]
	}
	for name, value := range properties {
		path := name
		if prefix != "" {
			path = prefix + "." + name
		}
		if allowed[name] {
			paths[path] = true
			continue
		}
		if child, ok := value.(map[string]any); ok && !hasDirectProjection {
			collectResponseProjection(child, allowed, path, paths, depth+1)
		}
	}
	if items, ok := projectable["items"].(map[string]any); ok {
		collectResponseProjection(items, allowed, prefix, paths, depth+1)
	}
	for _, keyword := range []string{"oneOf", "anyOf", "allOf"} {
		if branches, ok := projectable[keyword].([]any); ok {
			for _, value := range branches {
				if child, childOK := value.(map[string]any); childOK {
					collectResponseProjection(child, allowed, prefix, paths, depth+1)
				}
			}
		}
	}
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
