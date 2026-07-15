package upstreamdrift

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
)

var restMethods = map[string]bool{
	"delete": true, "get": true, "head": true, "patch": true,
	"post": true, "put": true,
}

type restOperation struct {
	ID         string
	Schema     string
	Auth       string
	Deprecated bool
}

type graphSurface struct {
	Operations   map[string]string
	Schemas      map[string]string
	Deprecations map[string]string
}

// Analyze classifies structural upstream drift without producing generated artifacts.
func Analyze(pinned, current SnapshotSet) (Report, error) {
	pinnedREST, err := parseREST(pinned.REST)
	if err != nil {
		return Report{}, fmt.Errorf("parse pinned REST metadata: %w", err)
	}
	currentREST, err := parseREST(current.REST)
	if err != nil {
		return Report{}, fmt.Errorf("parse current REST metadata: %w", err)
	}
	pinnedPermissions, err := parsePermissions(pinned.Permissions)
	if err != nil {
		return Report{}, fmt.Errorf("parse pinned permission metadata: %w", err)
	}
	currentPermissions, err := parsePermissions(current.Permissions)
	if err != nil {
		return Report{}, fmt.Errorf("parse current permission metadata: %w", err)
	}
	pinnedGraphQL, err := parseGraphQL(pinned.GraphQL)
	if err != nil {
		return Report{}, fmt.Errorf("parse pinned GraphQL metadata: %w", err)
	}
	currentGraphQL, err := parseGraphQL(current.GraphQL)
	if err != nil {
		return Report{}, fmt.Errorf("parse current GraphQL metadata: %w", err)
	}

	changes := compareVersions(pinned.APIVersions, current.APIVersions)
	changes = append(changes, compareREST(pinnedREST, currentREST)...)
	changes = append(changes, compareMaps(CategoryPermission, pinnedPermissions, currentPermissions)...)
	changes = append(changes, compareMaps(CategoryOperation, pinnedGraphQL.Operations, currentGraphQL.Operations)...)
	changes = append(changes, compareMaps(CategorySchema, pinnedGraphQL.Schemas, currentGraphQL.Schemas)...)
	changes = append(changes, compareMaps(CategoryDeprecation, pinnedGraphQL.Deprecations, currentGraphQL.Deprecations)...)
	slices.SortFunc(changes, compareChanges)
	return Report{RetrievedAt: latestRetrieval(current.Sources), Sources: slices.Clone(current.Sources), Changes: changes}, nil
}

func parseREST(data []byte) (map[string]restOperation, error) {
	var document struct {
		Security json.RawMessage                       `json:"security"`
		Paths    map[string]map[string]json.RawMessage `json:"paths"`
	}
	if err := json.Unmarshal(data, &document); err != nil || len(document.Paths) == 0 {
		return nil, fmt.Errorf("invalid OpenAPI document")
	}
	result := make(map[string]restOperation)
	for path, item := range document.Paths {
		for method, raw := range item {
			if !restMethods[strings.ToLower(method)] {
				continue
			}
			operation, err := decodeRESTOperation(raw, document.Security)
			if err != nil {
				return nil, fmt.Errorf("%s %s: %w", method, path, err)
			}
			result[strings.ToUpper(method)+" "+path] = operation
		}
	}
	return result, nil
}

func decodeRESTOperation(raw, inheritedSecurity json.RawMessage) (restOperation, error) {
	var value map[string]any
	if err := json.Unmarshal(raw, &value); err != nil {
		return restOperation{}, err
	}
	security := value["security"]
	if security == nil && len(inheritedSecurity) != 0 {
		if err := json.Unmarshal(inheritedSecurity, &security); err != nil {
			return restOperation{}, err
		}
	}
	operation := restOperation{
		ID:         stringValue(value["operationId"]),
		Auth:       digestValue(security),
		Deprecated: boolValue(value["deprecated"]),
	}
	delete(value, "description")
	delete(value, "summary")
	delete(value, "externalDocs")
	delete(value, "tags")
	delete(value, "security")
	delete(value, "deprecated")
	delete(value, "operationId")
	operation.Schema = digestValue(stripDescriptions(value))
	return operation, nil
}

func compareREST(before, after map[string]restOperation) []Change {
	changes := make([]Change, 0)
	for _, key := range unionKeys(before, after) {
		left, leftOK := before[key]
		right, rightOK := after[key]
		if !leftOK || !rightOK {
			changes = append(changes, presenceChange(CategoryOperation, key, leftOK, rightOK))
			continue
		}
		if left.ID != right.ID {
			changes = append(changes, Change{Category: CategoryOperation, Kind: "changed", Key: key, Before: left.ID, After: right.ID})
		}
		if left.Schema != right.Schema {
			changes = append(changes, Change{Category: CategorySchema, Kind: "changed", Key: key, Before: left.Schema, After: right.Schema})
		}
		if left.Auth != right.Auth {
			changes = append(changes, Change{Category: CategoryAuthentication, Kind: "changed", Key: key, Before: left.Auth, After: right.Auth})
		}
		if left.Deprecated != right.Deprecated {
			changes = append(changes, Change{Category: CategoryDeprecation, Kind: "changed", Key: key, Before: fmt.Sprint(left.Deprecated), After: fmt.Sprint(right.Deprecated)})
		}
	}
	return changes
}

func parsePermissions(data []byte) (map[string]string, error) {
	var groups map[string]permissionGroup
	if err := json.Unmarshal(data, &groups); err != nil || len(groups) == 0 {
		return nil, fmt.Errorf("invalid permission matrix")
	}
	routes := map[string]map[string]string{}
	for permission, group := range groups {
		addPermissionGroup(routes, permission, group)
	}
	result := make(map[string]string, len(routes))
	for key, permissions := range routes {
		result[key] = digestValue(permissions)
	}
	return result, nil
}

type permissionGroup struct {
	Permissions []permissionEntry `json:"permissions"`
}

type permissionEntry struct {
	Verb        string `json:"verb"`
	RequestPath string `json:"requestPath"`
	Access      string `json:"access"`
	User        bool   `json:"user-to-server"`
	Server      bool   `json:"server-to-server"`
}

func addPermissionGroup(routes map[string]map[string]string, permission string, group permissionGroup) {
	for _, entry := range group.Permissions {
		addPermissionEntry(routes, permission, entry)
	}
}

func addPermissionEntry(routes map[string]map[string]string, permission string, entry permissionEntry) {
	if !entry.User && !entry.Server {
		return
	}
	key := strings.ToUpper(entry.Verb) + " " + entry.RequestPath
	if routes[key] == nil {
		routes[key] = map[string]string{}
	}
	access := entry.Access
	if access == "" {
		access = "read"
	}
	if routes[key][permission] != "write" || access == "write" {
		routes[key][permission] = access
	}
}

func parseGraphQL(data []byte) (graphSurface, error) {
	var response struct {
		Data struct {
			Schema struct {
				Types []struct {
					Name   string           `json:"name"`
					Fields []map[string]any `json:"fields"`
					Raw    map[string]any
				} `json:"types"`
			} `json:"__schema"`
		} `json:"data"`
	}
	var generic map[string]any
	if err := json.Unmarshal(data, &generic); err != nil {
		return graphSurface{}, err
	}
	if err := json.Unmarshal(data, &response); err != nil || len(response.Data.Schema.Types) == 0 {
		return graphSurface{}, fmt.Errorf("invalid introspection response")
	}
	surface := graphSurface{Operations: map[string]string{}, Schemas: map[string]string{}, Deprecations: map[string]string{}}
	dataObject, _ := generic["data"].(map[string]any)
	schemaObject, _ := dataObject["__schema"].(map[string]any)
	types, _ := schemaObject["types"].([]any)
	for _, candidate := range types {
		addGraphQLType(&surface, candidate)
	}
	return surface, nil
}

func addGraphQLType(surface *graphSurface, candidate any) {
	typeObject, _ := candidate.(map[string]any)
	name := stringValue(typeObject["name"])
	if name == "" || strings.HasPrefix(name, "__") {
		return
	}
	fields, _ := typeObject["fields"].([]any)
	if name == "Query" || name == "Mutation" {
		addGraphQLOperations(surface.Operations, name, fields)
	} else {
		surface.Schemas[name] = digestValue(stripDescriptions(typeObject))
	}
	collectDeprecations(surface.Deprecations, name, fields)
}

func addGraphQLOperations(target map[string]string, typeName string, fields []any) {
	for _, field := range fields {
		fieldObject, _ := field.(map[string]any)
		key := strings.ToLower(typeName) + "." + stringValue(fieldObject["name"])
		target[key] = digestValue(stripDescriptions(fieldObject))
	}
}

func collectDeprecations(target map[string]string, typeName string, fields []any) {
	for _, field := range fields {
		value, _ := field.(map[string]any)
		if boolValue(value["isDeprecated"]) {
			target[typeName+"."+stringValue(value["name"])] = stringValue(value["deprecationReason"])
		}
	}
}

func compareVersions(before, after []string) []Change {
	left, right := map[string]string{}, map[string]string{}
	for _, version := range before {
		left[version] = version
	}
	for _, version := range after {
		right[version] = version
	}
	return compareMaps(CategoryAPIVersion, left, right)
}

func compareMaps(category string, before, after map[string]string) []Change {
	changes := make([]Change, 0)
	for _, key := range unionKeys(before, after) {
		left, leftOK := before[key]
		right, rightOK := after[key]
		switch {
		case !leftOK || !rightOK:
			changes = append(changes, presenceChange(category, key, leftOK, rightOK))
		case left != right:
			changes = append(changes, Change{Category: category, Kind: "changed", Key: key, Before: left, After: right})
		}
	}
	return changes
}

func presenceChange(category, key string, before, after bool) Change {
	kind := "added"
	if before && !after {
		kind = "removed"
	}
	return Change{Category: category, Kind: kind, Key: key}
}

func unionKeys[T any](before, after map[string]T) []string {
	keys := make([]string, 0, len(before)+len(after))
	seen := make(map[string]bool, len(before)+len(after))
	for key := range before {
		seen[key] = true
		keys = append(keys, key)
	}
	for key := range after {
		if !seen[key] {
			keys = append(keys, key)
		}
	}
	slices.Sort(keys)
	return keys
}

func stripDescriptions(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		return stripDescriptionMap(typed)
	case []any:
		return stripDescriptionSlice(typed)
	default:
		return typed
	}
}

func stripDescriptionMap(value map[string]any) map[string]any {
	result := make(map[string]any, len(value))
	for key, child := range value {
		if key != "description" && key != "summary" && key != "externalDocs" {
			result[key] = stripDescriptions(child)
		}
	}
	return result
}

func stripDescriptionSlice(value []any) []any {
	result := make([]any, len(value))
	for index, child := range value {
		result[index] = stripDescriptions(child)
	}
	return result
}

func digestValue(value any) string {
	encoded, _ := json.Marshal(value)
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

func stringValue(value any) string { result, _ := value.(string); return result }
func boolValue(value any) bool     { result, _ := value.(bool); return result }

func compareChanges(left, right Change) int {
	if value := strings.Compare(left.Category, right.Category); value != 0 {
		return value
	}
	if value := strings.Compare(left.Kind, right.Kind); value != 0 {
		return value
	}
	return strings.Compare(left.Key, right.Key)
}
