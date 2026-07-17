// Package openapidrift compares the structural surface of two OpenAPI documents.
package openapidrift

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
)

const (
	CategoryAuthentication = "authentication"
	CategoryDeprecation    = "deprecation"
	CategoryOperation      = "operation"
	CategorySchema         = "schema"
)

var methods = map[string]bool{
	"delete": true, "get": true, "head": true, "patch": true,
	"post": true, "put": true, "options": true, "trace": true,
}

type operation struct {
	ID         string
	Schema     string
	Auth       string
	Deprecated bool
}

// Change is one added, removed, or structurally changed OpenAPI surface.
type Change struct {
	Category string
	Kind     string
	Key      string
	Before   string
	After    string
}

// Analyze returns deterministic structural changes while ignoring prose-only edits.
func Analyze(pinned, current []byte) ([]Change, error) {
	before, err := parse(pinned)
	if err != nil {
		return nil, fmt.Errorf("parse pinned OpenAPI document: %w", err)
	}
	after, err := parse(current)
	if err != nil {
		return nil, fmt.Errorf("parse current OpenAPI document: %w", err)
	}
	changes := compare(before, after)
	slices.SortFunc(changes, compareChanges)
	return changes, nil
}

func parse(data []byte) (map[string]operation, error) {
	var document map[string]any
	if err := json.Unmarshal(data, &document); err != nil {
		return nil, fmt.Errorf("invalid OpenAPI document")
	}
	paths, ok := document["paths"].(map[string]any)
	if !ok || len(paths) == 0 {
		return nil, fmt.Errorf("invalid OpenAPI document")
	}
	result := make(map[string]operation)
	for path, rawItem := range paths {
		values, err := parsePath(path, rawItem, document)
		if err != nil {
			return nil, err
		}
		for key, value := range values {
			result[key] = value
		}
	}
	return result, nil
}

func parsePath(path string, rawItem any, document map[string]any) (map[string]operation, error) {
	item, ok := rawItem.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("path %s is invalid", path)
	}
	result := make(map[string]operation)
	for method, raw := range item {
		if !methods[strings.ToLower(method)] {
			continue
		}
		value, ok := raw.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("%s %s: invalid operation", method, path)
		}
		decoded, err := decodeOperation(value, document["security"], item["parameters"], document)
		if err != nil {
			return nil, fmt.Errorf("%s %s: %w", method, path, err)
		}
		result[strings.ToUpper(method)+" "+path] = decoded
	}
	return result, nil
}

func decodeOperation(value map[string]any, inheritedSecurity, pathParameters any, root map[string]any) (operation, error) {
	security := value["security"]
	if security == nil {
		security = inheritedSecurity
	}
	references, err := referencedComponents(root, []any{value, pathParameters})
	if err != nil {
		return operation{}, err
	}
	result := operation{
		ID:         stringValue(value["operationId"]),
		Auth:       digestValue(effectiveSecurity(root, security)),
		Deprecated: boolValue(value["deprecated"]),
	}
	structural := cloneMap(value)
	delete(structural, "description")
	delete(structural, "summary")
	delete(structural, "externalDocs")
	delete(structural, "tags")
	delete(structural, "security")
	delete(structural, "deprecated")
	delete(structural, "operationId")
	result.Schema = digestValue(stripDescriptions(map[string]any{
		"operation":       structural,
		"path_parameters": pathParameters,
		"references":      references,
	}))
	return result, nil
}

func cloneMap(value map[string]any) map[string]any {
	result := make(map[string]any, len(value))
	for key, child := range value {
		result[key] = child
	}
	return result
}

func compare(before, after map[string]operation) []Change {
	changes := make([]Change, 0)
	for _, key := range unionKeys(before, after) {
		left, leftOK := before[key]
		right, rightOK := after[key]
		if !leftOK || !rightOK {
			kind := "added"
			if leftOK {
				kind = "removed"
			}
			changes = append(changes, Change{Category: CategoryOperation, Kind: kind, Key: key})
			continue
		}
		changes = append(changes, compareExisting(key, left, right)...)
	}
	return changes
}

func compareExisting(key string, left, right operation) []Change {
	changes := make([]Change, 0, 4)
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
	return changes
}

func unionKeys(before, after map[string]operation) []string {
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
