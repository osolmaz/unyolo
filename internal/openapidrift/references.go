package openapidrift

import (
	"fmt"
	"strconv"
	"strings"
)

func referencedComponents(root map[string]any, values []any) (map[string]any, error) {
	result := make(map[string]any)
	for _, value := range values {
		if err := collectReferences(root, value, result); err != nil {
			return nil, err
		}
	}
	return result, nil
}

func collectReferences(root map[string]any, value any, result map[string]any) error {
	switch typed := value.(type) {
	case map[string]any:
		return collectMapReferences(root, typed, result)
	case []any:
		return collectSliceReferences(root, typed, result)
	}
	return nil
}

func collectMapReferences(root, value map[string]any, result map[string]any) error {
	if err := collectReference(root, value, result); err != nil {
		return err
	}
	for _, child := range value {
		if err := collectReferences(root, child, result); err != nil {
			return err
		}
	}
	return nil
}

func collectSliceReferences(root map[string]any, value []any, result map[string]any) error {
	for _, child := range value {
		if err := collectReferences(root, child, result); err != nil {
			return err
		}
	}
	return nil
}

func collectReference(root, value map[string]any, result map[string]any) error {
	reference, _ := value["$ref"].(string)
	if !strings.HasPrefix(reference, "#/") || result[reference] != nil {
		return nil
	}
	result[reference] = map[string]any{"$cycle": true}
	resolved, err := resolvePointer(root, reference)
	if err != nil {
		return err
	}
	result[reference] = stripDescriptions(resolved)
	return collectReferences(root, resolved, result)
}

func resolvePointer(root map[string]any, reference string) (any, error) {
	var current any = root
	for _, rawToken := range strings.Split(strings.TrimPrefix(reference, "#/"), "/") {
		token := strings.ReplaceAll(strings.ReplaceAll(rawToken, "~1", "/"), "~0", "~")
		var found bool
		current, found = pointerChild(current, token)
		if !found {
			return nil, fmt.Errorf("unresolved local reference %q", reference)
		}
	}
	return current, nil
}

func pointerChild(current any, token string) (any, bool) {
	switch typed := current.(type) {
	case map[string]any:
		value, found := typed[token]
		return value, found
	case []any:
		return slicePointerChild(typed, token)
	default:
		return nil, false
	}
}

func resolvePathItem(root map[string]any, raw any) (map[string]any, error) {
	item, ok := raw.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("expected object")
	}
	return resolvePathItemReferences(root, item, map[string]bool{})
}

func resolvePathItemReferences(root, item map[string]any, seen map[string]bool) (map[string]any, error) {
	reference, _ := item["$ref"].(string)
	if !strings.HasPrefix(reference, "#/") {
		return cloneMap(item), nil
	}
	if seen[reference] {
		return nil, fmt.Errorf("cyclic Path Item reference %q", reference)
	}
	seen[reference] = true
	resolved, err := resolvePointer(root, reference)
	if err != nil {
		return nil, err
	}
	target, ok := resolved.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("path item reference %q is not an object", reference)
	}
	result, err := resolvePathItemReferences(root, target, seen)
	if err != nil {
		return nil, err
	}
	for key, value := range item {
		if key != "$ref" {
			result[key] = value
		}
	}
	return result, nil
}

func slicePointerChild(current []any, token string) (any, bool) {
	index, err := strconv.Atoi(token)
	if err != nil || index < 0 || index >= len(current) {
		return nil, false
	}
	return current[index], true
}

func effectiveSecurity(root map[string]any, requirements any) (any, error) {
	schemes := selectedSecuritySchemes(root, requirements)
	references, err := referencedComponents(root, []any{schemes})
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"requirements": requirements,
		"schemes":      schemes,
		"references":   references,
	}, nil
}

func selectedSecuritySchemes(root map[string]any, requirements any) map[string]any {
	components, _ := root["components"].(map[string]any)
	schemes, _ := components["securitySchemes"].(map[string]any)
	result := make(map[string]any)
	entries, _ := requirements.([]any)
	for _, entry := range entries {
		names, _ := entry.(map[string]any)
		for name := range names {
			if scheme, found := schemes[name]; found {
				result[name] = stripDescriptions(scheme)
			}
		}
	}
	return result
}
