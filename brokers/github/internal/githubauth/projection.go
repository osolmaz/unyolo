package githubauth

import "strings"

func projectJSON(value any, projection []string) (any, bool) {
	if len(projection) == 0 {
		return value, true
	}
	nameProjection := true
	allowed := make(map[string]bool, len(projection))
	for _, entry := range projection {
		allowed[entry] = true
		if strings.Contains(entry, ".") {
			nameProjection = false
		}
	}
	if nameProjection {
		return projectByName(value, allowed)
	}
	return projectByPath(value, allowed, "")
}

func projectByName(value any, allowed map[string]bool) (any, bool) {
	switch typed := value.(type) {
	case map[string]any:
		return projectMapByName(typed, allowed)
	case []any:
		return projectArrayByName(typed, allowed)
	default:
		return nil, false
	}
}

func projectMapByName(value map[string]any, allowed map[string]bool) (any, bool) {
	result := map[string]any{}
	for key, child := range value {
		if allowed[key] {
			result[key] = child
			continue
		}
		if projected, keep := projectByName(child, allowed); keep {
			result[key] = projected
		}
	}
	return result, len(result) > 0
}

func projectArrayByName(value []any, allowed map[string]bool) (any, bool) {
	result := make([]any, 0, len(value))
	for _, child := range value {
		if projected, keep := projectByName(child, allowed); keep {
			result = append(result, projected)
		}
	}
	return result, len(result) > 0
}

func projectByPath(value any, allowed map[string]bool, prefix string) (any, bool) {
	switch typed := value.(type) {
	case map[string]any:
		return projectMapByPath(typed, allowed, prefix)
	case []any:
		return projectArrayByPath(typed, allowed, prefix)
	default:
		return nil, allowed[prefix]
	}
}

func projectMapByPath(value map[string]any, allowed map[string]bool, prefix string) (any, bool) {
	result := map[string]any{}
	for key, child := range value {
		path := childProjectionPath(prefix, key)
		if allowed[path] {
			result[key] = child
			continue
		}
		if projected, keep := projectByPath(child, allowed, path); keep {
			result[key] = projected
		}
	}
	return result, len(result) > 0
}

func childProjectionPath(prefix, key string) string {
	if prefix == "" {
		return key
	}
	return prefix + "." + key
}

func projectArrayByPath(value []any, allowed map[string]bool, prefix string) (any, bool) {
	result := make([]any, 0, len(value))
	for _, child := range value {
		if projected, keep := projectByPath(child, allowed, prefix); keep {
			result = append(result, projected)
		}
	}
	return result, len(result) > 0
}
