package apicompat

import (
	"encoding/json"

	"github.com/vektah/gqlparser/v2/ast"
)

// resolveValue converts one GraphQL literal or variable reference into the
// JSON-shaped value that GitHub executes. A missing variable is null.
func resolveValue(value *ast.Value, variables map[string]any) (any, error) {
	switch value.Kind {
	case ast.Variable:
		return variables[value.Raw], nil
	case ast.StringValue, ast.BlockValue, ast.EnumValue:
		return value.Raw, nil
	case ast.IntValue, ast.FloatValue:
		return json.Number(value.Raw), nil
	case ast.BooleanValue:
		return value.Raw == "true", nil
	case ast.ListValue:
		return resolveList(value.Children, variables)
	case ast.ObjectValue:
		return resolveObject(value.Children, variables)
	default:
		return nil, nil
	}
}

func resolveList(children ast.ChildValueList, variables map[string]any) ([]any, error) {
	result := make([]any, 0, len(children))
	for _, child := range children {
		value, err := resolveValue(child.Value, variables)
		if err != nil {
			return nil, err
		}
		result = append(result, value)
	}
	return result, nil
}

func resolveObject(children ast.ChildValueList, variables map[string]any) (map[string]any, error) {
	result := make(map[string]any, len(children))
	for _, child := range children {
		if _, duplicate := result[child.Name]; duplicate {
			return nil, malformed("GraphQL input field %s is repeated", child.Name)
		}
		value, err := resolveValue(child.Value, variables)
		if err != nil {
			return nil, err
		}
		result[child.Name] = value
	}
	return result, nil
}
