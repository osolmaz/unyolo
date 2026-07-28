package capability

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/osolmaz/unyolo/internal/strictjson"
)

type FieldProjection struct {
	Canonical string `json:"canonical"`
	MCP       string `json:"mcp"`
}

// Projection is one validated bidirectional JSON Pointer mapping set.
type Projection struct {
	fields []FieldProjection
}

func NewProjection(fields []FieldProjection) (Projection, error) {
	projection := Projection{fields: slices.Clone(fields)}
	canonical, mcp := map[string]bool{}, map[string]bool{}
	for _, field := range projection.fields {
		if err := validateFieldProjection(field, canonical, mcp); err != nil {
			return Projection{}, err
		}
		canonical[field.Canonical], mcp[field.MCP] = true, true
	}
	return projection, nil
}

func validateFieldProjection(field FieldProjection, canonical, mcp map[string]bool) error {
	canonicalTokens, err := pointerTokens(field.Canonical)
	if err != nil {
		return fmt.Errorf("canonical projection path: %w", err)
	}
	mcpTokens, err := pointerTokens(field.MCP)
	if err != nil {
		return fmt.Errorf("MCP projection path: %w", err)
	}
	if err := validateWildcardProjection(canonicalTokens, mcpTokens); err != nil {
		return err
	}
	if field.Canonical == field.MCP || canonical[field.Canonical] || mcp[field.MCP] {
		return errors.New("projection paths are duplicated or unchanged")
	}
	return nil
}

func validateWildcardProjection(canonical, mcp []string) error {
	if !slices.Contains(canonical, "*") && !slices.Contains(mcp, "*") {
		return nil
	}
	if len(canonical) != len(mcp) || !slices.Equal(canonical[:len(canonical)-1], mcp[:len(mcp)-1]) {
		return errors.New("array projection paths must use the same parent pattern")
	}
	return nil
}

func MustProjection(fields ...FieldProjection) Projection {
	projection, err := NewProjection(fields)
	if err != nil {
		panic(err)
	}
	return projection
}

func (p Projection) Empty() bool { return len(p.fields) == 0 }

// MCPSchema renames canonical public properties while preserving the exact
// leaf schema and requiredness at both parent objects.
func (p Projection) MCPSchema(canonical map[string]any) (map[string]any, error) {
	result := cloneSchema(canonical)
	for _, field := range p.fields {
		if err := moveSchemaProperty(result, field.Canonical, field.MCP); err != nil {
			return nil, err
		}
	}
	if issues := AuditMCPPublicSchema(result); len(issues) > 0 {
		return nil, issues[0]
	}
	return result, nil
}

func (p Projection) ToCanonical(raw json.RawMessage) (json.RawMessage, error) {
	return p.projectJSON(raw, false)
}

func (p Projection) ToMCP(raw json.RawMessage) (json.RawMessage, error) {
	return p.projectJSON(raw, true)
}

func (p Projection) projectJSON(raw json.RawMessage, outbound bool) (json.RawMessage, error) {
	var value map[string]any
	if err := strictjson.Decode(raw, &value, true); err != nil || value == nil {
		return nil, errors.New("projected payload must be one JSON object")
	}
	fields := p.fields
	if !outbound {
		fields = slices.Clone(fields)
		slices.Reverse(fields)
	}
	for _, field := range fields {
		source, destination := field.Canonical, field.MCP
		if !outbound {
			source, destination = field.MCP, field.Canonical
		}
		if err := moveJSONValue(value, source, destination); err != nil {
			return nil, err
		}
	}
	return json.Marshal(value)
}

func moveSchemaProperty(root map[string]any, source, destination string) error {
	sourceTokens, _ := pointerTokens(source)
	destinationTokens, _ := pointerTokens(destination)
	sourceParent, sourceName, err := schemaParent(root, sourceTokens)
	if err != nil {
		return err
	}
	destinationParent, destinationName, err := schemaParent(root, destinationTokens)
	if err != nil {
		return err
	}
	sourceProperties := sourceParent["properties"].(map[string]any)
	destinationProperties := destinationParent["properties"].(map[string]any)
	leaf, found := sourceProperties[sourceName]
	if !found {
		return fmt.Errorf("projection source %s is absent", source)
	}
	if _, exists := destinationProperties[destinationName]; exists {
		return fmt.Errorf("projection destination %s already exists", destination)
	}
	required := schemaRequiresProperty(sourceParent, sourceName)
	delete(sourceProperties, sourceName)
	removeRequiredProperty(sourceParent, sourceName)
	destinationProperties[destinationName] = leaf
	if required {
		addRequiredProperty(destinationParent, destinationName)
	}
	return nil
}

func schemaParent(root map[string]any, tokens []string) (map[string]any, string, error) {
	if len(tokens) == 0 {
		return nil, "", errors.New("projection path must identify a property")
	}
	current := root
	for _, token := range tokens[:len(tokens)-1] {
		next, err := schemaChild(current, token)
		if err != nil {
			return nil, "", err
		}
		current = next
	}
	if _, ok := current["properties"].(map[string]any); !ok {
		return nil, "", errors.New("projection parent is not an object schema")
	}
	return current, tokens[len(tokens)-1], nil
}

func schemaChild(current map[string]any, token string) (map[string]any, error) {
	if token == "*" {
		next, ok := current["items"].(map[string]any)
		if !ok {
			return nil, errors.New("projection wildcard crosses a non-array schema")
		}
		return next, nil
	}
	properties, ok := current["properties"].(map[string]any)
	if !ok {
		return nil, errors.New("projection path crosses a non-object schema")
	}
	next, ok := properties[token].(map[string]any)
	if !ok {
		return nil, errors.New("projection parent is absent from schema")
	}
	return next, nil
}

func moveJSONValue(root map[string]any, source, destination string) error {
	sourceTokens, _ := pointerTokens(source)
	destinationTokens, _ := pointerTokens(destination)
	if slices.Contains(sourceTokens, "*") || slices.Contains(destinationTokens, "*") {
		return moveJSONWildcardValue(root, sourceTokens, destinationTokens)
	}
	sourceParent, sourceName, found := jsonParent(root, sourceTokens)
	if !found {
		return nil
	}
	destinationParent, destinationName, destinationFound := jsonParent(root, destinationTokens)
	if !destinationFound {
		return fmt.Errorf("projection destination parent %s is absent", destination)
	}
	if _, collision := destinationParent[destinationName]; collision {
		return fmt.Errorf("projection destination %s collides", destination)
	}
	value, present := sourceParent[sourceName]
	if !present {
		return nil
	}
	delete(sourceParent, sourceName)
	destinationParent[destinationName] = value
	return nil
}

func moveJSONWildcardValue(root map[string]any, source, destination []string) error {
	if len(source) != len(destination) || len(source) == 0 || !slices.Equal(source[:len(source)-1], destination[:len(destination)-1]) {
		return errors.New("array projection paths must use the same parent pattern")
	}
	return renameJSONAt(root, source[:len(source)-1], source[len(source)-1], destination[len(destination)-1])
}

func renameJSONAt(current any, path []string, source, destination string) error {
	if len(path) == 0 {
		return renameJSONObjectField(current, source, destination)
	}
	if path[0] == "*" {
		return renameJSONItems(current, path[1:], source, destination)
	}
	object, ok := current.(map[string]any)
	if !ok {
		return errors.New("projection path crosses a non-object value")
	}
	next, present := object[path[0]]
	if !present {
		return nil
	}
	return renameJSONAt(next, path[1:], source, destination)
}

func renameJSONObjectField(current any, source, destination string) error {
	object, ok := current.(map[string]any)
	if !ok {
		return errors.New("projection parent is not an object")
	}
	if _, collision := object[destination]; collision {
		return fmt.Errorf("projection destination %s collides", destination)
	}
	value, present := object[source]
	if !present {
		return nil
	}
	delete(object, source)
	object[destination] = value
	return nil
}

func renameJSONItems(current any, path []string, source, destination string) error {
	items, ok := current.([]any)
	if !ok {
		return errors.New("projection wildcard crosses a non-array value")
	}
	for _, item := range items {
		if err := renameJSONAt(item, path, source, destination); err != nil {
			return err
		}
	}
	return nil
}

func jsonParent(root map[string]any, tokens []string) (map[string]any, string, bool) {
	if len(tokens) == 0 {
		return nil, "", false
	}
	current := root
	for _, token := range tokens[:len(tokens)-1] {
		next, ok := current[token].(map[string]any)
		if !ok {
			return nil, "", false
		}
		current = next
	}
	return current, tokens[len(tokens)-1], true
}

func pointerTokens(pointer string) ([]string, error) {
	if pointer == "" || pointer[0] != '/' {
		return nil, errors.New("projection path must be an absolute JSON Pointer")
	}
	parts := strings.Split(pointer[1:], "/")
	for index, part := range parts {
		decoded, err := decodePointerToken(part)
		if err != nil {
			return nil, err
		}
		parts[index] = decoded
	}
	return parts, nil
}

func decodePointerToken(value string) (string, error) {
	for offset := 0; offset < len(value); offset++ {
		if invalidPointerEscape(value, offset) {
			return "", errors.New("projection path contains invalid JSON Pointer escaping")
		}
	}
	return strings.ReplaceAll(strings.ReplaceAll(value, "~1", "/"), "~0", "~"), nil
}

func invalidPointerEscape(value string, offset int) bool {
	return value[offset] == '~' && (offset+1 >= len(value) || (value[offset+1] != '0' && value[offset+1] != '1'))
}

func removeRequiredProperty(schema map[string]any, name string) {
	switch required := schema["required"].(type) {
	case []string:
		schema["required"] = slices.DeleteFunc(required, func(value string) bool { return value == name })
	case []any:
		schema["required"] = slices.DeleteFunc(required, func(value any) bool { return value == name })
	}
}

func escapeJSONPointerToken(value string) string {
	return strings.ReplaceAll(strings.ReplaceAll(value, "~", "~0"), "/", "~1")
}
