package capability

import (
	"slices"
	"strings"
)

// InputSchemas supplies provider-owned target, public argument, and sealed
// argument schemas to shared descriptor-driven surfaces.
type InputSchemas func(Descriptor) (map[string]any, map[string]any, map[string]any)

// SurfaceOptions configures descriptor-driven CLI and MCP generation without
// embedding provider vocabulary in the shared package.
type SurfaceOptions struct {
	Descriptors            []Descriptor
	Schemas                InputSchemas
	AttributeNames         []string
	ToolDescription        func(Descriptor) string
	CredentialSlotPattern  string
	WindowSubmitsOperation bool
}

// AgentFacing returns the descriptors exposed to authenticated agent clients.
func AgentFacing(descriptors []Descriptor) []Descriptor {
	result := make([]Descriptor, 0, len(descriptors))
	for _, descriptor := range descriptors {
		if descriptor.AgentFacing {
			result = append(result, descriptor)
		}
	}
	return result
}

// MatchCLICommand matches the longest provider-owned descriptor command at the
// start of args.
func MatchCLICommand(descriptors []Descriptor, args []string) (Descriptor, int, bool) {
	var matched Descriptor
	matchedWords := 0
	for _, descriptor := range AgentFacing(descriptors) {
		words := strings.Fields(*descriptor.CLICommand)
		if len(words) <= matchedWords || len(args) < len(words) {
			continue
		}
		if slices.Equal(args[:len(words)], words) {
			matched, matchedWords = descriptor, len(words)
		}
	}
	return matched, matchedWords, matchedWords > 0
}

// MCPTools generates one typed MCP tool per agent-facing descriptor.
func MCPTools(options SurfaceOptions) []map[string]any {
	descriptors := AgentFacing(options.Descriptors)
	tools := make([]map[string]any, 0, len(descriptors))
	for _, descriptor := range descriptors {
		description := descriptor.Name
		if options.ToolDescription != nil {
			description = options.ToolDescription(descriptor)
		}
		tools = append(tools, map[string]any{
			"name": *descriptor.MCPTool, "description": description,
			"inputSchema": MCPToolSchema(descriptor, options),
		})
	}
	return tools
}

// MCPToolSchema generates the closed submission schema for one descriptor.
func MCPToolSchema(descriptor Descriptor, options SurfaceOptions) map[string]any {
	targetSchema, argumentsSchema, sealedSchema := options.Schemas(descriptor)
	properties := map[string]any{
		"target":          targetSchema,
		"reason":          map[string]any{"type": "string", "minLength": 1, "maxLength": 2000},
		"idempotency_key": map[string]any{"type": "string", "minLength": 1},
		"wait_seconds":    map[string]any{"type": "integer", "minimum": 0, "maximum": 900},
	}
	required := []string{"target", "reason", "idempotency_key"}
	if descriptor.AuthorizationMode == ModeExecution || options.WindowSubmitsOperation {
		properties["arguments"] = argumentsSchema
		required = append(required, "arguments")
		if descriptor.Sealed {
			if descriptor.CredentialOutputKind != nil {
				pattern := options.CredentialSlotPattern
				if pattern == "" {
					pattern = "^[A-Za-z][A-Za-z0-9._-]{0,127}$"
				}
				properties["credential_slot"] = map[string]any{"type": "string", "pattern": pattern}
				required = append(required, "credential_slot")
			} else if sealedSchema != nil {
				properties["sealed_arguments"] = sealedSchema
				if len(RequiredPropertyNames(sealedSchema)) > 0 {
					required = append(required, "sealed_arguments")
				}
			}
		}
	} else {
		properties["attrs"] = attributeSchema(options.AttributeNames)
		properties["minutes"] = map[string]any{"type": "integer", "minimum": 0}
		properties["max_uses"] = map[string]any{"type": []string{"integer", "null"}, "minimum": 1}
	}
	return map[string]any{"type": "object", "additionalProperties": false, "required": required, "properties": properties}
}

// RequiredPropertyNames returns a cloned string view of a decoded required list.
func RequiredPropertyNames(schema map[string]any) []string {
	switch values := schema["required"].(type) {
	case []any:
		result := make([]string, 0, len(values))
		for _, value := range values {
			if name, ok := value.(string); ok {
				result = append(result, name)
			}
		}
		return result
	case []string:
		return slices.Clone(values)
	default:
		return nil
	}
}

func attributeSchema(names []string) map[string]any {
	properties := make(map[string]any, len(names))
	for _, name := range names {
		properties[name] = map[string]any{"oneOf": []any{
			map[string]any{"type": "integer", "minimum": 0},
			map[string]any{"type": "string"},
			map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		}}
	}
	return map[string]any{"type": "object", "properties": properties, "additionalProperties": false}
}
