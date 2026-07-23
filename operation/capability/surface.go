package capability

import (
	"slices"
	"strings"

	"github.com/osolmaz/brokerkit/mcp/operation"
)

// InputSchemas supplies provider-owned target, public argument, and sealed
// argument schemas to shared descriptor-driven surfaces.
type InputSchemas func(Descriptor) (map[string]any, map[string]any, map[string]any)

type SurfaceProjection struct {
	Target    Projection
	Arguments Projection
	Attrs     Projection
	Result    Projection
}

type SurfaceProjections func(Descriptor) SurfaceProjection

// StreamInputSchema supplies a provider-owned broker stream reference schema.
type StreamInputSchema func(Descriptor) map[string]any

// SurfaceOptions configures descriptor-driven CLI and MCP generation without
// embedding provider vocabulary in the shared package.
type SurfaceOptions struct {
	Descriptors            []Descriptor
	Schemas                InputSchemas
	AttributeNames         []string
	ToolDescription        func(Descriptor) string
	CredentialSlotPattern  string
	WindowSubmitsOperation bool
	MCPToolPrefix          string
	Projections            SurfaceProjections
	StreamInputSchema      StreamInputSchema
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
	tools := make([]map[string]any, 0, len(descriptors)+3)
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
	if options.MCPToolPrefix != "" {
		tools = append(tools, OperationUtilityTools(options.MCPToolPrefix)...)
	}
	return tools
}

// MCPToolSchema generates the closed submission schema for one descriptor.
func MCPToolSchema(descriptor Descriptor, options SurfaceOptions) map[string]any {
	targetSchema, argumentsSchema, sealedSchema := options.Schemas(descriptor)
	projection := SurfaceProjection{}
	if options.Projections != nil {
		projection = options.Projections(descriptor)
	}
	targetSchema = projectedMCPSchema(targetSchema, projection.Target)
	if argumentsSchema != nil {
		argumentsSchema = projectedMCPSchema(argumentsSchema, projection.Arguments)
	}
	properties := map[string]any{
		"target":     targetSchema,
		"reason":     map[string]any{"type": "string", "minLength": 1, "maxLength": 2000},
		"request_id": requestIDSchema(),
	}
	required := []string{"target", "reason"}
	if descriptor.AuthorizationMode == ModeExecution || options.WindowSubmitsOperation {
		required = addExecutionToolProperties(properties, required, descriptor, options, argumentsSchema, sealedSchema)
	} else {
		addWindowToolProperties(properties, options.AttributeNames, projection.Attrs)
	}
	return map[string]any{"type": "object", "additionalProperties": false, "required": required, "properties": properties}
}

func addExecutionToolProperties(
	properties map[string]any,
	required []string,
	descriptor Descriptor,
	options SurfaceOptions,
	argumentsSchema map[string]any,
	sealedSchema map[string]any,
) []string {
	properties["arguments"] = argumentsSchema
	required = append(required, "arguments")
	if options.StreamInputSchema != nil {
		if streamSchema := options.StreamInputSchema(descriptor); streamSchema != nil {
			properties["stream_input"] = streamSchema
			required = append(required, "stream_input")
		}
	}
	if !descriptor.Sealed {
		return required
	}
	return addProtectedToolProperties(properties, required, descriptor, options, sealedSchema)
}

func addProtectedToolProperties(properties map[string]any, required []string, descriptor Descriptor, options SurfaceOptions, sealedSchema map[string]any) []string {
	if descriptor.CredentialOutputKind != nil {
		pattern := options.CredentialSlotPattern
		if pattern == "" {
			pattern = "^[A-Za-z][A-Za-z0-9._-]{0,127}$"
		}
		properties["credential_slot"] = map[string]any{"type": "string", "pattern": pattern}
		return append(required, "credential_slot")
	}
	if sealedSchema == nil {
		return required
	}
	properties["sealed_arguments"] = sealedSchema
	if len(RequiredPropertyNames(sealedSchema)) > 0 {
		return append(required, "sealed_arguments")
	}
	return required
}

func addWindowToolProperties(properties map[string]any, attributeNames []string, projection Projection) {
	properties["attrs"] = projectedMCPSchema(attributeSchema(attributeNames), projection)
	properties["minutes"] = map[string]any{"type": "integer", "minimum": 0}
	properties["max_uses"] = map[string]any{"type": []string{"integer", "null"}, "minimum": 1}
}

func projectedMCPSchema(schema map[string]any, projection Projection) map[string]any {
	if projection.Empty() {
		if issues := AuditMCPPublicSchema(schema); len(issues) > 0 {
			panic(issues[0])
		}
		return schema
	}
	projected, err := projection.MCPSchema(schema)
	if err != nil {
		panic(err)
	}
	return projected
}

// OperationUtilityTools returns provider-prefixed operation lifecycle tools
// with closed shared schemas.
func OperationUtilityTools(prefix string) []map[string]any {
	id := map[string]any{"type": "string", "minLength": 1, "maxLength": 128}
	get := map[string]any{
		"type": "object", "additionalProperties": false, "required": []string{"operation_id"},
		"properties": map[string]any{"operation_id": id},
	}
	wait := cloneSchema(get)
	wait["properties"].(map[string]any)["timeout_seconds"] = map[string]any{
		"type": "integer", "minimum": 0, "maximum": mcpoperation.MaxWaitSeconds, "default": mcpoperation.DefaultWaitSeconds,
	}
	list := map[string]any{
		"type": "object", "additionalProperties": false, "properties": map[string]any{
			"request_id": requestIDSchema(),
			"state":      map[string]any{"type": "string", "enum": []string{"pending", "approved", "executing", "succeeded", "failed", "denied", "expired", "canceled"}},
			"limit":      map[string]any{"type": "integer", "minimum": 1, "maximum": mcpoperation.MaxListLimit, "default": mcpoperation.DefaultListLimit},
			"cursor":     id,
		},
	}
	return []map[string]any{
		{"name": prefix + "operation_get", "description": "Get one requester-owned broker operation by operation_id.", "inputSchema": get},
		{"name": prefix + "operation_wait", "description": "Wait up to 25 seconds for one requester-owned broker operation.", "inputSchema": wait},
		{"name": prefix + "operation_list", "description": "List or recover requester-owned broker operations.", "inputSchema": list},
		{"name": prefix + "operation_cancel", "description": "Cancel one requester-owned broker operation before execution starts.", "inputSchema": get},
	}
}

func requestIDSchema() map[string]any {
	return map[string]any{"type": "string", "minLength": 1, "maxLength": 128, "pattern": "^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$"}
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
