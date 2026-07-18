package capability

import (
	"slices"
	"testing"
)

func TestDescriptorDrivenSurfaces(t *testing.T) {
	windowTool, windowCommand := "hf_repo_read", "repo read"
	secretTool, secretCommand := "hf_secret_set", "secret set"
	credentialTool, credentialCommand := "hf_token_create", "token create"
	credentialKind := "service-token"
	descriptors := []Descriptor{
		{Name: "repo.read", AuthorizationMode: ModeWindow, AgentFacing: true, MCPTool: &windowTool, CLICommand: &windowCommand},
		{Name: "secret.set", AuthorizationMode: ModeExecution, AgentFacing: true, Sealed: true, MCPTool: &secretTool, CLICommand: &secretCommand},
		{Name: "token.create", AuthorizationMode: ModeExecution, AgentFacing: true, Sealed: true,
			CredentialOutputKind: &credentialKind, MCPTool: &credentialTool, CLICommand: &credentialCommand},
		{Name: "internal.sync", AuthorizationMode: ModeExecution},
	}
	options := SurfaceOptions{
		Descriptors: descriptors, AttributeNames: []string{"ref"},
		MCPToolPrefix: "test_",
		Schemas: func(descriptor Descriptor) (map[string]any, map[string]any, map[string]any) {
			sealed := map[string]any(nil)
			if descriptor.Name == "secret.set" {
				sealed = map[string]any{"type": "object", "required": []any{"value"}, "properties": map[string]any{"value": map[string]any{"type": "string"}}}
			}
			return map[string]any{"type": "object"}, map[string]any{"type": "object"}, sealed
		},
		ToolDescription: func(descriptor Descriptor) string { return "Run " + descriptor.Name },
	}
	if facing := AgentFacing(descriptors); len(facing) != 3 {
		t.Fatalf("agent-facing descriptors = %d", len(facing))
	}
	matched, words, found := MatchCLICommand(descriptors, []string{"secret", "set", "--target"})
	if !found || words != 2 || matched.Name != "secret.set" {
		t.Fatalf("CLI match = %+v, %d, %v", matched, words, found)
	}
	if _, _, found := MatchCLICommand(descriptors, []string{"missing"}); found {
		t.Fatal("unknown CLI command matched")
	}
	tools := MCPTools(options)
	if len(tools) != 7 || tools[0]["description"] != "Run repo.read" || tools[5]["name"] != "test_operation_list" || tools[6]["name"] != "test_operation_cancel" {
		t.Fatalf("MCP tools = %#v", tools)
	}

	window := MCPToolSchema(descriptors[0], options)
	windowProperties := window["properties"].(map[string]any)
	if windowProperties["request_id"] == nil || windowProperties["idempotency_key"] != nil || windowProperties["wait_seconds"] != nil ||
		slices.Contains(RequiredPropertyNames(window), "request_id") {
		t.Fatalf("request identity schema = %#v", window)
	}
	if windowProperties["attrs"] == nil || windowProperties["minutes"] == nil || windowProperties["max_uses"] == nil {
		t.Fatalf("window schema = %#v", window)
	}
	operationWindowOptions := options
	operationWindowOptions.WindowSubmitsOperation = true
	operationWindow := MCPToolSchema(descriptors[0], operationWindowOptions)
	operationProperties := operationWindow["properties"].(map[string]any)
	if operationProperties["arguments"] == nil || operationProperties["attrs"] != nil || operationProperties["minutes"] != nil ||
		operationProperties["max_uses"] != nil || !slices.Contains(RequiredPropertyNames(operationWindow), "arguments") {
		t.Fatalf("operation window schema = %#v", operationWindow)
	}
	secret := MCPToolSchema(descriptors[1], options)
	if !slices.Contains(RequiredPropertyNames(secret), "sealed_arguments") {
		t.Fatalf("sealed schema = %#v", secret)
	}
	credential := MCPToolSchema(descriptors[2], options)
	if !slices.Contains(RequiredPropertyNames(credential), "credential_slot") {
		t.Fatalf("credential schema = %#v", credential)
	}
}

func TestRequiredPropertyNamesRepresentations(t *testing.T) {
	if values := RequiredPropertyNames(map[string]any{"required": []string{"one"}}); !slices.Equal(values, []string{"one"}) {
		t.Fatalf("string required = %#v", values)
	}
	if values := RequiredPropertyNames(map[string]any{"required": []any{"one", 2}}); !slices.Equal(values, []string{"one"}) {
		t.Fatalf("decoded required = %#v", values)
	}
	if values := RequiredPropertyNames(map[string]any{}); values != nil {
		t.Fatalf("missing required = %#v", values)
	}
}
