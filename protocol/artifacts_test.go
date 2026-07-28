package protocol_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/osolmaz/unyolo/protocol/contract"
)

func TestOperatorV1ArtifactsAreClosedAndValid(t *testing.T) {
	files, err := filepath.Glob("schema/*.schema.json")
	if err != nil || len(files) != 7 {
		t.Fatalf("schemas = %v, %v", files, err)
	}
	for _, path := range files {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var schema map[string]any
		if err := json.Unmarshal(data, &schema); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		if schema["type"] != "object" || schema["additionalProperties"] != false {
			t.Fatalf("%s is not a closed object", path)
		}
		if !strings.Contains(string(data), "Generated from protocol/openapi/operator-v1.yaml") {
			t.Fatalf("%s is not marked as generated", path)
		}
	}
	openAPI, err := os.ReadFile("openapi/operator-v1.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(openAPI, &document); err != nil {
		t.Fatalf("OpenAPI must remain machine-readable JSON/YAML: %v", err)
	}
	text := string(openAPI)
	assertCanonicalOpenAPI(t, document)
	components := document["components"].(map[string]any)
	schemas := components["schemas"].(map[string]any)
	for _, name := range []string{"UISnapshot", "UISnapshotEvent", "UISummary", "UIRequest"} {
		if schemas[name] == nil {
			t.Fatalf("OpenAPI missing %s", name)
		}
	}
	for _, route := range []string{"/.well-known/unyolo-operator", "/api/operator/v1/requests", "/api/operator/v1/events"} {
		if !strings.Contains(text, route) {
			t.Fatalf("OpenAPI missing %s", route)
		}
	}
	if strings.Contains(text, "/api/grants") {
		t.Fatal("OpenAPI contains legacy route")
	}
	if strings.Contains(text, "decision_reason") {
		t.Fatal("OpenAPI contains removed operator decision reason")
	}
}

func TestAgentV1ArtifactsAreClosedAndValid(t *testing.T) {
	files, err := filepath.Glob("agent-schema/*.schema.json")
	if err != nil || len(files) != 5 {
		t.Fatalf("agent schemas = %v, %v", files, err)
	}
	for _, path := range files {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var schema map[string]any
		if err := json.Unmarshal(data, &schema); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		if schema["type"] != "object" || schema["additionalProperties"] != false {
			t.Fatalf("%s is not a closed object", path)
		}
		if !strings.Contains(string(data), "Generated from protocol/openapi/agent-v1.yaml") {
			t.Fatalf("%s is not marked as generated", path)
		}
	}
	openAPI, err := os.ReadFile("openapi/agent-v1.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(openAPI, &document); err != nil {
		t.Fatalf("Agent OpenAPI must remain machine-readable JSON/YAML: %v", err)
	}
	text := string(openAPI)
	assertCanonicalOpenAPI(t, document)
	for _, route := range []string{"/.well-known/unyolo-agent", "/api/agent/v1/operations", "/events"} {
		if !strings.Contains(text, route) {
			t.Fatalf("Agent OpenAPI missing %s", route)
		}
	}
}

func TestMCPV1ArtifactsAreClosedAndValid(t *testing.T) {
	files, err := filepath.Glob("mcp-schema/*.schema.json")
	if err != nil || len(files) != 4 {
		t.Fatalf("MCP schemas = %v, %v", files, err)
	}
	for _, path := range files {
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			t.Fatal(readErr)
		}
		var schema map[string]any
		if json.Unmarshal(data, &schema) != nil || schema["type"] != "object" || schema["additionalProperties"] != false {
			t.Fatalf("%s is not a closed object", path)
		}
		if !strings.Contains(string(data), "Generated from protocol/openapi/mcp-v1.yaml") {
			t.Fatalf("%s is not marked as generated", path)
		}
	}
	openAPI, err := os.ReadFile("openapi/mcp-v1.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if json.Unmarshal(openAPI, &document) != nil {
		t.Fatal("MCP OpenAPI must remain machine-readable JSON/YAML")
	}
	assertCanonicalOpenAPI(t, document)
}

func TestContractIdentitiesAndRuntimeBundleSchema(t *testing.T) {
	for name, digest := range map[string]string{"agent": contract.AgentV1Digest, "operator": contract.OperatorV1Digest} {
		if len(digest) != len("sha256:")+64 || !strings.HasPrefix(digest, "sha256:") {
			t.Fatalf("%s contract digest = %q", name, digest)
		}
	}
	data, err := os.ReadFile("runtime-bundle.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	var schema map[string]any
	if err := json.Unmarshal(data, &schema); err != nil {
		t.Fatal(err)
	}
	if schema["type"] != "object" || schema["additionalProperties"] != false {
		t.Fatal("runtime bundle schema is not closed")
	}
	properties := schema["properties"].(map[string]any)
	if properties["operator_contract_digest"] == nil || properties["agent_contract_digest"] == nil || properties["components"] == nil {
		t.Fatal("runtime bundle schema omits compatibility identity")
	}
}

func assertCanonicalOpenAPI(t *testing.T, document map[string]any) {
	t.Helper()
	components, ok := document["components"].(map[string]any)
	if !ok {
		t.Fatal("OpenAPI components are missing")
	}
	schemas, ok := components["schemas"].(map[string]any)
	if !ok || len(schemas) == 0 {
		t.Fatal("OpenAPI component schemas are missing")
	}
	seen := map[string]bool{}
	paths, _ := document["paths"].(map[string]any)
	for _, rawPath := range paths {
		path, _ := rawPath.(map[string]any)
		for _, method := range []string{"get", "post", "put", "patch", "delete"} {
			operation, _ := path[method].(map[string]any)
			if operation == nil {
				continue
			}
			id, _ := operation["operationId"].(string)
			if id == "" || seen[id] {
				t.Fatalf("OpenAPI operationId is missing or duplicated: %q", id)
			}
			seen[id] = true
		}
	}
}
