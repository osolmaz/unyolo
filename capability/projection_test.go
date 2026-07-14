package capability

import (
	"encoding/json"
	"os"
	"slices"
	"testing"
)

func TestCompatibilityProfileAndAudit(t *testing.T) {
	profile := MCPCompatibilityProfile{}
	if profile.Classify("request_key", false) != MCPFieldCollision || profile.Classify("request_key", true) != MCPFieldSensitive ||
		profile.Classify("request_id", false) != MCPFieldSafe {
		t.Fatal("compatibility profile classification drifted")
	}
	schema := map[string]any{"type": "object", "properties": map[string]any{
		"request_id": map[string]any{"type": "string"}, "nested": map[string]any{"type": "object", "properties": map[string]any{"key": map[string]any{"type": "string"}}},
	}}
	issues := AuditMCPPublicSchema(schema)
	if len(issues) != 1 || issues[0].Path != "/nested/key" {
		t.Fatalf("issues = %+v", issues)
	}
}

func TestCompatibilityAuditDescendsThroughSchemaContainers(t *testing.T) {
	schema := map[string]any{
		"type": "object",
		"properties": map[string]any{
			"entries": map[string]any{"type": "array", "items": map[string]any{
				"type": "object", "properties": map[string]any{"api_token": map[string]any{"type": "string"}},
			}},
		},
		"allOf": []any{map[string]any{
			"type": "object", "properties": map[string]any{"private_key": map[string]any{"type": "string"}},
		}},
	}
	issues := AuditMCPPublicSchema(schema)
	if len(issues) != 2 || issues[0].Path != "/entries/*/api_token" || issues[1].Path != "/private_key" {
		t.Fatalf("issues = %+v", issues)
	}
}

func TestCompatibilityProfileConformsToPinnedOpenClawFixture(t *testing.T) {
	raw, err := os.ReadFile("testdata/openclaw-redaction-v2026.7.1-beta.5.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Source struct{ Package, Version string } `json:"source"`
		Cases  []struct {
			Name       string `json:"name"`
			Sensitive  bool   `json:"sensitive"`
			ShortValue string `json:"short_value"`
			LongValue  string `json:"long_value"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.Source.Package != "openclaw" || fixture.Source.Version != "2026.7.1-beta.5" || len(fixture.Cases) < 30 {
		t.Fatalf("invalid OpenClaw fixture metadata: %+v", fixture.Source)
	}
	profile := MCPCompatibilityProfile{}
	for _, testCase := range fixture.Cases {
		class := profile.Classify(testCase.Name, false)
		if testCase.Sensitive && class == MCPFieldSafe {
			t.Errorf("OpenClaw redacts %q but BrokerKit classifies it safe", testCase.Name)
		}
		if !testCase.Sensitive && transcriptSafeExactNames[testCase.Name] && class != MCPFieldSafe {
			t.Errorf("reviewed alias %q is not safe", testCase.Name)
		}
		if testCase.Sensitive && (testCase.ShortValue == "hunter2" || testCase.LongValue == "abcdefghijklmnopqrstu") {
			t.Errorf("OpenClaw fixture did not redact %q", testCase.Name)
		}
	}
}

func TestProjectionSchemaAndJSONRoundTrip(t *testing.T) {
	projection := MustProjection(FieldProjection{Canonical: "/key", MCP: "/variable_name"})
	canonical := map[string]any{
		"type": "object", "additionalProperties": false, "required": []any{"key", "value"},
		"properties": map[string]any{"key": map[string]any{"type": "string"}, "value": map[string]any{"type": "integer"}},
	}
	mcp, err := projection.MCPSchema(canonical)
	if err != nil {
		t.Fatal(err)
	}
	properties := mcp["properties"].(map[string]any)
	if properties["key"] != nil || properties["variable_name"] == nil ||
		!slices.Contains(RequiredPropertyNames(mcp), "variable_name") || slices.Contains(RequiredPropertyNames(mcp), "key") {
		t.Fatalf("projected schema = %#v", mcp)
	}
	inbound, err := projection.ToCanonical(json.RawMessage(`{"variable_name":"MODE","value":1}`))
	if err != nil || string(inbound) != `{"key":"MODE","value":1}` {
		t.Fatalf("inbound = %s, %v", inbound, err)
	}
	outbound, err := projection.ToMCP(inbound)
	if err != nil || string(outbound) != `{"value":1,"variable_name":"MODE"}` {
		t.Fatalf("outbound = %s, %v", outbound, err)
	}
}

func TestProjectionRejectsInvalidMappings(t *testing.T) {
	for _, fields := range [][]FieldProjection{
		{{Canonical: "key", MCP: "/name"}},
		{{Canonical: "/key", MCP: "/key"}},
		{{Canonical: "/key", MCP: "/name"}, {Canonical: "/other", MCP: "/name"}},
	} {
		if _, err := NewProjection(fields); err == nil {
			t.Fatalf("invalid projection accepted: %+v", fields)
		}
	}
}
