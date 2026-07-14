package githubsurface

import "testing"

func TestGeneratedGitHubSurfaceValidates(t *testing.T) {
	if err := Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestSensitiveFieldDetectionRejectsCredentialMaterialButNotFlags(t *testing.T) {
	schema := map[string]any{
		"type": "object",
		"properties": map[string]any{
			"config": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"webhook_secret": map[string]any{"type": "string"},
				},
			},
			"hide_secret": map[string]any{"type": "boolean"},
		},
	}
	fields := sensitiveTopLevelFields(schema)
	if len(fields) != 1 || fields[0] != "config" {
		t.Fatalf("sensitive fields = %v", fields)
	}
	if !containsSensitiveField(schema) {
		t.Fatal("nested webhook secret was not detected")
	}
	if containsSensitiveField(map[string]any{"type": "object", "properties": map[string]any{"hide_secret": map[string]any{"type": "boolean"}}}) {
		t.Fatal("boolean secret-display flag was classified as credential material")
	}
}
