package schemautil_test

import (
	"slices"
	"testing"

	"github.com/osolmaz/brokerkit/schemautil"
)

func TestSensitiveFields(t *testing.T) {
	t.Parallel()
	schema := map[string]any{"properties": map[string]any{
		"visible": map[string]any{"type": "string"},
		"nested": map[string]any{"type": "array", "items": map[string]any{"properties": map[string]any{
			"api_token": map[string]any{"type": "string"},
		}}},
		"password": map[string]any{"type": "string"},
	}}
	if got := schemautil.SensitiveTopLevelFields(schema); !slices.Equal(got, []string{"nested", "password"}) {
		t.Fatalf("SensitiveTopLevelFields() = %v", got)
	}
	if schemautil.IsSensitiveField("token", map[string]any{"type": "boolean"}) {
		t.Fatal("boolean token field classified as secret")
	}
	if schemautil.ContainsSensitiveField(map[string]any{"oneOf": []any{map[string]any{"properties": map[string]any{
		"private_key": map[string]any{"type": "string"},
	}}}}) != true {
		t.Fatal("composed sensitive schema was not detected")
	}
}
