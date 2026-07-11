package protocol_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
	for _, route := range []string{"/.well-known/brokerkit-operator", "/api/operator/v1/requests", "/api/operator/v1/events"} {
		if !strings.Contains(text, route) {
			t.Fatalf("OpenAPI missing %s", route)
		}
	}
	if strings.Contains(text, "/api/grants") {
		t.Fatal("OpenAPI contains legacy route")
	}
}
