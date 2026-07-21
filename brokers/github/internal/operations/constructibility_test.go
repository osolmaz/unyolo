package operations

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/osolmaz/brokerkit/brokers/github/internal/opbinding"
	"github.com/osolmaz/brokerkit/brokers/github/internal/opcatalog"
	"github.com/osolmaz/brokerkit/brokers/github/internal/schemaregistry"
	"github.com/osolmaz/brokerkit/internal/storage/sealed"
	"github.com/osolmaz/brokerkit/internal/storage/stream"
)

func TestEveryAdvertisedOperationAcceptsConstructibleInput(t *testing.T) {
	adapters, err := NewGeneratedAdapters(nil, newAdapterOptions(t))
	if err != nil {
		t.Fatal(err)
	}
	registry, err := NewRegistry(adapters...)
	if err != nil {
		t.Fatal(err)
	}
	for _, descriptor := range opcatalog.MustAll() {
		adapter, found := registry.Lookup(descriptor.Name)
		if !found {
			continue
		}
		targetSchema, publicSchema, _ := schemaregistry.InputSchemas(descriptor.Descriptor)
		targetValue := schemaExample(targetSchema)
		if descriptor.Name == adminMergeOperation {
			targetValue = map[string]any{"kind": "pull_request", "owner": "octocat", "repo": "hello-world", "number": 1}
		}
		target := mustJSON(t, targetValue)
		public := mustJSON(t, schemaExample(publicSchema))
		arguments := public
		switch {
		case streamDirection(descriptor.Name) == "upload":
			arguments = mustJSON(t, map[string]any{"public": public, "stream_input": streamReference(descriptor.Name)})
		case descriptor.CredentialOutputKind != nil:
			arguments = mustJSON(t, map[string]any{"public": public, "credential_slot": "generated-contract"})
		case descriptor.Sealed:
			arguments = mustJSON(t, map[string]any{"public": public, "sealed_payload": sealedReference(descriptor.Name)})
		}
		if _, err := adapter.Decode(target, arguments); err != nil {
			t.Errorf("%s rejected generated target=%s arguments=%s: %v", descriptor.Name, target, arguments, err)
		}
	}
}

func streamDirection(operation string) string {
	bindings := opbinding.ByOperation(operation)
	if len(bindings) == 1 {
		return bindings[0].StreamDirection
	}
	return ""
}

func streamReference(operation string) streamstore.Reference {
	return streamstore.Reference{ID: "stream_abcdefghijklmnopqrstuvwx", Owner: "bob", Purpose: operation, RequestKey: "contract",
		Digest: strings.Repeat("a", 64), Size: 1, MediaType: "application/octet-stream", ExpiresAt: time.Now().Add(time.Hour).Unix()}
}

func sealedReference(operation string) sealedstore.Reference {
	return sealedstore.Reference{ID: "sealed_abcdefghijklmnopqrstuvwx", Owner: "bob", Purpose: operation, RequestKey: "contract",
		Digest: strings.Repeat("a", 64), Size: 1, ExpiresAt: time.Now().Add(time.Hour).Unix()}
}

func mustJSON(t *testing.T, value any) json.RawMessage {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func schemaExample(schema map[string]any) any {
	if value, found := schema["const"]; found {
		return value
	}
	if values, ok := schema["enum"].([]any); ok && len(values) > 0 {
		return values[0]
	}
	if branches, ok := schema["oneOf"].([]any); ok && len(branches) > 0 {
		if branch, branchOK := branches[0].(map[string]any); branchOK {
			return schemaExample(mergeSchemaBranch(schema, branch, "oneOf"))
		}
	}
	if branches, ok := schema["anyOf"].([]any); ok && len(branches) > 0 {
		if branch, branchOK := branches[0].(map[string]any); branchOK {
			return schemaExample(mergeSchemaBranch(schema, branch, "anyOf"))
		}
	}
	if branches, ok := schema["allOf"].([]any); ok && len(branches) > 0 {
		result := map[string]any{}
		for _, value := range branches {
			branch, _ := value.(map[string]any)
			if object, ok := schemaExample(branch).(map[string]any); ok {
				for name, child := range object {
					result[name] = child
				}
			}
		}
		return result
	}
	typeName := schemaType(schema["type"])
	switch typeName {
	case "object", "":
		properties, _ := schema["properties"].(map[string]any)
		required := stringSet(schema["required"])
		result := map[string]any{}
		for name := range required {
			child, _ := properties[name].(map[string]any)
			result[name] = schemaExample(child)
		}
		return result
	case "array":
		count := intNumber(schema["minItems"])
		items, _ := schema["items"].(map[string]any)
		result := make([]any, count)
		for index := range result {
			result[index] = schemaExample(items)
		}
		return result
	case "boolean":
		return false
	case "integer":
		return intNumber(schema["minimum"])
	case "number":
		return float64(intNumber(schema["minimum"]))
	case "null":
		return nil
	default:
		return schemaString(schema)
	}
}

func mergeSchemaBranch(parent, branch map[string]any, keyword string) map[string]any {
	merged := map[string]any{}
	for name, value := range parent {
		if name != keyword {
			merged[name] = value
		}
	}
	for name, value := range branch {
		switch name {
		case "properties":
			properties := map[string]any{}
			if parentProperties, ok := parent[name].(map[string]any); ok {
				for field, child := range parentProperties {
					properties[field] = child
				}
			}
			if branchProperties, ok := value.(map[string]any); ok {
				for field, child := range branchProperties {
					properties[field] = child
				}
			}
			merged[name] = properties
		case "required":
			required := stringSet(parent[name])
			for field := range stringSet(value) {
				required[field] = true
			}
			values := make([]any, 0, len(required))
			for field := range required {
				values = append(values, field)
			}
			merged[name] = values
		default:
			merged[name] = value
		}
	}
	return merged
}

func schemaType(value any) string {
	if direct, ok := value.(string); ok {
		return direct
	}
	if choices, ok := value.([]any); ok {
		for _, choice := range choices {
			if name, ok := choice.(string); ok && name != "null" {
				return name
			}
		}
	}
	return ""
}

func stringSet(value any) map[string]bool {
	result := map[string]bool{}
	if values, ok := value.([]any); ok {
		for _, item := range values {
			if name, ok := item.(string); ok {
				result[name] = true
			}
		}
	}
	return result
}

func intNumber(value any) int {
	switch number := value.(type) {
	case float64:
		return int(number)
	case int:
		return number
	default:
		return 0
	}
}

func schemaString(schema map[string]any) string {
	switch schema["format"] {
	case "date-time":
		return "2026-01-01T00:00:00Z"
	case "date":
		return "2026-01-01"
	case "uri":
		return "https://example.invalid/resource"
	case "repo.nwo":
		return "owner/repo"
	case "int64":
		return "1"
	}
	pattern, _ := schema["pattern"].(string)
	if pattern != "" {
		compiled, err := regexp.Compile(pattern)
		if err == nil {
			for _, candidate := range []string{
				strings.Repeat("a", 64), strings.Repeat("a", 40), "sha256:" + strings.Repeat("a", 64),
				"refs/heads/main", "ssh-ed25519 AAAA", "1.0.0", "https://example.invalid", "dGVzdA==", "value", "1",
			} {
				if compiled.MatchString(candidate) {
					return candidate
				}
			}
			panic(fmt.Sprintf("no generated string matches pattern %q", pattern))
		}
	}
	minimum := intNumber(schema["minLength"])
	if minimum < 1 {
		minimum = 1
	}
	return strings.Repeat("a", minimum)
}
