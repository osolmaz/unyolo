package schemaregistry

import (
	"bytes"
	"encoding/json"
	"sync"
	"testing"

	"github.com/osolmaz/brokerkit/brokers/github/internal/opcatalog"
)

func TestSchemasCoverCatalogAndAreClosed(t *testing.T) {
	if err := Validate(); err != nil {
		t.Fatal(err)
	}
	names, err := OperationNames()
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != opcatalog.ExpectedCount {
		t.Fatalf("schemas=%d catalog=%d", len(names), opcatalog.ExpectedCount)
	}
	for _, descriptor := range opcatalog.MustAll() {
		operation, found := ForOperation(descriptor.Name)
		if !found || operation.Target != descriptor.TargetSchema {
			t.Fatalf("schema missing for %q", descriptor.Name)
		}
		if descriptor.AgentFacing && HasRawEscapeHatch(descriptor.Name) {
			t.Fatalf("raw escape hatch in %q", descriptor.Name)
		}
	}
}

func TestRepositoryUpdateSchemasRemainFieldSplit(t *testing.T) {
	for _, name := range []string{"repo.description.update", "repo.visibility.update", "repo.default_branch.update", "repo.feature.update"} {
		operation, found := ForOperation(name)
		if !found {
			t.Fatalf("%s missing", name)
		}
		if operation.Arguments["additionalProperties"] != false {
			t.Fatalf("%s arguments are open", name)
		}
	}
}

func TestSubmissionValidationRejectsRawAndUnknownFields(t *testing.T) {
	validTarget := []byte(`{"kind":"repo","owner":"osolmaz","name":"brokerkit"}`)
	if err := ValidateSubmission("pull_request.create", validTarget, []byte(`{"input":{"title":"Coverage","head":"feature","base":"main"}}`)); err != nil {
		t.Fatal(err)
	}
	for _, arguments := range [][]byte{[]byte(`{"method":"GET"}`), []byte(`{"url":"https://example.invalid"}`), []byte(`{"input":{"title":"Coverage","head":"feature","base":"main","caller":"agent"}}`)} {
		if err := ValidateSubmission("pull_request.create", validTarget, arguments); err == nil {
			t.Fatalf("accepted raw/unknown arguments %s", arguments)
		}
	}
	for _, arguments := range [][]byte{
		[]byte(`{"input":{"title":"x","title":"y","head":"h","base":"b"}}`),
		[]byte(`{} {}`),
		{0xff},
	} {
		if err := ValidateSubmission("pull_request.create", validTarget, arguments); err == nil {
			t.Fatalf("accepted malformed arguments %q", arguments)
		}
	}
	if err := ValidateSubmission("pull_request.create", validTarget, bytes.Repeat([]byte(" "), (1<<20)+1)); err == nil {
		t.Fatal("accepted oversized input")
	}
}

func TestSchemaHelpersFailClosed(t *testing.T) {
	for _, schema := range []any{
		map[string]any{"$ref": "https://example.invalid/schema"},
		map[string]any{"type": "object"},
		map[string]any{"type": "object", "additionalProperties": true},
		map[string]any{"type": "array", "items": map[string]any{"type": "object"}},
		[]any{map[string]any{"type": "object"}},
	} {
		if closedSchema(schema) {
			t.Fatalf("open schema accepted: %#v", schema)
		}
	}
	if !closedSchema(map[string]any{"type": "object", "additionalProperties": false, "properties": map[string]any{"value": map[string]any{"type": "string"}}}) {
		t.Fatal("closed schema rejected")
	}
	for _, field := range []string{"method", "url", "graphql", "caller", "headers"} {
		if !containsForbiddenRawField(map[string]any{"properties": map[string]any{field: map[string]any{"type": "string"}}}) {
			t.Fatalf("raw field %q accepted", field)
		}
	}
	if _, found := targetSchemaForID("repo"); found {
		t.Fatal("unversioned target schema accepted")
	}
	if _, found := targetSchemaForID("target.repo.v2"); found {
		t.Fatal("v2 target schema accepted")
	}
	if err := validateRaw([]byte(`{}`), map[string]any{"type": "not-a-json-schema-type"}); err == nil {
		t.Fatal("invalid schema accepted")
	}
	if err := ValidateSubmission("not.real", []byte(`{}`), []byte(`{}`)); err == nil {
		t.Fatal("unknown operation accepted")
	}
	if HasRawEscapeHatch("not.real") {
		t.Fatal("unknown operation has escape hatch")
	}
}

func TestInputSchemasSplitSealedArguments(t *testing.T) {
	unsealed, _ := opcatalog.ByName("repo.metadata.read")
	target, arguments, sealed := InputSchemas(unsealed.Descriptor)
	if target["additionalProperties"] != false || arguments["additionalProperties"] != false || sealed != nil {
		t.Fatalf("unsealed target=%#v arguments=%#v sealed=%#v", target, arguments, sealed)
	}
	protected, found := opcatalog.ByName("agent_task.create_or_update_repo_secret")
	if !found || !protected.Sealed {
		t.Fatal("sealed descriptor missing")
	}
	target, arguments, sealed = InputSchemas(protected.Descriptor)
	if target == nil || arguments == nil || sealed == nil {
		t.Fatalf("sealed target=%#v arguments=%#v sealed=%#v", target, arguments, sealed)
	}
}

func TestSchemaRegistryLoadFailsClosed(t *testing.T) {
	original := append([]byte(nil), raw...)
	t.Cleanup(func() {
		raw = original
		once = sync.Once{}
		loaded, loadErr = document{}, nil
		_ = load()
	})
	var valid document
	if err := json.Unmarshal(original, &valid); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		mutate func(*document)
	}{
		{"version", func(value *document) { value.Version = 2 }},
		{"target", func(value *document) { value.Targets["repo"]["additionalProperties"] = true }},
		{"operation", func(value *document) {
			operation := value.Operations["repo.metadata.read"]
			operation.Target = ""
			value.Operations["repo.metadata.read"] = operation
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			data, _ := json.Marshal(valid)
			var altered document
			_ = json.Unmarshal(data, &altered)
			test.mutate(&altered)
			raw, _ = json.Marshal(altered)
			once = sync.Once{}
			loaded, loadErr = document{}, nil
			if err := load(); err == nil {
				t.Fatal("invalid schema registry accepted")
			}
			if _, found := ForOperation("repo.metadata.read"); found {
				t.Fatal("operation returned after load failure")
			}
			if _, found := Target("repo"); found {
				t.Fatal("target returned after load failure")
			}
		})
	}
	raw = []byte(`not-json`)
	once = sync.Once{}
	loaded, loadErr = document{}, nil
	if err := load(); err == nil {
		t.Fatal("malformed registry accepted")
	}
}

func TestInputSchemasPanicsOnMissingGeneratedMetadata(t *testing.T) {
	missing := opcatalog.MustAll()[0]
	missing.Name = "not.real"
	assertPanic := func(descriptor opcatalog.Descriptor) {
		t.Helper()
		defer func() {
			if recover() == nil {
				t.Fatal("missing schema did not panic")
			}
		}()
		InputSchemas(descriptor.Descriptor)
	}
	assertPanic(missing)
	missing = opcatalog.MustAll()[0]
	missing.TargetKind = "not_real"
	assertPanic(missing)
}
