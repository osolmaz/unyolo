package schemaregistry

import (
	"bytes"
	"encoding/json"
	"slices"
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
	wantFields := map[string][]string{
		"repo.archival.update":       {"archived"},
		"repo.default_branch.update": {"default_branch"},
		"repo.description.update":    {"description"},
		"repo.feature.update":        {"allow_forking", "has_issues", "has_projects", "has_pull_requests", "has_wiki", "is_template", "web_commit_signoff_required"},
		"repo.merge_policy.update":   {"allow_auto_merge", "allow_merge_commit", "allow_rebase_merge", "allow_squash_merge", "allow_update_branch", "delete_branch_on_merge", "merge_commit_message", "merge_commit_title", "pull_request_creation_policy", "squash_merge_commit_message", "squash_merge_commit_title", "use_squash_pr_title_as_default"},
		"repo.name.update":           {"name"},
		"repo.security.update":       {"security_and_analysis"},
		"repo.visibility.update":     {"private", "visibility"},
		"repo.website.update":        {"homepage"},
	}
	for name, want := range wantFields {
		operation, found := ForOperation(name)
		if !found {
			t.Fatalf("%s missing", name)
		}
		properties, _ := operation.Arguments["properties"].(map[string]any)
		input, _ := properties["input"].(map[string]any)
		inputProperties, _ := input["properties"].(map[string]any)
		got := make([]string, 0, len(inputProperties))
		for field := range inputProperties {
			got = append(got, field)
		}
		slices.Sort(got)
		if !slices.Equal(got, want) || operation.Arguments["additionalProperties"] != false || input["additionalProperties"] != false {
			t.Fatalf("%s fields = %v, want %v", name, got, want)
		}
	}
	target := json.RawMessage(`{"kind":"repo","owner":"osolmaz","name":"brokerkit"}`)
	if err := ValidateSubmission("repo.description.update", target, json.RawMessage(`{"input":{"visibility":"private"}}`)); err == nil {
		t.Fatal("repo.description.update accepted a visibility change")
	}
}

func TestGlobalAndNestedOperationsUseRealTargets(t *testing.T) {
	for name, want := range map[string]string{
		"gist.gists_create": "user", "repo.search_code": "installation",
		"member.orgs_update_membership_for_authenticated_user": "organization",
		"environment.repos_create_or_update_environment":       "environment",
	} {
		descriptor, found := opcatalog.ByName(name)
		if !found || descriptor.TargetKind != want {
			t.Fatalf("%s target = %q, want %q", name, descriptor.TargetKind, want)
		}
	}
	operation, found := ForOperation("repo.contents.read")
	if !found {
		t.Fatal("repo.contents.read schema is missing")
	}
	encoded, _ := json.Marshal(operation.Result)
	for _, field := range []string{`"content"`, `"encoding"`, `"path"`, `"oneOf"`, `"type":"array"`} {
		if !bytes.Contains(encoded, []byte(field)) {
			t.Fatalf("repo.contents.read result schema is missing %s", field)
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

func TestPaginatedOperationsExposeBoundedPageControls(t *testing.T) {
	target := []byte(`{"kind":"user","name":"osolmaz"}`)
	if err := ValidateSubmission("repo.list_for_authenticated_user", target, []byte(`{"page":2,"per_page":100}`)); err != nil {
		t.Fatal(err)
	}
	for _, arguments := range [][]byte{[]byte(`{"page":0}`), []byte(`{"page":10001}`), []byte(`{"per_page":0}`), []byte(`{"per_page":101}`)} {
		if err := ValidateSubmission("repo.list_for_authenticated_user", target, arguments); err == nil {
			t.Fatalf("accepted unbounded pagination %s", arguments)
		}
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

func TestSpecializedValidationBoundaries(t *testing.T) {
	target := json.RawMessage(`{"kind":"repo","owner":"osolmaz","name":"brokerkit"}`)
	sealedOperation := "agent_task.create_or_update_repo_secret"
	if err := ValidatePublicSubmission(sealedOperation, target, json.RawMessage(`{"secret_name":"DEPLOY_TOKEN"}`)); err != nil {
		t.Fatal(err)
	}
	if err := ValidateSealedArguments(sealedOperation, json.RawMessage(`{"input":{"encrypted_value":"YWJjZA==","key_id":"key-1"}}`)); err != nil {
		t.Fatal(err)
	}
	if err := ValidateArguments("repo.metadata.read", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	if err := ValidateStreamPublic("repo.download_zipball_archive", target, json.RawMessage(`{"ref":"main"}`)); err != nil {
		t.Fatal(err)
	}
	if err := ValidateResult("repo.metadata.read", json.RawMessage(`{"id":1,"name":"brokerkit"}`)); err != nil {
		t.Fatal(err)
	}
	if err := ValidateResult("artifact.actions_list_artifacts_for_repo", json.RawMessage(`{"artifacts":[{"id":1,"name":"build"}]}`)); err != nil {
		t.Fatalf("bounded container result rejected: %v", err)
	}
	if err := ValidateResult("issue.issues_update", json.RawMessage(`{"id":1,"state":"open"}`)); err != nil {
		t.Fatalf("composed projected result rejected: %v", err)
	}

	for name, call := range map[string]func() error{
		"public unknown": func() error { return ValidatePublicSubmission("repo.metadata.read", target, json.RawMessage(`{}`)) },
		"public target": func() error {
			return ValidatePublicSubmission(sealedOperation, json.RawMessage(`{}`), json.RawMessage(`{"secret_name":"x"}`))
		},
		"public arguments":  func() error { return ValidatePublicSubmission(sealedOperation, target, json.RawMessage(`{}`)) },
		"sealed unknown":    func() error { return ValidateSealedArguments("repo.metadata.read", json.RawMessage(`{}`)) },
		"sealed invalid":    func() error { return ValidateSealedArguments(sealedOperation, json.RawMessage(`{"input":{}}`)) },
		"arguments unknown": func() error { return ValidateArguments("not.real", json.RawMessage(`{}`)) },
		"arguments invalid": func() error { return ValidateArguments("repo.metadata.read", json.RawMessage(`{"extra":true}`)) },
		"stream unknown":    func() error { return ValidateStreamPublic("not.real", target, json.RawMessage(`{}`)) },
		"stream target": func() error {
			return ValidateStreamPublic("repo.download_zipball_archive", json.RawMessage(`{}`), json.RawMessage(`{"ref":"main"}`))
		},
		"stream arguments": func() error {
			return ValidateStreamPublic("repo.download_zipball_archive", target, json.RawMessage(`{}`))
		},
		"result unknown":   func() error { return ValidateResult("not.real", json.RawMessage(`{}`)) },
		"result invalid":   func() error { return ValidateResult("repo.metadata.read", json.RawMessage(`{"private":true}`)) },
		"result oversized": func() error { return ValidateResult("repo.metadata.read", bytes.Repeat([]byte(" "), (1<<20)+1)) },
	} {
		t.Run(name, func(t *testing.T) {
			if err := call(); err == nil {
				t.Fatal("invalid boundary input accepted")
			}
		})
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
