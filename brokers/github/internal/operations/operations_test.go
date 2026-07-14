package operations

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/osolmaz/brokerkit/brokers/github/internal/githubauth"
	"github.com/osolmaz/brokerkit/brokers/github/internal/opbinding"
	"github.com/osolmaz/brokerkit/brokers/github/internal/opcatalog"
	"github.com/osolmaz/brokerkit/capability"
	"github.com/osolmaz/brokerkit/credentialstore"
	"github.com/osolmaz/brokerkit/sealedstore"
	"github.com/osolmaz/brokerkit/streamstore"
)

func TestGeneratedRegistryCoversAgentFacingOperations(t *testing.T) {
	adapters, err := NewGeneratedAdapters(nil, newAdapterOptions(t))
	if err != nil {
		t.Fatal(err)
	}
	registry, err := NewRegistry(adapters...)
	if err != nil {
		t.Fatal(err)
	}
	if err := registry.ValidateCoverage(); err != nil {
		t.Fatal(err)
	}
	if _, found := registry.Lookup("app.get_authenticated"); found {
		t.Fatal("operator-only app operation was registered")
	}
	if _, found := registry.Lookup("repo.metadata.read"); !found {
		t.Fatal("implemented REST operation is missing")
	}
	if _, found := registry.Lookup("repo.read_repository"); found {
		t.Fatal("unbound persisted GraphQL operation was registered")
	}
}

func TestRESTAdapterRejectsEscapeHatchesAndExecutes(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/repos/osolmaz/brokerkit" || r.Header.Get("Authorization") != "Bearer dev-canary" {
			t.Fatalf("request = %s %s headers=%+v", r.Method, r.URL.String(), r.Header)
		}
		_, _ = w.Write([]byte(`{"id":1,"node_id":"R_1","name":"brokerkit","private":true}`))
	}))
	t.Cleanup(server.Close)
	adapter := mustLookupGenerated(t, newOperationsManager(t, server.URL), "repo.metadata.read")
	if _, err := adapter.Decode(json.RawMessage(`{"kind":"repo","owner":"osolmaz","name":"brokerkit"}`), json.RawMessage(`{"headers":{"x-test":"1"}}`)); err == nil {
		t.Fatal("raw escape hatch was accepted")
	}
	contents := mustLookupGenerated(t, newOperationsManager(t, server.URL), "repo.contents.read")
	if _, err := contents.Decode(json.RawMessage(`{"kind":"repo","owner":"osolmaz","name":"brokerkit"}`), json.RawMessage(`{"path":"README.md"}`)); err != nil {
		t.Fatalf("argument-owned path parameter was rejected: %v", err)
	}
	input, err := adapter.Decode(json.RawMessage(`{"kind":"repo","owner":"osolmaz","name":"brokerkit"}`), json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	plan, err := adapter.Resolve(context.Background(), input)
	if err != nil || plan.Credential.Kind != githubauth.KindDevelopmentToken || !slices.Equal(plan.Authorization.TargetFields["owner"], []string{"osolmaz"}) {
		t.Fatalf("plan = %+v err=%v", plan, err)
	}
	outcome, err := adapter.Execute(context.Background(), plan)
	if err != nil || !outcome.Proven || outcome.UpstreamStatus != http.StatusOK {
		t.Fatalf("execute = %+v err=%v", outcome, err)
	}
	assertJSONEqual(t, outcome.Result, `{"id":1,"node_id":"R_1","name":"brokerkit"}`)
}

func TestRepositoryContentsPreservesBoundedFileAndDirectoryResults(t *testing.T) {
	for name, response := range map[string]string{
		"file":      `{"type":"file","name":"README.md","path":"README.md","sha":"abc","encoding":"base64","content":"Y2FuYXJ5","url":"https://api.github.test/content"}`,
		"directory": `[{"type":"file","name":"README.md","path":"README.md","sha":"abc","url":"https://api.github.test/content"}]`,
	} {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
				if request.URL.Path != "/repos/osolmaz/brokerkit/contents/README.md" {
					t.Fatalf("path = %q", request.URL.Path)
				}
				_, _ = w.Write([]byte(response))
			}))
			t.Cleanup(server.Close)
			adapter := mustLookupGenerated(t, newOperationsManager(t, server.URL), "repo.contents.read")
			input, err := adapter.Decode(json.RawMessage(`{"kind":"repo","owner":"osolmaz","name":"brokerkit"}`), json.RawMessage(`{"path":"README.md"}`))
			if err != nil {
				t.Fatal(err)
			}
			plan, err := adapter.Resolve(t.Context(), input)
			if err != nil {
				t.Fatal(err)
			}
			outcome, err := adapter.Execute(t.Context(), plan)
			if err != nil || !outcome.Proven || !bytes.Contains(outcome.Result, []byte(`"path":"README.md"`)) {
				t.Fatalf("outcome = %s err = %v", outcome.Result, err)
			}
			if name == "file" && !bytes.Contains(outcome.Result, []byte(`"content":"Y2FuYXJ5"`)) {
				t.Fatalf("file content was projected out: %s", outcome.Result)
			}
		})
	}
}

func TestGraphQLOperationsRequireReviewedTargetBindings(t *testing.T) {
	descriptor, found := opcatalog.ByName("repo.read_repository")
	if !found || descriptor.AgentFacing || descriptor.Implementation != capability.StatusOperatorOnly || descriptor.MCPTool != nil || descriptor.CLICommand != nil {
		t.Fatalf("GraphQL descriptor is exposed before target binding review: %+v", descriptor)
	}
	adapters, err := NewGeneratedAdapters(newOperationsManager(t, "http://127.0.0.1"), newAdapterOptions(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, adapter := range adapters {
		if adapter.Descriptor().Name == descriptor.Name {
			t.Fatal("GraphQL adapter is registered before target binding review")
		}
	}
}

func TestGeneratedUserIdentityValidationAppliesOnlyToSelfTargets(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.Method != http.MethodGet || r.URL.Path != "/user" {
			t.Fatalf("identity request = %s %s", r.Method, r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"id":7,"login":"osolmaz"}`))
	}))
	t.Cleanup(server.Close)
	manager := newOperationsManager(t, server.URL)

	block := mustLookupGenerated(t, manager, "member.users_block")
	input, err := block.Decode(json.RawMessage(`{"kind":"user","name":"octocat"}`), json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := block.Resolve(t.Context(), input); err != nil || requests != 0 {
		t.Fatalf("explicit user Resolve() requests=%d err=%v", requests, err)
	}

	self := mustLookupGenerated(t, manager, "member.users_get_authenticated")
	input, err = self.Decode(json.RawMessage(`{"kind":"user","name":"osolmaz"}`), json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := self.Resolve(t.Context(), input); err != nil || requests != 1 {
		t.Fatalf("self user Resolve() requests=%d err=%v", requests, err)
	}
}

func TestGeneratedAdapterLifecycleMetadata(t *testing.T) {
	adapter := mustLookupGenerated(t, newOperationsManager(t, "http://127.0.0.1"), "pull_request.create")
	input, err := adapter.Decode(json.RawMessage(`{"kind":"repo","owner":"osolmaz","name":"brokerkit"}`),
		json.RawMessage(`{"input":{"title":"Cutover","head":"agent/work","base":"main"}}`))
	if err != nil {
		t.Fatal(err)
	}
	plan, err := adapter.Resolve(t.Context(), input)
	if err != nil {
		t.Fatal(err)
	}
	authorization := adapter.Authorize(plan)
	presentation := adapter.Present(plan)
	if authorization.Operation != "pull_request.create" || !slices.Equal(authorization.TargetFields["owner"], []string{"osolmaz"}) ||
		!slices.Equal(authorization.Attrs["head_ref"], []string{"agent/work"}) || presentation.Title == "" {
		t.Fatalf("authorization = %+v presentation = %+v", authorization, presentation)
	}
	if err := adapter.(PlanCleaner).Cleanup(plan); err != nil {
		t.Fatal(err)
	}

	plan.Authorization = Authorization{}
	plan.Presentation.Title = ""
	if got := adapter.Authorize(plan); got.Operation != "pull_request.create" || got.CredentialKind != string(githubauth.KindInstallation) {
		t.Fatalf("derived authorization = %+v", got)
	}
	if got := adapter.Present(plan); got.Title == "" || !strings.Contains(got.Summary, "osolmaz/brokerkit") {
		t.Fatalf("derived presentation = %+v", got)
	}
	metadata, err := CredentialFromPreconditions(plan.Preconditions)
	if err != nil || metadata.Kind != githubauth.KindDevelopmentToken {
		t.Fatalf("credential preconditions = %+v, %v", metadata, err)
	}
	for _, invalid := range []json.RawMessage{json.RawMessage(`{}`), json.RawMessage(`{"kind":"development-token","kind":"user"}`), json.RawMessage(`{`)} {
		if _, err := CredentialFromPreconditions(invalid); err == nil {
			t.Fatalf("invalid credential preconditions accepted: %s", invalid)
		}
	}
}

func TestGeneratedAdapterHelpersFailClosed(t *testing.T) {
	descriptor := opcatalog.Descriptor{Descriptor: capability.Descriptor{Name: "test.operation", Summary: "Test operation", TargetKind: "issue",
		CredentialKind: string(githubauth.KindInstallation), AgentFacing: true, Implementation: capability.StatusImplemented, ExecutorKind: "rest-binding"}}
	if summary := targetSummary("repo", map[string]any{"owner": "osolmaz", "name": "brokerkit"}); summary != "osolmaz/brokerkit" {
		t.Fatalf("repo summary = %q", summary)
	}
	for _, test := range []struct {
		target map[string]any
		want   string
	}{{map[string]any{"name": "triage"}, "issue triage"}, {map[string]any{"number": float64(7)}, "issue #7"},
		{map[string]any{"id": json.Number("9")}, "issue 9"}, {map[string]any{}, "issue"}} {
		if got := targetSummary("issue", test.target); got != test.want {
			t.Fatalf("target summary = %q, want %q", got, test.want)
		}
	}
	presentation := presentDescriptor(descriptor, map[string]any{"number": float64(7)})
	authorization := authorizeDescriptor(descriptor, nil, map[string]any{"owner": "osolmaz", "name": "brokerkit", "id": float64(3)},
		map[string]any{"ref": "main", "input": map[string]any{"base": "main", "head": "feature", "merge_method": "squash",
			"labels": []any{"bug", "urgent"}, "permission": "maintain"}})
	if presentation.Title != "Test operation" || !slices.Equal(authorization.TargetFields["id"], []string{"3"}) ||
		!slices.Equal(authorization.Attrs["base_ref"], []string{"main"}) {
		t.Fatalf("presentation = %+v authorization = %+v", presentation, authorization)
	}
	if !slices.Equal(authorization.Attrs["label"], []string{"bug", "urgent"}) ||
		!slices.Equal(authorization.Attrs["merge_method"], []string{"squash"}) ||
		!slices.Equal(authorization.Attrs["permission"], []string{"maintain"}) {
		t.Fatalf("nested authorization attrs = %+v", authorization.Attrs)
	}
	if fields := authorizationTargetFields(map[string]any{}); fields != nil {
		t.Fatalf("empty target fields = %+v", fields)
	}
	if attrs := authorizationAttrs(map[string]any{}); attrs != nil {
		t.Fatalf("empty attrs = %+v", attrs)
	}
	if object, err := decodeObject(json.RawMessage(`null`)); err != nil || len(object) != 0 {
		t.Fatalf("null object = %+v, %v", object, err)
	}
	if _, err := decodeObject(json.RawMessage(`{`)); err == nil {
		t.Fatal("invalid object accepted")
	}
	if cloneRaw(nil) != nil || string(cloneRaw(json.RawMessage(`{"a":1}`))) != `{"a":1}` {
		t.Fatal("raw clone changed")
	}

	if !shouldHaveAdapter(descriptor) {
		t.Fatal("implemented REST adapter excluded")
	}
	descriptor.AgentFacing = false
	if shouldHaveAdapter(descriptor) {
		t.Fatal("internal adapter included")
	}
	descriptor.AgentFacing = true
	descriptor.ExecutorKind = "unknown"
	if shouldHaveAdapter(descriptor) {
		t.Fatal("unknown executor included")
	}

	for _, err := range []error{githubauth.APIError{Code: "validation_failed", StatusCode: 422}, githubauth.APIError{Code: "unavailable"}, context.Canceled} {
		classified := classifyExecutionError(http.MethodPost, err)
		if classified == nil {
			t.Fatal("execution error disappeared")
		}
	}
}

func TestAuthorizationAttrsCoverClosedPolicyVocabulary(t *testing.T) {
	attrs := authorizationAttrs(map[string]any{"input": map[string]any{
		"actorId": json.Number("1"), "actorLogin": "alice", "base": "main", "environmentName": "production", "head": "feature",
		"name": "brokerkit-next", "owner": "osolmaz",
		"labels": []any{"bug", "urgent"}, "mergeMethod": "squash", "paths": []any{"README.md", "docs/guide.md"},
		"permission": "maintain", "ref": "refs/heads/main", "releaseState": "draft", "resourceId": "R_1", "role": "admin",
		"visibility": "private", "workflow": "ci", "workflowRef": "ci.yml@main",
	}})
	want := map[string][]string{
		"actor_id": {"1"}, "actor_login": {"alice"}, "base_ref": {"main"}, "environment": {"production"},
		"head_ref": {"feature"}, "label": {"bug", "urgent"}, "merge_method": {"squash"},
		"path": {"README.md", "docs/guide.md"}, "permission": {"maintain"}, "ref": {"refs/heads/main"},
		"release_state": {"draft"}, "resource_id": {"R_1"}, "role": {"admin"}, "visibility": {"private"},
		"workflow": {"ci"}, "workflow_ref": {"ci.yml@main"}, "resource_name": {"brokerkit-next"}, "resource_owner": {"osolmaz"},
	}
	if !maps.EqualFunc(attrs, want, slices.Equal) {
		t.Fatalf("authorization attrs = %+v, want %+v", attrs, want)
	}
	if values := scalarStrings(map[string]any{"not": "scalar"}); values != nil {
		t.Fatalf("object scalar values = %+v", values)
	}
}

func TestAuthorizationBindsConcretePathSelectors(t *testing.T) {
	binding := opbinding.ByOperation("collaborator.orgs_remove_outside_collaborator")
	if len(binding) != 1 {
		t.Fatalf("bindings = %+v", binding)
	}
	descriptor, found := opcatalog.ByName("collaborator.orgs_remove_outside_collaborator")
	if !found {
		t.Fatal("descriptor not found")
	}
	authorization := authorizeDescriptor(descriptor, &binding[0], map[string]any{"name": "acme"}, map[string]any{"username": "octocat"})
	if !slices.Equal(authorization.Attrs["selector_username"], []string{"octocat"}) {
		t.Fatalf("authorization = %+v", authorization)
	}
}

func TestGeneratedAdapterConstructionRequiresProtectedStores(t *testing.T) {
	if _, err := NewGeneratedAdapters(nil, Options{}); err == nil || !strings.Contains(err.Error(), "store") {
		t.Fatalf("missing protected stores error = %v", err)
	}
	registry, err := NewRegistry()
	if err != nil {
		t.Fatal(err)
	}
	if coverageErr := registry.ValidateCoverage(); coverageErr == nil {
		t.Fatal("empty registry passed coverage validation")
	}
}

func TestGeneratedAdapterCleanupAndInvalidStoredPlans(t *testing.T) {
	options := newAdapterOptions(t)
	manager := newOperationsManager(t, "http://127.0.0.1")
	adapters, err := NewGeneratedAdapters(manager, options)
	if err != nil {
		t.Fatal(err)
	}
	registry, _ := NewRegistry(adapters...)

	sealedReference, err := options.SealedStore.(*sealedstore.Store).PutForRequest("bob", "workflow.actions_create_or_update_repo_secret", "cleanup-secret",
		[]byte(`{"input":{"encrypted_value":"Y2FuYXJ5","key_id":"key-1"}}`), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	sealedAdapter, _ := registry.Lookup("workflow.actions_create_or_update_repo_secret")
	sealedWrapper, _ := json.Marshal(map[string]any{"public": json.RawMessage(`{"secret_name":"TOKEN"}`), "sealed_payload": sealedReference})
	sealedInput, err := sealedAdapter.Decode(json.RawMessage(`{"kind":"repo","owner":"osolmaz","name":"brokerkit"}`), sealedWrapper)
	if err != nil {
		t.Fatal(err)
	}
	sealedPlan, err := sealedAdapter.Resolve(t.Context(), sealedInput)
	if err != nil || sealedAdapter.(PlanCleaner).Cleanup(sealedPlan) != nil {
		t.Fatalf("sealed cleanup plan = %+v, %v", sealedPlan, err)
	}
	if options.SealedStore.Validate(sealedReference) == nil {
		t.Fatal("sealed cleanup retained payload")
	}

	streamReference, err := options.StreamStore.(*streamstore.Store).Put("bob", "release.repos_upload_release_asset", "cleanup-stream",
		"application/octet-stream", strings.NewReader("asset"), 16, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	streamAdapter, _ := registry.Lookup("release.repos_upload_release_asset")
	streamWrapper, _ := json.Marshal(map[string]any{"public": json.RawMessage(`{"name":"asset.bin"}`), "stream_input": streamReference})
	streamInput, err := streamAdapter.Decode(json.RawMessage(`{"kind":"release","id":9,"owner":"osolmaz","repo":"brokerkit"}`), streamWrapper)
	if err != nil {
		t.Fatal(err)
	}
	streamPlan, err := streamAdapter.Resolve(t.Context(), streamInput)
	if err != nil || streamAdapter.(PlanCleaner).Cleanup(streamPlan) != nil {
		t.Fatalf("stream cleanup plan = %+v, %v", streamPlan, err)
	}
	if options.StreamStore.Validate(streamReference) == nil {
		t.Fatal("stream cleanup retained input")
	}

	restAdapter := mustLookupGenerated(t, manager, "repo.metadata.read").(generatedAdapter)
	if _, err := restAdapter.Execute(t.Context(), Plan{Target: json.RawMessage(`{`)}); err == nil {
		t.Fatal("invalid stored target executed")
	}
	if _, err := restAdapter.Execute(t.Context(), Plan{Target: json.RawMessage(`{"owner":"o","name":"r"}`), Arguments: json.RawMessage(`{`)}); err == nil {
		t.Fatal("invalid stored arguments executed")
	}
	deleteAdapter := mustLookupGenerated(t, manager, "repo.delete").(generatedAdapter)
	if _, err := deleteAdapter.Reconcile(t.Context(), Plan{Target: json.RawMessage(`{`)}); err == nil {
		t.Fatal("invalid reconciliation target accepted")
	}
	if _, err := sealedAdapter.(generatedAdapter).publicArguments(json.RawMessage(`{`)); err == nil {
		t.Fatal("invalid public arguments accepted")
	}
}

func TestMutationExecuteClassifiesAmbiguousFailuresWithoutRetry(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/repos/osolmaz/brokerkit/pulls" {
			t.Fatalf("request = %s %s", r.Method, r.URL.String())
		}
		http.Error(w, "upstream failure", http.StatusBadGateway)
	}))
	t.Cleanup(server.Close)
	adapter := mustLookupGenerated(t, newOperationsManager(t, server.URL), "pull_request.create")
	input, err := adapter.Decode(
		json.RawMessage(`{"kind":"repo","owner":"osolmaz","name":"brokerkit"}`),
		json.RawMessage(`{"input":{"title":"Agent cutover","head":"feature","base":"main"}}`),
	)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := adapter.Resolve(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := adapter.Execute(context.Background(), plan); !IsPossiblePartial(err) {
		t.Fatalf("execute error = %v", err)
	}
	if outcome, err := adapter.Reconcile(context.Background(), plan); err != nil || outcome.Proven {
		t.Fatalf("reconcile = %+v err=%v", outcome, err)
	}
}

func TestResolveVerifiesUnboundImmutableTargetIdentity(t *testing.T) {
	var mutations int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/repos/osolmaz/brokerkit/issues/7" {
			t.Fatalf("request path = %s", request.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		switch request.Method {
		case http.MethodGet:
			_, _ = io.WriteString(w, `{"id":99,"node_id":"I_99","number":7,"state":"open","url":"https://api.github.test/issues/7"}`)
		case http.MethodPatch:
			mutations++
			_, _ = io.WriteString(w, `{"id":99,"node_id":"I_99","number":7,"state":"closed","url":"https://api.github.test/issues/7"}`)
		default:
			t.Fatalf("request method = %s", request.Method)
		}
	}))
	t.Cleanup(server.Close)
	adapter := mustLookupGenerated(t, newOperationsManager(t, server.URL), "issue.issues_update")
	arguments := json.RawMessage(`{"input":{"state":"closed"}}`)
	spoofed, err := adapter.Decode(json.RawMessage(`{"kind":"issue","owner":"osolmaz","repo":"brokerkit","number":7,"id":98,"node_id":"I_99"}`), arguments)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := adapter.Resolve(t.Context(), spoofed); err == nil {
		t.Fatal("spoofed immutable target identity was authorized")
	}
	verified, err := adapter.Decode(json.RawMessage(`{"kind":"issue","owner":"osolmaz","repo":"brokerkit","number":7,"id":99,"node_id":"I_99"}`), arguments)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := adapter.Resolve(t.Context(), verified)
	if err != nil || !slices.Equal(plan.Authorization.TargetFields["id"], []string{"99"}) ||
		!slices.Equal(plan.Authorization.TargetFields["node_id"], []string{"I_99"}) {
		t.Fatalf("verified plan = %+v, %v", plan, err)
	}
	if _, err := adapter.Execute(t.Context(), plan); err != nil || mutations != 1 {
		t.Fatalf("verified execution mutations = %d, %v", mutations, err)
	}
}

func TestOptionalSealedArgumentsExecuteWithoutPayloadReference(t *testing.T) {
	adapter := mustLookupGenerated(t, newOperationsManager(t, "http://127.0.0.1:1"), "organization.update_webhook")
	input, err := adapter.Decode(json.RawMessage(`{"kind":"organization","name":"osolmaz"}`), json.RawMessage(`{"public":{"hook_id":1}}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := adapter.(ClientBoundAdapter).ValidateClient(input, "bob", "optional-secret"); err != nil {
		t.Fatalf("optional sealed input validation = %v", err)
	}
	plan, err := adapter.Resolve(t.Context(), input)
	if err != nil || string(plan.Arguments) != `{"public":{"hook_id":1}}` {
		t.Fatalf("optional sealed plan = %+v, %v", plan, err)
	}
	required := mustLookupGenerated(t, newOperationsManager(t, "http://127.0.0.1:1"), "workflow.actions_create_or_update_repo_secret").(generatedAdapter)
	if err := required.validateSealedEnvelope(sealedArguments{}); err == nil {
		t.Fatal("required sealed envelope accepted without a payload")
	}
	credential := mustLookupGenerated(t, newOperationsManager(t, "http://127.0.0.1:1"), "runner.actions_create_registration_token_for_repo").(generatedAdapter)
	if err := credential.validateSealedEnvelope(sealedArguments{CredentialSlot: "invalid/slot"}); err == nil {
		t.Fatal("invalid credential destination accepted")
	}
}

func TestDocumentedAcceptedMutationIsSuccessful(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/repos/osolmaz/brokerkit/deployments" {
			t.Fatalf("request = %s %s", r.Method, r.URL.Path)
		}
		w.WriteHeader(http.StatusAccepted)
		_, _ = io.WriteString(w, `{"id":7}`)
	}))
	t.Cleanup(server.Close)
	adapter := mustLookupGenerated(t, newOperationsManager(t, server.URL), "deployment.repos_create_deployment")
	input, err := adapter.Decode(json.RawMessage(`{"kind":"repo","owner":"osolmaz","name":"brokerkit"}`), json.RawMessage(`{"input":{"ref":"main"}}`))
	if err != nil {
		t.Fatal(err)
	}
	plan, err := adapter.Resolve(t.Context(), input)
	if err != nil {
		t.Fatal(err)
	}
	outcome, err := adapter.Execute(t.Context(), plan)
	if err != nil || !outcome.Proven || outcome.UpstreamStatus != http.StatusAccepted || !strings.Contains(string(outcome.Result), `"id":7`) {
		t.Fatalf("outcome = %+v, err = %v", outcome, err)
	}
}

func TestExecutionStatusRejectsUndocumentedOutcomes(t *testing.T) {
	for _, test := range []struct {
		name        string
		method      string
		status      int
		wantPartial bool
		wantError   bool
	}{
		{name: "documented", method: http.MethodPost, status: 202},
		{name: "mutation", method: http.MethodPost, status: 299, wantPartial: true, wantError: true},
		{name: "read", method: http.MethodGet, status: 299, wantError: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := executionStatusError(opbinding.Binding{Method: test.method, SuccessStatusCodes: []int{202}}, test.status)
			if (err != nil) != test.wantError || IsPossiblePartial(err) != test.wantPartial {
				t.Fatalf("error = %v, partial = %t", err, IsPossiblePartial(err))
			}
		})
	}
}

func TestMutationResponseValidationFailureRequiresReconciliation(t *testing.T) {
	mutationErr := classifyResponseValidationError(http.MethodPost, errors.New("invalid projected response"))
	if !IsPossiblePartial(mutationErr) {
		t.Fatalf("mutation validation error = %v", mutationErr)
	}
	readErr := classifyResponseValidationError(http.MethodGet, errors.New("invalid projected response"))
	if IsPossiblePartial(readErr) {
		t.Fatalf("read validation error = %v", readErr)
	}
}

func TestRepositoryDeletionReconcilesByAbsenceWithoutReplay(t *testing.T) {
	for _, test := range []struct {
		name       string
		status     int
		wantProven bool
	}{
		{name: "absent", status: http.StatusNotFound, wantProven: true},
		{name: "still present", status: http.StatusOK, wantProven: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			var methods []string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
				methods = append(methods, request.Method)
				if request.Method != http.MethodGet || request.URL.Path != "/repos/osolmaz/disposable" {
					t.Fatalf("reconciliation request = %s %s", request.Method, request.URL.Path)
				}
				w.WriteHeader(test.status)
				if test.status == http.StatusOK {
					_, _ = w.Write([]byte(`{"id":1,"node_id":"R_1","name":"disposable"}`))
				}
			}))
			t.Cleanup(server.Close)
			adapter := mustLookupGenerated(t, newOperationsManager(t, server.URL), "repo.delete")
			input, err := adapter.Decode(json.RawMessage(`{"kind":"repo","owner":"osolmaz","name":"disposable"}`), json.RawMessage(`{}`))
			if err != nil {
				t.Fatal(err)
			}
			plan, err := adapter.Resolve(context.Background(), input)
			if err != nil {
				t.Fatal(err)
			}
			outcome, err := adapter.Reconcile(context.Background(), plan)
			if err != nil || outcome.Proven != test.wantProven {
				t.Fatalf("reconcile = %+v err=%v", outcome, err)
			}
			if len(methods) != 1 || methods[0] != http.MethodGet {
				t.Fatalf("reconciliation methods = %v", methods)
			}
		})
	}
}

func TestSealedAdapterConsumesBoundPayloadWithoutPersistingSecret(t *testing.T) {
	const secret = "ZW5jcnlwdGVkLWNhbmFyeS12YWx1ZQ=="
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPut || request.URL.Path != "/repos/osolmaz/brokerkit/actions/secrets/DEPLOY_TOKEN" {
			t.Fatalf("request = %s %s", request.Method, request.URL.Path)
		}
		body, err := io.ReadAll(request.Body)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(body), secret) || !strings.Contains(string(body), `"key_id":"key-1"`) {
			t.Fatalf("request body = %s", body)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(server.Close)
	store := newSealedStore(t)
	reference, err := store.PutForRequest("bob", "workflow.actions_create_or_update_repo_secret", "secret-request",
		[]byte(`{"input":{"encrypted_value":"`+secret+`","key_id":"key-1"}}`), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	options := newAdapterOptions(t)
	options.SealedStore = store
	adapters, err := NewGeneratedAdapters(newOperationsManager(t, server.URL), options)
	if err != nil {
		t.Fatal(err)
	}
	registry, err := NewRegistry(adapters...)
	if err != nil {
		t.Fatal(err)
	}
	adapter, found := registry.Lookup("workflow.actions_create_or_update_repo_secret")
	if !found {
		t.Fatal("sealed adapter not found")
	}
	wrapper, _ := json.Marshal(map[string]any{
		"public":         json.RawMessage(`{"secret_name":"DEPLOY_TOKEN"}`),
		"sealed_payload": reference,
	})
	input, err := adapter.Decode(json.RawMessage(`{"kind":"repo","owner":"osolmaz","name":"brokerkit"}`), wrapper)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(input.Arguments), secret) {
		t.Fatal("secret was retained in decoded arguments")
	}
	bound := adapter.(ClientBoundAdapter)
	if err := bound.ValidateClient(input, "bob", "secret-request"); err != nil {
		t.Fatal(err)
	}
	if err := bound.ValidateClient(input, "alice", "secret-request"); err == nil {
		t.Fatal("accepted another client's sealed payload")
	}
	plan, err := adapter.Resolve(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(plan.Arguments), secret) {
		t.Fatal("secret was retained in the immutable plan")
	}
	outcome, err := adapter.Execute(context.Background(), plan)
	if err != nil || !outcome.Proven || outcome.UpstreamStatus != http.StatusNoContent {
		t.Fatalf("execute = %+v err=%v", outcome, err)
	}
	if _, err := store.Consume(reference); err == nil {
		t.Fatal("sealed payload was reusable")
	}
}

func TestCredentialOutputAdapterStoresRunnerTokenWithoutReadback(t *testing.T) {
	const token = "runner-token-canary"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.Path != "/repos/osolmaz/brokerkit/actions/runners/registration-token" {
			t.Fatalf("request = %s %s", request.Method, request.URL.Path)
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"token":"` + token + `","expires_at":"2026-07-14T12:00:00Z"}`))
	}))
	t.Cleanup(server.Close)
	credentials, err := credentialstore.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	options := newAdapterOptions(t)
	options.CredentialStore = credentials
	adapters, err := NewGeneratedAdapters(newOperationsManager(t, server.URL), options)
	if err != nil {
		t.Fatal(err)
	}
	registry, _ := NewRegistry(adapters...)
	adapter, found := registry.Lookup("runner.actions_create_registration_token_for_repo")
	if !found {
		t.Fatal("runner token adapter not found")
	}
	input, err := adapter.Decode(json.RawMessage(`{"kind":"repo","owner":"osolmaz","name":"brokerkit"}`),
		json.RawMessage(`{"public":{},"credential_slot":"ci-runner"}`))
	if err != nil {
		t.Fatal(err)
	}
	plan, err := adapter.Resolve(context.Background(), input)
	if err != nil || !strings.Contains(plan.Presentation.Summary, "ci-runner") {
		t.Fatalf("plan = %+v err = %v", plan, err)
	}
	outcome, err := adapter.Execute(context.Background(), plan)
	if err != nil || !outcome.Proven || outcome.UpstreamStatus != http.StatusCreated || strings.Contains(string(outcome.Result), token) {
		t.Fatalf("outcome = %+v err = %v", outcome, err)
	}
	stored, metadata, err := credentials.Get("ci-runner", "github-runner-token")
	if err != nil || string(stored) != token || metadata.Slot != "ci-runner" {
		t.Fatalf("stored = %q metadata = %+v err = %v", stored, metadata, err)
	}
}

func TestStreamUploadExecutesFromBoundPrivateFile(t *testing.T) {
	const content = "release-asset-canary"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.Path != "/repos/osolmaz/brokerkit/releases/9/assets" ||
			request.Header.Get("Content-Type") != "application/octet-stream" {
			t.Fatalf("request = %s %s query=%s headers=%v", request.Method, request.URL.Path, request.URL.RawQuery, request.Header)
		}
		body, _ := io.ReadAll(request.Body)
		if string(body) != content {
			t.Fatalf("body = %q", body)
		}
		w.WriteHeader(http.StatusCreated)
		if request.URL.Query().Get("name") == "malformed.bin" {
			_, _ = w.Write([]byte(`{"id":"not-an-integer"}`))
			return
		}
		if request.URL.Query().Get("name") != "artifact.bin" {
			t.Fatalf("asset name = %q", request.URL.Query().Get("name"))
		}
		_, _ = w.Write([]byte(`{"id":10,"node_id":"asset-10","name":"artifact.bin","state":"uploaded","url":"https://api.github.test/assets/10"}`))
	}))
	t.Cleanup(server.Close)
	streams, _ := streamstore.Open(t.TempDir())
	reference, err := streams.Put("bob", "release.repos_upload_release_asset", "asset-request", "application/octet-stream",
		strings.NewReader(content), 1024, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	options := newAdapterOptions(t)
	options.StreamStore = streams
	adapters, err := NewGeneratedAdapters(newOperationsManager(t, server.URL), options)
	if err != nil {
		t.Fatal(err)
	}
	registry, _ := NewRegistry(adapters...)
	adapter, _ := registry.Lookup("release.repos_upload_release_asset")
	streamAdapter := adapter.(generatedAdapter)
	if _, err := streamAdapter.executeStreamUpload(t.Context(), Plan{Arguments: json.RawMessage(`{}`)}, nil); err == nil {
		t.Fatal("invalid stream upload plan executed")
	}
	wrapper, _ := json.Marshal(map[string]any{"public": json.RawMessage(`{"name":"artifact.bin"}`), "stream_input": reference})
	input, err := adapter.Decode(json.RawMessage(`{"kind":"release","id":9,"owner":"osolmaz","repo":"brokerkit"}`), wrapper)
	if err != nil {
		t.Fatal(err)
	}
	if err := adapter.(ClientBoundAdapter).ValidateClient(input, "bob", "asset-request"); err != nil {
		t.Fatal(err)
	}
	plan, err := adapter.Resolve(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	plan.Authorization.Client = "bob"
	outcome, err := adapter.Execute(context.Background(), plan)
	if err != nil || !outcome.Proven || outcome.UpstreamStatus != http.StatusCreated {
		t.Fatalf("outcome = %+v err = %v", outcome, err)
	}
	if streams.Validate(reference) != nil {
		t.Fatal("upload stream was removed before terminal cleanup")
	}
	if err := adapter.(PlanCleaner).Cleanup(plan); err != nil || streams.Validate(reference) == nil {
		t.Fatalf("terminal upload cleanup = %v", err)
	}
	replayed, err := streams.Put("bob", "release.repos_upload_release_asset", "asset-request", "application/octet-stream",
		strings.NewReader(content), 1024, time.Now().Add(time.Hour))
	if err != nil || replayed != reference {
		t.Fatalf("terminal upload replay = %+v, %v; want %+v", replayed, err, reference)
	}
	invalidReference, err := streams.Put("bob", "release.repos_upload_release_asset", "asset-invalid", "application/octet-stream",
		strings.NewReader(content), 1024, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	invalidWrapper, _ := json.Marshal(map[string]any{"public": json.RawMessage(`{"name":"malformed.bin"}`), "stream_input": invalidReference})
	invalidInput, err := adapter.Decode(json.RawMessage(`{"kind":"release","id":9,"owner":"osolmaz","repo":"brokerkit"}`), invalidWrapper)
	if err != nil {
		t.Fatal(err)
	}
	invalidPlan, err := adapter.Resolve(t.Context(), invalidInput)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := adapter.Execute(t.Context(), invalidPlan); !IsPossiblePartial(err) {
		t.Fatalf("invalid successful upload response = %v", err)
	}
}

func TestStreamDownloadStoresBoundedResultForOwner(t *testing.T) {
	content := bytes.Repeat([]byte("archive-canary"), 64)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet || request.URL.Path != "/repos/osolmaz/brokerkit/zipball/main" || request.Header.Get("Accept") != "application/octet-stream" {
			t.Fatalf("request = %s %s headers=%v", request.Method, request.URL.Path, request.Header)
		}
		w.Header().Set("Content-Type", "application/zip")
		_, _ = w.Write(content)
	}))
	t.Cleanup(server.Close)
	streams, _ := streamstore.Open(t.TempDir())
	options := newAdapterOptions(t)
	options.StreamStore = streams
	adapters, _ := NewGeneratedAdapters(newOperationsManager(t, server.URL), options)
	registry, _ := NewRegistry(adapters...)
	adapter, _ := registry.Lookup("repo.download_zipball_archive")
	input, err := adapter.Decode(json.RawMessage(`{"kind":"repo","owner":"osolmaz","name":"brokerkit"}`), json.RawMessage(`{"ref":"main"}`))
	if err != nil {
		t.Fatal(err)
	}
	plan, err := adapter.Resolve(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	plan.Authorization.Client = "bob"
	plan.ExecutionID = "operation-1"
	outcome, err := adapter.Execute(context.Background(), plan)
	if err != nil || !outcome.Proven || outcome.UpstreamStatus != http.StatusOK || bytes.Contains(outcome.Result, content[:32]) {
		t.Fatalf("outcome = %s err = %v", outcome.Result, err)
	}
	var result struct {
		Stream streamstore.Reference `json:"stream"`
	}
	if json.Unmarshal(outcome.Result, &result) != nil || result.Stream.Owner != "bob" || result.Stream.MediaType != "application/zip" {
		t.Fatalf("stream result = %+v", result)
	}
	file, err := streams.OpenStream(result.Stream)
	if err != nil {
		t.Fatal(err)
	}
	stored, _ := io.ReadAll(file)
	_ = file.Close()
	if !bytes.Equal(stored, content) {
		t.Fatal("download stream content drifted")
	}
	plan.ExecutionID = "operation-2"
	second, err := adapter.Execute(context.Background(), plan)
	if err != nil || !second.Proven {
		t.Fatalf("second outcome = %s err = %v", second.Result, err)
	}
	var secondResult struct {
		Stream streamstore.Reference `json:"stream"`
	}
	if json.Unmarshal(second.Result, &secondResult) != nil || secondResult.Stream.ID == result.Stream.ID {
		t.Fatalf("second stream = %+v, want a distinct execution result", secondResult.Stream)
	}
}

func newOperationsManager(t *testing.T, base string) *githubauth.Manager {
	t.Helper()
	apiURL, err := url.Parse(base)
	if err != nil {
		t.Fatal(err)
	}
	manager, err := githubauth.New(githubauth.Config{
		DevelopmentToken:     []byte("dev-canary"),
		DevelopmentTokenFile: "/tmp/dev-canary",
		APIBaseURL:           apiURL,
		WebBaseURL:           apiURL,
		HTTPClient:           serverClient(base),
	})
	if err != nil {
		t.Fatal(err)
	}
	return manager
}

func serverClient(_ string) *http.Client {
	return &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func mustLookupGenerated(t *testing.T, manager *githubauth.Manager, name string) Adapter {
	t.Helper()
	adapters, err := NewGeneratedAdapters(manager, newAdapterOptions(t))
	if err != nil {
		t.Fatal(err)
	}
	registry, err := NewRegistry(adapters...)
	if err != nil {
		t.Fatal(err)
	}
	adapter, found := registry.Lookup(name)
	if !found {
		t.Fatalf("adapter %q not found", name)
	}
	return adapter
}

func newSealedStore(t *testing.T) *sealedstore.Store {
	t.Helper()
	store, err := sealedstore.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func newAdapterOptions(t *testing.T) Options {
	t.Helper()
	credentials, err := credentialstore.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	streams, err := streamstore.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return Options{SealedStore: newSealedStore(t), CredentialStore: credentials, StreamStore: streams}
}

func assertJSONEqual(t *testing.T, raw json.RawMessage, expected string) {
	t.Helper()
	var gotValue, wantValue any
	if err := json.Unmarshal(raw, &gotValue); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(expected), &wantValue); err != nil {
		t.Fatal(err)
	}
	gotJSON, _ := json.Marshal(gotValue)
	wantJSON, _ := json.Marshal(wantValue)
	if string(gotJSON) != string(wantJSON) {
		t.Fatalf("json = %s, want %s", gotJSON, wantJSON)
	}
}
