package operations

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/osolmaz/brokerkit/brokers/github/internal/githubauth"
	"github.com/osolmaz/brokerkit/credentialstore"
	"github.com/osolmaz/brokerkit/sealedstore"
)

func TestGeneratedRegistryCoversAgentFacingRESTAndGraphQL(t *testing.T) {
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
	if _, found := registry.Lookup("repo.read_repository"); !found {
		t.Fatal("persisted GraphQL operation is missing")
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
	if err != nil || plan.Credential.Kind != githubauth.KindDevelopmentToken || plan.Authorization.TargetFields["owner"] != "osolmaz" {
		t.Fatalf("plan = %+v err=%v", plan, err)
	}
	outcome, err := adapter.Execute(context.Background(), plan)
	if err != nil || !outcome.Proven {
		t.Fatalf("execute = %+v err=%v", outcome, err)
	}
	assertJSONEqual(t, outcome.Result, `{"id":1,"node_id":"R_1","name":"brokerkit"}`)
}

func TestGraphQLAdapterExecutesPersistedDocument(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/graphql" {
			t.Fatalf("request = %s %s", r.Method, r.URL.String())
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if _, ok := body["query"].(string); !ok || body["operationName"] == "" {
			t.Fatalf("graphql body = %#v", body)
		}
		_, _ = w.Write([]byte(`{"data":{"repository":{"__typename":"Repository"}}}`))
	}))
	t.Cleanup(server.Close)
	adapter := mustLookupGenerated(t, newOperationsManager(t, server.URL), "repo.read_repository")
	input, err := adapter.Decode(json.RawMessage(`{"kind":"repo","owner":"osolmaz","name":"brokerkit"}`), json.RawMessage(`{"owner":"osolmaz","name":"brokerkit"}`))
	if err != nil {
		t.Fatal(err)
	}
	plan, err := adapter.Resolve(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	outcome, err := adapter.Execute(context.Background(), plan)
	if err != nil || !outcome.Proven || !strings.Contains(string(outcome.Result), "Repository") {
		t.Fatalf("execute = %+v err=%v", outcome, err)
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
	if err != nil || !outcome.Proven {
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
	if err != nil || !outcome.Proven || strings.Contains(string(outcome.Result), token) {
		t.Fatalf("outcome = %+v err = %v", outcome, err)
	}
	stored, metadata, err := credentials.Get("ci-runner", "github-runner-token")
	if err != nil || string(stored) != token || metadata.Slot != "ci-runner" {
		t.Fatalf("stored = %q metadata = %+v err = %v", stored, metadata, err)
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
	return Options{SealedStore: newSealedStore(t), CredentialStore: credentials}
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
