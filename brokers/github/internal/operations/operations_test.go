package operations

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/osolmaz/brokerkit/brokers/github/internal/githubauth"
)

func TestGeneratedRegistryCoversAgentFacingRESTAndGraphQL(t *testing.T) {
	adapters, err := NewGeneratedAdapters(nil, Options{})
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
	if _, err := contents.Decode(json.RawMessage(`{"kind":"repo","owner":"osolmaz","name":"brokerkit"}`), json.RawMessage(`{"path":"README.md"}`)); err == nil || !strings.Contains(err.Error(), "validated target") {
		t.Fatalf("path parameter decode error = %v", err)
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
	adapters, err := NewGeneratedAdapters(manager, Options{})
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
