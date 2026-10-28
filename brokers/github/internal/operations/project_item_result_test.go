package operations

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/osolmaz/unyolo/brokers/github/internal/githubauth"
	"github.com/osolmaz/unyolo/brokers/github/internal/opbinding"
	"github.com/osolmaz/unyolo/brokers/github/internal/schemaregistry"
)

// Exercise the actual generated binding, ExecuteREST decoder/projection, result
// validator and agent array wrapper, without a live provider or credential.
func TestOrganizationProjectItemReadback(t *testing.T) {
	fixture := projectItemExample(t)
	content := fixture["content"].(map[string]any)
	fields := fixture["fields"].([]any)
	status := fields[2].(map[string]any)
	option := status["value"].(map[string]any)
	wantContent := map[string]any{}
	for _, key := range []string{"id", "node_id", "number", "url", "html_url"} {
		wantContent[key] = content[key]
	}
	wantStatus := map[string]any{
		"id": status["id"], "name": status["name"], "data_type": status["data_type"],
		"value": map[string]any{"id": option["id"], "name": map[string]any{"raw": option["name"].(map[string]any)["raw"]}},
	}
	// Canary additions are synthetic; all expected identities/values come from
	// the immutable official OpenAPI example, not a purported provider response.
	fixture["token"] = "excluded-canary"
	fixture["unknown"] = map[string]any{"id": 99}
	content["token"] = "excluded-canary"
	content["unknown"] = map[string]any{"id": 99}
	status["token"] = "excluded-canary"
	status["unknown"] = map[string]any{"id": 99}
	option["token"] = "excluded-canary"
	option["unknown"] = map[string]any{"id": 99}
	option["name"].(map[string]any)["token"] = "excluded-canary"
	option["name"].(map[string]any)["unknown"] = map[string]any{"id": 99}

	for _, name := range []string{"project.projects_list_items_for_org", "project.projects_get_org_item", "project.projects_update_item_for_org"} {
		t.Run(name, func(t *testing.T) {
			bindings := opbinding.ByOperation(name)
			if len(bindings) != 1 {
				t.Fatalf("bindings = %d", len(bindings))
			}
			binding := bindings[0]
			isList := binding.ResponseRootType == "array"
			arguments := map[string]any{"project_number": float64(1), "item_id": fixture["id"]}
			input := map[string]any{"fields": []any{map[string]any{"id": status["id"], "value": option["id"]}}}
			if binding.Method == http.MethodPatch {
				arguments["input"] = input
			} else {
				arguments["fields"] = "3"
			}
			if isList {
				delete(arguments, "item_id")
				arguments["per_page"] = float64(10)
			}
			if err := schemaregistry.ValidateArguments(name, mustProjectJSON(t, arguments)); err != nil {
				t.Fatal(err)
			}
			empty := false
			requests := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests++
				path := "/orgs/github/projectsV2/1/items"
				if !isList {
					path += "/13"
				}
				if r.Method != binding.Method || r.URL.Path != path {
					t.Errorf("request = %s %s", r.Method, r.URL.Path)
				}
				if r.Header.Get("Authorization") != "Bearer offline-canary" || r.Header.Get("X-GitHub-Api-Version") != binding.APIVersion || r.Header.Get("Accept") != binding.MediaType {
					t.Error("request headers changed")
				}
				if binding.Method == http.MethodPatch {
					body, err := io.ReadAll(r.Body)
					if err != nil {
						t.Error(err)
					}
					assertJSONEqual(t, body, string(mustProjectJSON(t, input)))
					if r.URL.RawQuery != "" {
						t.Errorf("unexpected update query: %s", r.URL.RawQuery)
					}
				} else {
					wantQuery := "fields=3"
					if isList {
						wantQuery += "&per_page=10"
					}
					if r.URL.RawQuery != wantQuery {
						t.Errorf("query = %s, want %s", r.URL.RawQuery, wantQuery)
					}
				}
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Link", `<https://example.invalid/next>; rel="next"`)
				var response any = fixture
				if isList {
					response = []any{fixture}
					if empty {
						response = []any{}
					}
				}
				_, _ = w.Write(mustProjectJSON(t, response))
			}))
			t.Cleanup(server.Close)
			base, err := url.Parse(server.URL + "/")
			if err != nil {
				t.Fatal(err)
			}
			manager, err := githubauth.New(githubauth.Config{APIBaseURL: base, WebBaseURL: base, DevelopmentToken: []byte("offline-canary"), DevelopmentTokenFile: "/offline/unused"})
			if err != nil {
				t.Fatal(err)
			}
			target := map[string]any{"kind": "organization", "name": "github"}
			selector := githubauth.Metadata{Kind: githubauth.KindDevelopmentToken, APIHost: base.Host}
			result, err := manager.ExecuteREST(t.Context(), selector, binding, target, arguments)
			if err != nil {
				t.Fatal(err)
			}
			outcome, err := validatedExecutionResult(binding, name, result)
			if err != nil {
				t.Fatal(err)
			}
			var item map[string]any
			if isList {
				var wrapped struct {
					Items []map[string]any `json:"items"`
				}
				if err := json.Unmarshal(outcome.Result, &wrapped); err != nil || len(wrapped.Items) != 1 {
					t.Fatalf("nonempty provider array lost: %s, %v", outcome.Result, err)
				}
				item = wrapped.Items[0]
			} else if err := json.Unmarshal(outcome.Result, &item); err != nil {
				t.Fatal(err)
			}
			if !outcome.Proven || item["id"] != fixture["id"] || item["node_id"] != fixture["node_id"] {
				t.Fatalf("item identity lost: %s", outcome.Result)
			}
			if item["content_type"] != fixture["content_type"] || !reflect.DeepEqual(item["content"], wantContent) {
				t.Errorf("content identity lost: got %#v, want %#v", item["content"], wantContent)
			}
			var gotStatus any
			if gotFields, ok := item["fields"].([]any); ok {
				for _, field := range gotFields {
					if field.(map[string]any)["id"] == status["id"] {
						gotStatus = field
					}
				}
			}
			if !reflect.DeepEqual(gotStatus, wantStatus) {
				t.Errorf("selected field value lost: got %#v, want %#v", gotStatus, wantStatus)
			}
			for _, excluded := range []string{"excluded-canary", `"body"`, `"html"`, `"description"`, `"creator"`, `"unknown"`, `"diff_url"`, `"total_count"`, `"cursor"`} {
				if strings.Contains(string(outcome.Result), excluded) {
					t.Errorf("excluded field exposed: %s", excluded)
				}
			}
			if isList {
				empty = true
				result, err = manager.ExecuteREST(t.Context(), selector, binding, target, arguments)
				if err != nil {
					t.Fatal(err)
				}
				outcome, err = validatedExecutionResult(binding, name, result)
				if err != nil {
					t.Fatal(err)
				}
				assertJSONEqual(t, outcome.Result, `{"items":[]}`)
			}
			wantRequests := 1
			if isList {
				wantRequests = 2
			}
			if requests != wantRequests {
				t.Fatalf("requests = %d, want %d", requests, wantRequests)
			}
		})
	}
}

func projectItemExample(t *testing.T) map[string]any {
	t.Helper()
	data, err := os.ReadFile("../upstream/snapshots/rest-api-2026-03-10.json")
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Components struct {
			Examples map[string]json.RawMessage `json:"examples"`
		} `json:"components"`
	}
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatal(err)
	}
	var example struct {
		Value map[string]any `json:"value"`
	}
	if err := json.Unmarshal(document.Components.Examples["projects-v2-item-with-content"], &example); err != nil {
		t.Fatal(err)
	}
	return example.Value
}

func mustProjectJSON(t *testing.T, value any) json.RawMessage {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
