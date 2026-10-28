package operations

import (
	"encoding/json"
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

// Synthetic loopback execution of the generated production bindings, projection,
// schema validation and agent wrapper. This is not live-provider acceptance.
func TestOrganizationProjectFieldReadback(t *testing.T) {
	for _, name := range []string{"project.projects_get_field_for_org", "project.projects_list_fields_for_org"} {
		t.Run(name, func(t *testing.T) {
			bindings := opbinding.ByOperation(name)
			if len(bindings) != 1 {
				t.Fatalf("bindings = %d", len(bindings))
			}
			binding := bindings[0]
			isList := binding.ResponseRootType == "array"
			fixture := projectFieldExample(t)
			want := map[string]any{}
			for _, key := range []string{"id", "node_id", "name", "created_at", "updated_at", "data_type"} {
				want[key] = fixture[key]
			}
			options := fixture["options"].([]any)
			wantOptions := []any{}
			for _, value := range options {
				option := value.(map[string]any)
				wantOptions = append(wantOptions, map[string]any{"id": option["id"], "name": map[string]any{"raw": option["name"].(map[string]any)["raw"]}})
				option["token"] = "excluded-canary"
				option["unknown"] = map[string]any{"id": 99}
				option["name"].(map[string]any)["token"] = "excluded-canary"
				option["name"].(map[string]any)["unknown"] = map[string]any{"id": 99}
			}
			want["options"] = wantOptions
			fixture["token"] = "excluded-canary"
			fixture["unknown"] = map[string]any{"id": 99}
			fixture["configuration"] = map[string]any{"iterations": []any{map[string]any{"id": 99}}}
			arguments := map[string]any{"project_number": float64(1)}
			if isList {
				arguments["per_page"] = float64(10)
				arguments["after"] = "offline-cursor"
			} else {
				arguments["field_id"] = fixture["id"]
			}
			if err := schemaregistry.ValidateArguments(name, mustFieldJSON(t, arguments)); err != nil {
				t.Fatal(err)
			}
			requests := 0
			var response any = fixture
			if isList {
				response = []any{fixture}
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests++
				path, query := "/orgs/github/projectsV2/1/fields", "after=offline-cursor&per_page=10"
				if !isList {
					path += "/12345"
					query = ""
				}
				if r.Method != http.MethodGet || r.URL.Path != path || r.URL.RawQuery != query {
					t.Errorf("request tuple changed: %s %s", r.Method, r.URL.String())
				}
				if r.Header.Get("Authorization") != "Bearer offline-canary" || r.Header.Get("X-GitHub-Api-Version") != binding.APIVersion || r.Header.Get("Accept") != binding.MediaType {
					t.Error("request headers changed")
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write(mustFieldJSON(t, response))
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
			selector := githubauth.Metadata{Kind: githubauth.KindDevelopmentToken, APIHost: base.Host}
			target := map[string]any{"kind": "organization", "name": "github"}
			execute := func() (json.RawMessage, error) {
				result, err := manager.ExecuteREST(t.Context(), selector, binding, target, arguments)
				if err != nil {
					return nil, err
				}
				outcome, err := validatedExecutionResult(binding, name, result)
				if err != nil {
					return nil, err
				}
				if !outcome.Proven {
					t.Error("read not proven")
				}
				return outcome.Result, nil
			}
			result, err := execute()
			if err != nil {
				t.Fatal(err)
			}
			var got map[string]any
			if isList {
				var wrapped struct {
					Items []map[string]any `json:"items"`
				}
				if err := json.Unmarshal(result, &wrapped); err != nil || len(wrapped.Items) != 1 {
					t.Fatalf("array lost: %s, %v", result, err)
				}
				got = wrapped.Items[0]
			} else if err := json.Unmarshal(result, &got); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, want) {
				t.Errorf("field option identity lost: got %s, want %s", result, mustFieldJSON(t, want))
			}
			for _, excluded := range []string{"excluded-canary", `"html"`, `"description"`, `"color"`, `"unknown"`, `"configuration"`, `"project_url"`} {
				if strings.Contains(string(result), excluded) {
					t.Errorf("excluded field exposed: %s", excluded)
				}
			}
			// Malformed and over-limit retained values must not become proven results.
			for _, tc := range []struct {
				name  string
				value any
			}{
				{"too many options", make([]any, 101)},
				{"long option id", []any{map[string]any{"id": strings.Repeat("x", 1048577)}}},
				{"long option name", []any{map[string]any{"name": map[string]any{"raw": strings.Repeat("x", 1048577)}}}},
			} {
				t.Run(tc.name, func(t *testing.T) {
					if tc.name == "too many options" {
						for i := range tc.value.([]any) {
							tc.value.([]any)[i] = options[0]
						}
					}
					fixture["options"] = tc.value
					if _, err := execute(); err == nil {
						t.Error("invalid option result accepted")
					}
				})
			}
			fixture["options"] = []any{}
			if _, err := execute(); err != nil {
				t.Fatalf("empty options refused: %v", err)
			}
			// A scalar cannot supply the nested raw leaf; production may discard it
			// rather than reject the entire read, but must never expose it as a name.
			fixture["options"] = []any{map[string]any{"id": "synthetic-id", "name": "excluded-scalar"}}
			result, err = execute()
			if err == nil && strings.Contains(string(result), "excluded-scalar") {
				t.Error("scalar name exposed")
			}
			delete(fixture, "options")
			fixture["data_type"] = "text"
			if _, err := execute(); err != nil {
				t.Fatalf("non-select field refused: %v", err)
			}
			if isList {
				response = []any{}
				result, err = execute()
				if err != nil {
					t.Fatal(err)
				}
				assertJSONEqual(t, result, `{"items":[]}`)
			}
			expected := 7
			if isList {
				expected++
			}
			if requests != expected {
				t.Errorf("requests = %d, want %d", requests, expected)
			}
		})
	}
}

func projectFieldExample(t *testing.T) map[string]any {
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
	if err := json.Unmarshal(document.Components.Examples["projects-v2-field-single-select"], &example); err != nil {
		t.Fatal(err)
	}
	return example.Value
}
