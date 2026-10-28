package githubauth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/osolmaz/unyolo/brokers/github/internal/opbinding"
)

// Every case crosses the real HTTP client + authorization + maintained REST
// projection, not just a Link parser. Unknown metadata must not imply complete.
func TestProjectPaginationHTTP(t *testing.T) {
	const path = "/orgs/github/projectsV2/1/items"
	const query = "fields=3&per_page=1"
	next := func(host string) string { return `<` + host + path + `?after=cursor2&` + query + `>; rel="next"` }
	prev := func(host string) string { return `<` + host + path + `?before=cursor1&` + query + `>; rel="prev"` }
	tests := []struct {
		name         string
		links        func(string) []string
		body         string
		status       int
		argument     string
		arguments    map[string]any
		apiPrefix    string
		operation    string
		trailer      bool
		nonpaginated bool
		truncated    bool
		want         *RESTPagination
		wantError    bool
	}{
		{name: "next", links: func(h string) []string { return []string{next(h)} }, want: &RESTPagination{HasNext: true, NextAfter: "cursor2"}},
		{name: "terminal_no_link", want: &RESTPagination{}},
		{name: "enterprise_prefix", apiPrefix: "/api/v3", links: func(h string) []string { return []string{next(h)} }, want: &RESTPagination{HasNext: true, NextAfter: "cursor2"}},
		{name: "link_trailer_unavailable", trailer: true, links: func(h string) []string { return []string{next(h)} }},
		{name: "other_link_operation_unchanged", operation: "project.projects_list_items_for_user", links: func(h string) []string { return []string{next(h)} }},
		{name: "empty_terminal_no_link", body: "[]", want: &RESTPagination{}},
		{name: "empty_array_bad_link_not_complete", body: "[]", links: func(h string) []string { return []string{next("https://wrong.invalid")} }},
		{name: "nonempty_terminal_prev", links: func(h string) []string { return []string{prev(h)} }, argument: "after", want: &RESTPagination{}},
		{name: "multiple_header_values", links: func(h string) []string { return []string{next(h), prev(h)} }, want: &RESTPagination{HasNext: true, NextAfter: "cursor2"}},
		{name: "combined_header", links: func(h string) []string { return []string{next(h) + ", " + prev(h)} }, want: &RESTPagination{HasNext: true, NextAfter: "cursor2"}},
		{name: "unquoted_relation", links: func(h string) []string { return []string{strings.ReplaceAll(next(h), `"next"`, `next`)} }, want: &RESTPagination{HasNext: true, NextAfter: "cursor2"}},
		{name: "base64_cursor", links: func(h string) []string { return []string{strings.ReplaceAll(next(h), "cursor2", "Y3Vyc29yOjI%3D")} }, want: &RESTPagination{HasNext: true, NextAfter: "Y3Vyc29yOjI="}},
		{name: "base64_reserved_characters", links: func(h string) []string { return []string{strings.ReplaceAll(next(h), "cursor2", "ab%2Bcd%2Fef%3D%3D")} }, want: &RESTPagination{HasNext: true, NextAfter: "ab+cd/ef=="}},
		{name: "multiple_fields", arguments: map[string]any{"fields": []any{"3", "4"}}, links: func(h string) []string { return []string{strings.ReplaceAll(next(h), "fields=3", "fields=3&fields=4")} }, want: &RESTPagination{HasNext: true, NextAfter: "cursor2"}},
		{name: "comma_fields", arguments: map[string]any{"fields": "3,4"}, links: func(h string) []string { return []string{strings.ReplaceAll(next(h), "fields=3", "fields=3,4")} }, want: &RESTPagination{HasNext: true, NextAfter: "cursor2"}},
		{name: "unchanged_filter", arguments: map[string]any{"q": "status:Done"}, links: func(h string) []string {
			return []string{strings.ReplaceAll(next(h), "fields=3", "fields=3&q=status%3ADone")}
		}, want: &RESTPagination{HasNext: true, NextAfter: "cursor2"}},
		{name: "changed_field_array", arguments: map[string]any{"fields": []any{"3", "4"}}, links: func(h string) []string { return []string{strings.ReplaceAll(next(h), "fields=3", "fields=3&fields=5")} }},
		{name: "request_cursor_unavailable", arguments: map[string]any{"after": "ghp_secret-canary"}},
		{name: "large_request_query_unavailable", arguments: map[string]any{"q": strings.Repeat("a", 4097)}},
		{name: "wrong_origin", links: func(h string) []string { return []string{next("https://wrong.invalid")} }},
		{name: "wrong_scheme", links: func(h string) []string { return []string{next(strings.Replace(h, "http:", "https:", 1))} }},
		{name: "wrong_path", links: func(h string) []string { return []string{strings.ReplaceAll(next(h), "projectsV2/1", "projectsV2/2")} }},
		{name: "wrong_org", links: func(h string) []string { return []string{strings.ReplaceAll(next(h), "/github/", "/other/")} }},
		{name: "relative_url", links: func(h string) []string { return []string{next("")} }},
		{name: "encoded_path", links: func(h string) []string { return []string{strings.ReplaceAll(next(h), "/orgs/", "/%6Frgs/")} }},
		{name: "dot_path", links: func(h string) []string { return []string{strings.ReplaceAll(next(h), "/items?", "/../items?")} }},
		{name: "userinfo", links: func(h string) []string {
			return []string{next(strings.Replace(h, "http://", "http://secret-canary@", 1))}
		}},
		{name: "fragment", links: func(h string) []string { return []string{strings.ReplaceAll(next(h), ">;", "#secret-canary>;")} }},
		{name: "unknown_signed_query", links: func(h string) []string {
			return []string{strings.ReplaceAll(next(h), "after=cursor2", "after=cursor2&X-Amz-Signature=secret-canary")}
		}},
		{name: "unknown_page_query", links: func(h string) []string { return []string{strings.ReplaceAll(next(h), "after=cursor2", "page=2")} }},
		{name: "duplicate_cursor", links: func(h string) []string {
			return []string{strings.ReplaceAll(next(h), "after=cursor2", "after=cursor2&after=cursor3")}
		}},
		{name: "both_cursors", links: func(h string) []string {
			return []string{strings.ReplaceAll(next(h), "after=cursor2", "after=cursor2&before=cursor1")}
		}},
		{name: "missing_cursor", links: func(h string) []string { return []string{strings.ReplaceAll(next(h), "after=cursor2&", "")} }},
		{name: "empty_cursor", links: func(h string) []string { return []string{strings.ReplaceAll(next(h), "cursor2", "")} }},
		{name: "cursor_control", links: func(h string) []string { return []string{strings.ReplaceAll(next(h), "cursor2", "%0Asecret-canary")} }},
		{name: "cursor_url", links: func(h string) []string {
			return []string{strings.ReplaceAll(next(h), "cursor2", "https%3A%2F%2Fsecret-canary.invalid")}
		}},
		{name: "cursor_token", links: func(h string) []string { return []string{strings.ReplaceAll(next(h), "cursor2", "ghp_secret-canary")} }},
		{name: "cursor_pat", links: func(h string) []string {
			return []string{strings.ReplaceAll(next(h), "cursor2", "github_pat_secret-canary")}
		}},
		{name: "cursor_jwt", links: func(h string) []string { return []string{strings.ReplaceAll(next(h), "cursor2", "eyJsecret-canary")} }},
		{name: "long_cursor", links: func(h string) []string {
			return []string{strings.ReplaceAll(next(h), "cursor2", strings.Repeat("a", 257))}
		}},
		{name: "oversized_url", links: func(h string) []string {
			return []string{strings.ReplaceAll(next(h), "fields=3", "fields="+strings.Repeat("3", 2048))}
		}},
		{name: "oversized_headers", links: func(h string) []string {
			return []string{strings.ReplaceAll(next(h), ">;", ">"+strings.Repeat(" ", 8192)+";")}
		}},
		{name: "bad_percent", links: func(h string) []string { return []string{strings.ReplaceAll(next(h), "cursor2", "%ZZ")} }},
		{name: "query_semicolon", links: func(h string) []string { return []string{strings.ReplaceAll(next(h), "cursor2", "cursor2;bad")} }},
		{name: "changed_fields", links: func(h string) []string { return []string{strings.ReplaceAll(next(h), "fields=3", "fields=4")} }},
		{name: "changed_page_size", links: func(h string) []string { return []string{strings.ReplaceAll(next(h), "per_page=1", "per_page=2")} }},
		{name: "added_filter", links: func(h string) []string {
			return []string{strings.ReplaceAll(next(h), "fields=3", "fields=3&q=secret-canary")}
		}},
		{name: "duplicate_relation", links: func(h string) []string { return []string{next(h), next(h)} }},
		{name: "conflicting_relation", links: func(h string) []string { return []string{next(h), strings.ReplaceAll(next(h), "cursor2", "cursor3")} }},
		{name: "conflicting_cursors", links: func(h string) []string { return []string{next(h), strings.ReplaceAll(prev(h), "cursor1", "cursor2")} }},
		{name: "unknown_relation", links: func(h string) []string { return []string{strings.ReplaceAll(next(h), `"next"`, `"last"`)} }},
		{name: "multi_relation", links: func(h string) []string { return []string{strings.ReplaceAll(next(h), `"next"`, `"next prev"`)} }},
		{name: "relation_case", links: func(h string) []string { return []string{strings.ReplaceAll(next(h), `"next"`, `"NEXT"`)} }},
		{name: "extra_parameter", links: func(h string) []string { return []string{next(h) + `; title="secret-canary"`} }},
		{name: "dangling_comma", links: func(h string) []string { return []string{next(h) + ","} }},
		{name: "malformed_header", links: func(h string) []string { return []string{"secret-canary"} }},
		{name: "empty_header", links: func(h string) []string { return []string{""} }},
		{name: "valid_next_plus_malformed", links: func(h string) []string { return []string{next(h), "bad"} }},
		{name: "backward_request_no_link", argument: "before"},
		{name: "looping_next", argument: "after", links: func(h string) []string { return []string{strings.ReplaceAll(next(h), "cursor2", "cursor0")} }},
		{name: "nonpaginated_unchanged", nonpaginated: true, links: func(h string) []string { return []string{next(h)} }},
		{name: "nonpaginated_no_link", nonpaginated: true},
		{name: "blank_body_not_terminal", body: " "},
		{name: "null_body_not_terminal", body: "null"},
		{name: "wrong_root_not_terminal", body: "{}"},
		{name: "no_content_not_terminal", status: 204},
		{name: "invalid_json", body: "[", wantError: true},
		{name: "truncated_transport", truncated: true, wantError: true},
		{name: "provider_error", status: 500, wantError: true},
		{name: "redirect_error", status: 302, wantError: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			binding := opbinding.ByOperation("project.projects_list_items_for_org")[0]
			if test.nonpaginated {
				binding.Pagination = "none"
			}
			if test.operation != "" {
				binding.Operation = test.operation
			}
			var requests atomic.Int32
			body := test.body
			if body == "" {
				body = `[{"id":13,"node_id":"PVTI_lAAFAQ0","token":"excluded-canary"}]`
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				if r.URL.Path != test.apiPrefix+path || r.Method != "GET" || r.Header.Get("Authorization") != "Bearer offline-canary" {
					t.Error("unexpected request/authentication")
				}
				if test.trailer {
					w.Header().Set("Trailer", "Link")
				}
				if test.links != nil && !test.trailer {
					for _, line := range test.links("http://" + r.Host + test.apiPrefix) {
						w.Header().Add("Link", line)
					}
				}
				// Unrelated secret-like headers must never become output metadata.
				w.Header().Set("X-Credential", "secret-canary")
				w.Header().Set("Location", "https://secret-canary.invalid/signed?token=secret-canary")
				if test.truncated {
					w.Header().Set("Content-Length", "1000")
				}
				status := test.status
				if status == 0 {
					status = 200
				}
				w.WriteHeader(status)
				_, _ = fmt.Fprint(w, body)
				if test.trailer {
					for _, line := range test.links("http://" + r.Host) {
						w.Header().Add("Link", line)
					}
				}
			}))
			defer server.Close()
			base, _ := url.Parse(server.URL + test.apiPrefix + "/")
			manager, err := New(Config{APIBaseURL: base, WebBaseURL: base, DevelopmentToken: []byte("offline-canary"), DevelopmentTokenFile: "/offline/unused"})
			if err != nil {
				t.Fatal(err)
			}
			args := map[string]any{"project_number": float64(1), "fields": "3", "per_page": float64(1)}
			if test.argument != "" {
				args[test.argument] = "cursor0"
			}
			for key, value := range test.arguments {
				args[key] = value
			}
			result, err := manager.ExecuteREST(t.Context(), manager.development.Metadata(), binding, map[string]any{"kind": "organization", "name": "github"}, args)
			if (err != nil) != test.wantError {
				t.Fatalf("error=%v wantError=%v", err, test.wantError)
			}
			got, _ := json.Marshal(result.Pagination)
			want, _ := json.Marshal(test.want)
			if string(got) != string(want) {
				t.Fatalf("pagination=%s want=%s", got, want)
			}
			if test.body == "" && !test.wantError && test.status != 204 && string(result.Body) != `[{"id":13,"node_id":"PVTI_lAAFAQ0"}]` {
				t.Fatal("original projected result bytes changed or false-empty")
			}
			encoded, _ := json.Marshal(result)
			if test.want == nil && strings.Contains(string(encoded), `"pagination"`) {
				t.Fatal("unavailable pagination field was not omitted")
			}
			for _, canary := range []string{"secret-canary", "excluded-canary", "offline-canary", "X-Credential", "Location"} {
				if strings.Contains(string(encoded), canary) {
					t.Fatal("raw/secret-like header or excluded body leaked")
				}
			}
			if requests.Load() != 1 {
				t.Fatalf("requests=%d (autofollow/retry forbidden in this fixture)", requests.Load())
			}
		})
	}
}
