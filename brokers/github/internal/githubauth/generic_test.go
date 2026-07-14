package githubauth

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/osolmaz/brokerkit/brokers/github/internal/graphqlmanifest"
	"github.com/osolmaz/brokerkit/brokers/github/internal/opbinding"
)

func TestExecuteRESTBindsPathQueryBodyAndHeaders(t *testing.T) {
	var seenQuery string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenQuery = r.URL.RawQuery
		if r.Method != http.MethodPost || r.URL.EscapedPath() != "/repos/acme%20labs/demo%20repo/pulls" {
			t.Fatalf("request = %s %s", r.Method, r.URL.RequestURI())
		}
		if r.Header.Get("Authorization") != "Bearer dev-canary" || r.Header.Get("Accept") != "application/vnd.github+json" || r.Header.Get("X-GitHub-Api-Version") != APIVersion {
			t.Fatalf("headers = %+v", r.Header)
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if _, found := body["ignored"]; found || body["title"] != "Agent cutover" {
			t.Fatalf("body = %#v", body)
		}
		_, _ = w.Write([]byte(`{"id":7,"state":"open","url":"https://example.test/pull/7","token":"redacted"}`))
	}))
	t.Cleanup(server.Close)
	manager := newDevelopmentManager(t, server.URL)
	binding := opbinding.Binding{
		Method:               http.MethodPost,
		PathTemplate:         "/repos/{owner}/{repo}/pulls",
		MediaType:            "application/vnd.github+json",
		PathParameters:       []string{"owner", "repo"},
		TargetPathParameters: []opbinding.TargetParameter{{Name: "owner", Field: "owner"}, {Name: "repo", Field: "name"}},
		ArgumentParameters:   []opbinding.Parameter{{Name: "draft", In: "query"}},
		RequestBytesLimit:    1024,
		ResponseBytesLimit:   1024,
		ResponseProjection:   []string{"id", "state", "url"},
	}
	result, err := manager.ExecuteREST(t.Context(), manager.development.Metadata(), binding,
		map[string]any{"owner": "acme labs", "name": "demo repo"},
		map[string]any{"draft": true, "ignored": "value", "input": map[string]any{"title": "Agent cutover"}})
	if err != nil {
		t.Fatal(err)
	}
	if seenQuery != "draft=true" {
		t.Fatalf("query = %q", seenQuery)
	}
	assertJSONEqual(t, result.Body, `{"id":7,"state":"open","url":"https://example.test/pull/7"}`)
}

func TestExecuteRESTEnforcesLimitsAndClassifiesErrors(t *testing.T) {
	t.Run("response limit", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"id":"` + strings.Repeat("x", 64) + `"}`))
		}))
		t.Cleanup(server.Close)
		manager := newDevelopmentManager(t, server.URL)
		_, err := manager.ExecuteREST(t.Context(), manager.development.Metadata(), opbinding.Binding{
			Method:               http.MethodGet,
			PathTemplate:         "/repos/{owner}/{repo}",
			MediaType:            "application/vnd.github+json",
			PathParameters:       []string{"owner", "repo"},
			TargetPathParameters: []opbinding.TargetParameter{{Name: "owner", Field: "owner"}, {Name: "repo", Field: "name"}},
			ResponseBytesLimit:   16,
			ResponseProjection:   []string{"id"},
		}, map[string]any{"owner": "acme", "name": "demo"}, map[string]any{})
		if err == nil || !strings.Contains(err.Error(), "size limit") {
			t.Fatalf("limit error = %v", err)
		}
	})

	t.Run("rate limited", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("X-RateLimit-Remaining", "0")
			w.Header().Set("X-RateLimit-Reset", "1784000000")
			http.Error(w, "slow down", http.StatusTooManyRequests)
		}))
		t.Cleanup(server.Close)
		manager := newDevelopmentManager(t, server.URL)
		_, err := manager.ExecuteREST(t.Context(), manager.development.Metadata(), opbinding.Binding{
			Method:               http.MethodGet,
			PathTemplate:         "/repos/{owner}/{repo}",
			MediaType:            "application/vnd.github+json",
			PathParameters:       []string{"owner", "repo"},
			TargetPathParameters: []opbinding.TargetParameter{{Name: "owner", Field: "owner"}, {Name: "repo", Field: "name"}},
			ResponseBytesLimit:   1024,
			ResponseProjection:   []string{"id"},
		}, map[string]any{"owner": "acme", "name": "demo"}, map[string]any{})
		var apiErr APIError
		if !errors.As(err, &apiErr) || apiErr.Code != "rate_limited" || apiErr.RateReset.IsZero() {
			t.Fatalf("rate error = %#v", err)
		}
	})
}

func TestExecuteRESTDownloadFollowsOnlyCredentialFreeAllowedRedirects(t *testing.T) {
	var redirectedAuth string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/repos/acme/demo/zipball/main":
			http.Redirect(w, request, "/download/archive.zip", http.StatusFound)
		case "/download/archive.zip":
			redirectedAuth = request.Header.Get("Authorization")
			_, _ = w.Write([]byte("archive"))
		default:
			http.NotFound(w, request)
		}
	}))
	t.Cleanup(server.Close)
	manager := newDevelopmentManager(t, server.URL)
	binding := opbinding.Binding{Method: http.MethodGet, PathTemplate: "/repos/{owner}/{repo}/zipball/{ref}",
		PathParameters:       []string{"owner", "repo", "ref"},
		TargetPathParameters: []opbinding.TargetParameter{{Name: "owner", Field: "owner"}, {Name: "repo", Field: "name"}},
		StreamDirection:      "download", ResponseBytesLimit: 1024}
	response, err := manager.ExecuteRESTDownload(t.Context(), manager.development.Metadata(), binding,
		map[string]any{"kind": "repo", "owner": "acme", "name": "demo"}, map[string]any{"ref": "main"})
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if redirectedAuth != "" {
		t.Fatalf("credential leaked to redirect: %q", redirectedAuth)
	}

	blocked := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		w.Header().Set("Location", "https://example.invalid/archive.zip")
		w.WriteHeader(http.StatusFound)
	}))
	t.Cleanup(blocked.Close)
	manager = newDevelopmentManager(t, blocked.URL)
	if _, err := manager.ExecuteRESTDownload(t.Context(), manager.development.Metadata(), binding,
		map[string]any{"kind": "repo", "owner": "acme", "name": "demo"}, map[string]any{"ref": "main"}); err == nil {
		t.Fatal("disallowed redirect was followed")
	}
}

func TestExecuteGraphQLUsesPersistedDocumentAndFixedEndpoint(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/graphql" {
			t.Fatalf("request = %s %s", r.Method, r.URL.String())
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if body["query"] != "query Repo($owner: String!, $name: String!) { repository(owner: $owner, name: $name) { __typename } }" ||
			body["operationName"] != "Repo" {
			t.Fatalf("graphql body = %#v", body)
		}
		_, _ = w.Write([]byte(`{"data":{"repository":{"__typename":"Repository"}}}`))
	}))
	t.Cleanup(server.Close)
	manager := newDevelopmentManager(t, server.URL)
	document := graphqlmanifest.Document{
		OperationName:      "Repo",
		Document:           "query Repo($owner: String!, $name: String!) { repository(owner: $owner, name: $name) { __typename } }",
		ResponseProjection: []string{"repository"},
	}
	result, err := manager.ExecuteGraphQL(t.Context(), manager.development.Metadata(), document, map[string]any{"owner": "acme", "name": "demo"})
	if err != nil {
		t.Fatal(err)
	}
	assertJSONEqual(t, result.Body, `{"repository":{"__typename":"Repository"}}`)
}

func newDevelopmentManager(t *testing.T, base string) *Manager {
	t.Helper()
	apiURL, err := url.Parse(base)
	if err != nil {
		t.Fatal(err)
	}
	manager, err := New(Config{
		DevelopmentToken:     []byte("dev-canary"),
		DevelopmentTokenFile: "/tmp/dev-canary",
		APIBaseURL:           apiURL,
		WebBaseURL:           apiURL,
		HTTPClient:           &http.Client{Timeout: time.Second, CheckRedirect: stopRedirect},
	})
	if err != nil {
		t.Fatal(err)
	}
	return manager
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
