package githubauth

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/osolmaz/brokerkit/brokers/github/internal/graphqlmanifest"
	"github.com/osolmaz/brokerkit/brokers/github/internal/opbinding"
	"github.com/osolmaz/brokerkit/brokers/github/internal/opcatalog"
	"github.com/osolmaz/brokerkit/capability"
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
		_, _ = w.Write([]byte(`{"id":7,"state":"open","url":"https://example.test/pull/7","token":"redacted","user":{"id":8,"url":"https://example.test/users/8"}}`))
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

func TestAuthenticatedUserTargetMustMatchCredential(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/user" || r.Header.Get("Authorization") != "Bearer dev-canary" {
			t.Fatalf("request = %s, authorization = %q", r.URL.Path, r.Header.Get("Authorization"))
		}
		_, _ = io.WriteString(w, `{"id":7,"login":"osolmaz","token":"not-projected"}`)
	}))
	t.Cleanup(server.Close)
	manager := newDevelopmentManager(t, server.URL)
	selector := manager.development.Metadata()
	if err := manager.ValidateAuthenticatedUserTarget(t.Context(), selector, map[string]any{"kind": "user", "name": "osolmaz", "id": float64(7)}); err != nil {
		t.Fatal(err)
	}
	for _, target := range []map[string]any{
		{"kind": "user", "name": "dutifuldev"},
		{"kind": "user", "name": "osolmaz", "id": float64(8)},
		{"kind": "repo", "name": "osolmaz"},
	} {
		if err := manager.ValidateAuthenticatedUserTarget(t.Context(), selector, target); err == nil {
			t.Fatalf("mismatched target accepted: %#v", target)
		}
	}
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

func TestCredentialMetadataSelectionFailsClosed(t *testing.T) {
	descriptor := func(kind string) opcatalog.Descriptor {
		return opcatalog.Descriptor{Descriptor: capability.Descriptor{Name: "test.operation", CredentialKind: kind},
			RequiredGitHubPermissions: map[string]string{"contents": "read"}}
	}
	var nilManager *Manager
	if _, err := nilManager.SelectMetadata(t.Context(), descriptor(string(KindInstallation)), nil, 0); err == nil {
		t.Fatal("nil manager selected metadata")
	}

	development := newDevelopmentManager(t, "http://127.0.0.1")
	metadata, err := development.SelectMetadata(t.Context(), descriptor(string(KindUser)), nil, 0)
	if err != nil || metadata.Kind != KindDevelopmentToken {
		t.Fatalf("development metadata = %+v, %v", metadata, err)
	}

	apiURL, _ := url.Parse("https://api.github.test/")
	manager := &Manager{apiURL: apiURL, app: &appProvider{}}
	metadata, err = manager.SelectMetadata(t.Context(), descriptor(string(KindAppJWT)), nil, 0)
	if err != nil || metadata.Kind != KindAppJWT {
		t.Fatalf("app metadata = %+v, %v", metadata, err)
	}
	metadata, err = manager.SelectMetadata(t.Context(), descriptor(string(KindInstallation)), map[string]any{
		"installation_id": float64(42), "repository_ids": []any{float64(7), json.Number("8"), float64(-1)},
	}, 0)
	if err != nil || metadata.InstallationID != 42 || len(metadata.RepositoryIDs) != 2 || metadata.Permissions["contents"] != "read" {
		t.Fatalf("installation metadata = %+v, %v", metadata, err)
	}
	metadata, err = manager.SelectMetadata(t.Context(), descriptor(string(KindInstallation)), map[string]any{
		"kind": "installation", "id": float64(43),
	}, 0)
	if err != nil || metadata.InstallationID != 43 {
		t.Fatalf("canonical installation target metadata = %+v, %v", metadata, err)
	}
	for name, operation := range map[string]func() error{
		"missing installation": func() error {
			_, callErr := manager.SelectMetadata(t.Context(), descriptor(string(KindInstallation)), map[string]any{}, 0)
			return callErr
		},
		"resource ID is not installation ID": func() error {
			_, callErr := manager.SelectMetadata(t.Context(), descriptor(string(KindInstallation)), map[string]any{"kind": "team", "id": float64(42)}, 0)
			return callErr
		},
		"missing user": func() error {
			_, callErr := manager.SelectMetadata(t.Context(), descriptor(string(KindUser)), map[string]any{"kind": "user"}, 0)
			return callErr
		},
		"unavailable user": func() error {
			_, callErr := manager.SelectMetadata(t.Context(), descriptor(string(KindUser)), nil, 7)
			return callErr
		},
		"unavailable development": func() error {
			_, callErr := manager.SelectMetadata(t.Context(), descriptor(string(KindDevelopmentToken)), nil, 0)
			return callErr
		},
		"unsupported": func() error {
			_, callErr := manager.SelectMetadata(t.Context(), descriptor("unknown"), nil, 0)
			return callErr
		},
	} {
		t.Run(name, func(t *testing.T) {
			if err := operation(); err == nil {
				t.Fatal("credential selection succeeded")
			}
		})
	}
}

func TestRawAndStreamingRESTBoundaries(t *testing.T) {
	var uploaded []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/raw":
			_, _ = io.WriteString(w, `{"token":"one-use","id":7}`)
		case "/invalid":
			_, _ = io.WriteString(w, `{`)
		case "/upload":
			uploaded, _ = io.ReadAll(r.Body)
			if r.Header.Get("Content-Type") != "application/octet-stream" || r.ContentLength != 7 {
				t.Fatalf("upload metadata = %q, %d", r.Header.Get("Content-Type"), r.ContentLength)
			}
			_, _ = io.WriteString(w, `{"id":9}`)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	manager := newDevelopmentManager(t, server.URL)
	binding := opbinding.Binding{Method: http.MethodPost, PathTemplate: "/raw", MediaType: "application/json",
		RequestBytesLimit: 32, ResponseBytesLimit: 64, ResponseProjection: []string{"id"}}
	result, err := manager.ExecuteRESTRaw(t.Context(), manager.development.Metadata(), binding, nil, nil)
	if err != nil || !bytes.Contains(result.Body, []byte("one-use")) {
		t.Fatalf("raw result = %s, %v", result.Body, err)
	}
	binding.PathTemplate = "/invalid"
	if _, err := manager.ExecuteRESTRaw(t.Context(), manager.development.Metadata(), binding, nil, nil); err == nil {
		t.Fatal("invalid raw response accepted")
	}
	binding.PathTemplate = "/upload"
	binding.StreamDirection = "upload"
	result, err = manager.ExecuteRESTUpload(t.Context(), manager.development.Metadata(), binding, nil, nil,
		strings.NewReader("payload"), 7, "application/octet-stream")
	if err != nil || string(uploaded) != "payload" || result.StatusCode != http.StatusOK {
		t.Fatalf("upload = %q, %+v, %v", uploaded, result, err)
	}
	for _, invalid := range []struct {
		source io.Reader
		size   int64
		media  string
	}{{nil, 7, "application/octet-stream"}, {strings.NewReader("x"), 0, "application/octet-stream"},
		{strings.NewReader("x"), 33, "application/octet-stream"}, {strings.NewReader("x"), 1, ""}} {
		if _, err := manager.ExecuteRESTUpload(t.Context(), manager.development.Metadata(), binding, nil, nil, invalid.source, invalid.size, invalid.media); err == nil {
			t.Fatal("invalid upload accepted")
		}
	}
	var nilManager *Manager
	if _, err := nilManager.ExecuteRESTRaw(t.Context(), Metadata{}, binding, nil, nil); err == nil {
		t.Fatal("nil manager executed raw REST")
	}
}

func TestResponseAndRedirectFailureModes(t *testing.T) {
	response := func(status int, body string) *http.Response {
		return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}
	}
	for name, call := range map[string]func() error{
		"invalid rest json": func() error {
			_, err := decodeRESTResponse(response(http.StatusOK, `{`), opbinding.Binding{ResponseBytesLimit: 8})
			return err
		},
		"invalid graphql json": func() error {
			_, err := decodeGraphQLResponse(response(http.StatusOK, `{`), graphqlmanifest.Document{})
			return err
		},
		"graphql errors": func() error {
			_, err := decodeGraphQLResponse(response(http.StatusOK, `{"errors":[{"message":"hidden"}]}`), graphqlmanifest.Document{})
			return err
		},
		"missing graphql projection": func() error {
			_, err := decodeGraphQLResponse(response(http.StatusOK, `{"data":{"repository":null}}`), graphqlmanifest.Document{ResponseProjection: []string{"organization"}})
			return err
		},
		"invalid body limit": func() error { _, err := limitedBody(strings.NewReader("x"), 0); return err },
		"oversized body":     func() error { _, err := limitedBody(strings.NewReader("xx"), 1); return err },
	} {
		t.Run(name, func(t *testing.T) {
			if err := call(); err == nil {
				t.Fatal("failure mode succeeded")
			}
		})
	}
	if result, err := decodeRESTResponse(response(http.StatusNoContent, ""), opbinding.Binding{ResponseBytesLimit: 8}); err != nil || string(result.Body) != `{}` {
		t.Fatalf("empty REST response = %s, %v", result.Body, err)
	}
	if result, err := decodeRESTResponse(response(http.StatusNoContent, ""), opbinding.Binding{ResponseBytesLimit: 8, ResponseRootType: "array"}); err != nil || string(result.Body) != `[]` {
		t.Fatalf("empty REST array response = %s, %v", result.Body, err)
	}
	for body, want := range map[string]string{`["one","two"]`: `["one","two"]`, `[{"secret":"hidden"}]`: `[{}]`} {
		result, err := decodeRESTResponse(response(http.StatusOK, body), opbinding.Binding{
			ResponseBytesLimit: 64, ResponseProjection: []string{"$none"}, ResponseRootType: "array",
		})
		if err != nil || string(result.Body) != want {
			t.Fatalf("redacted REST array = %s, %v; want %s", result.Body, err, want)
		}
	}

	origin, _ := url.Parse("https://api.github.com/archive")
	for raw, allowed := range map[string]bool{
		"https://api.github.com/file": true, "https://objects.githubusercontent.com/file": true,
		"https://bucket.blob.core.windows.net/file": true, "https://example.test/file": false,
		"http://objects.githubusercontent.com/file": false,
	} {
		target, _ := url.Parse(raw)
		if got := allowedDownloadURL(origin, target); got != allowed {
			t.Fatalf("allowedDownloadURL(%q) = %t", raw, got)
		}
	}
	if allowedDownloadURL(origin, nil) {
		t.Fatal("nil redirect allowed")
	}

	for status, code := range map[int]string{http.StatusFound: "redirect_not_allowed", http.StatusForbidden: "forbidden", http.StatusTooManyRequests: "rate_limited"} {
		value := response(status, "error")
		if status == http.StatusTooManyRequests {
			value.Header.Set("X-RateLimit-Reset", "invalid")
		}
		var apiErr APIError
		if err := classifyHTTPError(value); !errors.As(err, &apiErr) || apiErr.Code != code {
			t.Fatalf("status %d error = %#v", status, err)
		}
	}
	secondary := response(http.StatusForbidden, "error")
	secondary.Header.Set("Retry-After", "1")
	var apiErr APIError
	if err := classifyHTTPError(secondary); !errors.As(err, &apiErr) || apiErr.Code != "secondary_rate_limited" {
		t.Fatalf("secondary rate limit = %v", err)
	}
}

func TestRESTPathQueryAndProjectionHelpers(t *testing.T) {
	binding := opbinding.Binding{PathTemplate: "/repos/{owner}/{repo}/issues/{issue_number}",
		PathParameters:       []string{"owner", "repo", "issue_number"},
		TargetPathParameters: []opbinding.TargetParameter{{Name: "owner", Field: "owner"}, {Name: "repo", Field: "name"}},
		ArgumentParameters:   []opbinding.Parameter{{Name: "labels", In: "query"}, {Name: "page", In: "query"}, {Name: "active", In: "query"}, {Name: "body", In: "body"}}}
	path, err := restPath(binding, map[string]any{"owner": "acme", "name": "demo"}, map[string]any{"issue_number": json.Number("12")})
	if err != nil || path != "/repos/acme/demo/issues/12" {
		t.Fatalf("path = %q, %v", path, err)
	}
	query, err := restQuery(binding, map[string]any{"labels": []any{"bug", "urgent"}, "page": float64(2), "active": true, "body": "ignored"})
	if err != nil || query.Encode() != "active=true&labels=bug&labels=urgent&page=2" {
		t.Fatalf("query = %q, %v", query.Encode(), err)
	}
	if _, err := restQuery(binding, map[string]any{"labels": map[string]any{"bad": true}}); err == nil {
		t.Fatal("invalid query value accepted")
	}
	query, err = restQuery(binding, map[string]any{"page": json.Number("2"), "active": true})
	if err != nil || query.Encode() != "active=true&page=2" {
		t.Fatalf("json.Number query = %q, %v", query.Encode(), err)
	}
	if _, err := restPath(binding, map[string]any{"owner": "acme", "name": "demo"}, map[string]any{"issue_number": 1.5}); err == nil {
		t.Fatal("fractional path value accepted")
	}

	value := map[string]any{"repository": map[string]any{"id": 7, "owner": map[string]any{"login": "acme"}}, "secret": "hidden"}
	projected, ok := projectJSON(value, []string{"repository.id", "repository.owner.login"})
	encoded, _ := json.Marshal(projected)
	if !ok || string(encoded) != `{"repository":{"id":7,"owner":{"login":"acme"}}}` {
		t.Fatalf("path projection = %s, %t", encoded, ok)
	}
	projected, ok = projectJSON([]any{value}, []string{"id"})
	if !ok {
		t.Fatalf("name projection = %#v, %t", projected, ok)
	}
	if _, ok := projectJSON(value, []string{"missing.path"}); ok {
		t.Fatal("missing projection was retained")
	}
	if projected, ok := projectJSON(value, nil); !ok || projected == nil {
		t.Fatal("empty projection did not preserve value")
	}
	projected, ok = projectRESTResponse(map[string]any{"id": 7, "owner": map[string]any{"id": 8}}, []string{"id"})
	encoded, _ = json.Marshal(projected)
	if !ok || string(encoded) != `{"id":7}` {
		t.Fatalf("REST projection retained nested fields = %s, %t", encoded, ok)
	}
	projected, ok = projectRESTResponse([]any{map[string]any{"id": 7, "owner": value}}, []string{"id"})
	encoded, _ = json.Marshal(projected)
	if !ok || string(encoded) != `[{"id":7}]` {
		t.Fatalf("REST list projection = %s, %t", encoded, ok)
	}
	projected, ok = projectRESTResponse(value, []string{"repository.id", "repository.owner.login"})
	encoded, _ = json.Marshal(projected)
	if !ok || string(encoded) != `{"repository":{"id":7,"owner":{"login":"acme"}}}` {
		t.Fatalf("REST path projection = %s, %t", encoded, ok)
	}
	projected, ok = projectJSON(map[string]any{"total_count": 1, "artifacts": []any{map[string]any{"id": 7, "secret": "hidden"}}}, []string{"id"})
	encoded, _ = json.Marshal(projected)
	if !ok || string(encoded) != `{"artifacts":[{"id":7}]}` {
		t.Fatalf("REST container projection = %s, %t", encoded, ok)
	}
	for _, test := range []struct {
		value any
		want  string
	}{
		{[]any{"one", "two"}, `["one","two"]`},
		{[]any{map[string]any{"secret": "hidden"}}, `[{}]`},
		{[]any{[]any{float64(1), float64(2)}}, `[[1,2]]`},
	} {
		_, ok = projectJSON(test.value, []string{"$none"})
		if ok {
			t.Fatal("$none unexpectedly retained a projected field")
		}
		encoded, _ = json.Marshal(emptyProjection(test.value))
		if string(encoded) != test.want {
			t.Fatalf("empty projection = %s, want %s", encoded, test.want)
		}
	}
}

func TestRESTURLsPreserveEnterprisePrefixAndUseUploadOrigin(t *testing.T) {
	enterprise, _ := url.Parse("https://ghe.example/api/v3/")
	manager := &Manager{apiURL: enterprise}
	got, err := manager.bindingRESTURL(opbinding.Binding{ServerRole: "api"}, "/repos/acme/demo", url.Values{"page": {"2"}})
	if err != nil || got != "https://ghe.example/api/v3/repos/acme/demo?page=2" {
		t.Fatalf("enterprise URL = %q, %v", got, err)
	}
	got, err = manager.bindingRESTURL(opbinding.Binding{ServerRole: "uploads"}, "/repos/acme/demo/releases/1/assets", nil)
	if err != nil || got != "https://ghe.example/api/v3/repos/acme/demo/releases/1/assets" {
		t.Fatalf("enterprise upload URL = %q, %v", got, err)
	}
	manager.apiURL, _ = url.Parse("https://api.github.com/")
	got, err = manager.bindingRESTURL(opbinding.Binding{ServerRole: "uploads"}, "/repos/acme/demo/releases/1/assets", nil)
	if err != nil || got != "https://uploads.github.com/repos/acme/demo/releases/1/assets" {
		t.Fatalf("GitHub.com upload URL = %q, %v", got, err)
	}
}

func TestExecuteRESTPollsAcceptedReadsWithoutReplayingMutations(t *testing.T) {
	var reads, writes int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			reads++
			if reads < 3 {
				w.WriteHeader(http.StatusAccepted)
				return
			}
			_, _ = io.WriteString(w, `{"id":7}`)
			return
		}
		writes++
		w.WriteHeader(http.StatusAccepted)
	}))
	t.Cleanup(server.Close)
	manager := newDevelopmentManager(t, server.URL)
	binding := opbinding.Binding{Method: http.MethodGet, PathTemplate: "/stats", MediaType: "application/json", ServerRole: "api",
		RequestBytesLimit: 32, ResponseBytesLimit: 32, ResponseProjection: []string{"id"}, ResponseRootType: "object"}
	result, err := manager.ExecuteREST(t.Context(), manager.development.Metadata(), binding, nil, nil)
	if err != nil || reads != 3 || string(result.Body) != `{"id":7}` {
		t.Fatalf("accepted read = %s, reads=%d, err=%v", result.Body, reads, err)
	}
	binding.Method = http.MethodPost
	result, err = manager.ExecuteREST(t.Context(), manager.development.Metadata(), binding, nil, nil)
	if err != nil || writes != 1 || result.StatusCode != http.StatusAccepted {
		t.Fatalf("accepted mutation = %+v, writes=%d, err=%v", result, writes, err)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) { return f(request) }

func TestStreamRequestsUseTransferTimeout(t *testing.T) {
	t.Parallel()
	apiURL, _ := url.Parse("https://api.github.test/")
	manager := &Manager{
		apiURL: apiURL, client: &http.Client{Timeout: time.Second}, streamTimeout: 10 * time.Minute,
		development: &Credential{metadata: Metadata{Kind: KindDevelopmentToken, APIHost: apiURL.Host}, token: []byte("token")},
	}
	client, credential, err := manager.requestClient(t.Context(), manager.development.Metadata(), manager.streamTimeout)
	if err != nil || credential != manager.development || client.Timeout != 10*time.Minute || manager.client.Timeout != time.Second {
		t.Fatalf("stream client = %+v credential=%p err=%v", client, credential, err)
	}
	if redirectClient := manager.streamClient(); redirectClient.Timeout != 10*time.Minute || manager.client.Timeout != time.Second {
		t.Fatalf("redirect stream client timeout = %s", redirectClient.Timeout)
	}
}

func TestCredentialClientsAndTransportFailures(t *testing.T) {
	apiURL, _ := url.Parse("https://api.github.test/")
	baseClient := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("offline")
	})}
	manager := &Manager{apiURL: apiURL, client: baseClient, app: &appProvider{round: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return responseForTest(http.StatusOK, `{}`), nil
	})}}
	if client, credential, err := manager.clientForMetadata(t.Context(), Metadata{Kind: KindAppJWT, APIHost: apiURL.Host}); err != nil || client == nil || credential != nil {
		t.Fatalf("app client = %v, %v, %v", client, credential, err)
	}
	for kind, selector := range map[Kind]Metadata{
		KindInstallation:     {Kind: KindInstallation, InstallationID: 1, APIHost: apiURL.Host},
		KindUser:             {Kind: KindUser, UserID: 1, APIHost: apiURL.Host},
		KindDevelopmentToken: {Kind: KindDevelopmentToken, APIHost: apiURL.Host},
		Kind("unknown"):      {Kind: Kind("unknown"), APIHost: apiURL.Host},
	} {
		if _, _, err := manager.clientForMetadata(t.Context(), selector); err == nil {
			t.Fatalf("unavailable %s credential client succeeded", kind)
		}
	}
	development := newDevelopmentManager(t, "http://127.0.0.1")
	if client, credential, err := development.clientForMetadata(t.Context(), development.development.Metadata()); err != nil || client == nil || credential == nil {
		t.Fatalf("development client = %v, %v, %v", client, credential, err)
	}
	if _, _, err := manager.clientForMetadata(t.Context(), Metadata{Kind: KindAppJWT, APIHost: "api.other.test"}); err == nil {
		t.Fatal("credential selector crossed its immutable API host")
	}
	request := httptest.NewRequest(http.MethodGet, "https://api.github.test/repos", http.NoBody)
	if _, err := manager.doAPIRequest(t.Context(), Metadata{Kind: KindAppJWT, APIHost: apiURL.Host}, request); err == nil {
		t.Fatal("transport failure was accepted")
	}
	if _, err := manager.doAPI(t.Context(), Metadata{Kind: KindAppJWT, APIHost: apiURL.Host}, request.Clone(t.Context())); err == nil {
		t.Fatal("API transport failure was accepted")
	}
}

func TestRedirectAndHelperEdgeCases(t *testing.T) {
	origin, _ := url.Parse("https://api.github.test/archive")
	redirectClient := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		response := responseForTest(http.StatusFound, "")
		response.Header.Set("Location", "https://api.github.test/archive")
		return response, nil
	})}
	manager := &Manager{client: redirectClient}
	initial := responseForTest(http.StatusFound, "")
	initial.Header.Set("Location", "https://api.github.test/archive")
	if _, err := manager.followDownloadRedirects(t.Context(), origin, initial); err == nil {
		t.Fatal("redirect loop accepted")
	}
	missing := responseForTest(http.StatusFound, "")
	if _, err := manager.followDownloadRedirects(t.Context(), origin, missing); err == nil {
		t.Fatal("redirect without location accepted")
	}
	failure := &Manager{client: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("offline")
	})}}
	initial = responseForTest(http.StatusFound, "")
	initial.Header.Set("Location", "https://api.github.test/archive")
	if _, err := failure.followDownloadRedirects(t.Context(), origin, initial); err == nil {
		t.Fatal("redirect transport failure accepted")
	}
	if _, err := manager.followDownloadRedirects(t.Context(), origin, responseForTest(http.StatusForbidden, "")); err == nil {
		t.Fatal("download error status accepted")
	}

	if value, err := targetPathValue("issue_number", "number", map[string]any{"number": float64(7)}); err != nil || value != "7" {
		t.Fatalf("numeric target path = %q, %v", value, err)
	}
	if _, err := targetPathValue("owner", "owner", map[string]any{}); err == nil {
		t.Fatal("missing target path accepted")
	}
	if value, ok := integerValue(int64(9)); !ok || value != 9 {
		t.Fatalf("int64 value = %d, %t", value, ok)
	}
	if _, ok := integerValue(json.Number("bad")); ok {
		t.Fatal("invalid JSON number accepted")
	}
	if ids := repositoryIDs(map[string]any{"repository_ids": "bad"}); ids != nil {
		t.Fatalf("invalid repository ids = %v", ids)
	}
	if projected, ok := projectByPath([]any{map[string]any{"id": 1}, map[string]any{"hidden": true}}, map[string]bool{"id": true}, ""); !ok || len(projected.([]any)) != 1 {
		t.Fatalf("array projection = %#v, %t", projected, ok)
	}
	if _, ok := projectByPath("value", map[string]bool{"other": true}, "id"); ok {
		t.Fatal("unlisted scalar projected")
	}
}

func TestGenericExecutionRejectsMalformedRequestsBeforeUpstream(t *testing.T) {
	manager := newDevelopmentManager(t, "http://127.0.0.1")
	binding := opbinding.Binding{Method: http.MethodPost, PathTemplate: "/repos/{owner}/{repo}", MediaType: "application/json",
		PathParameters: []string{"owner", "repo"}, TargetPathParameters: []opbinding.TargetParameter{{Name: "owner", Field: "owner"}, {Name: "repo", Field: "name"}},
		RequestBytesLimit: 2, ResponseBytesLimit: 16, ResponseProjection: []string{"id"}}
	if _, err := manager.ExecuteREST(t.Context(), manager.development.Metadata(), binding,
		map[string]any{"owner": "acme", "name": "demo"}, map[string]any{"input": map[string]any{"value": "too large"}}); err == nil {
		t.Fatal("oversized REST request accepted")
	}
	if _, err := manager.ExecuteREST(t.Context(), manager.development.Metadata(), binding,
		map[string]any{"owner": "acme"}, map[string]any{}); err == nil {
		t.Fatal("incomplete REST target accepted")
	}
	if _, err := manager.ExecuteRESTDownload(t.Context(), manager.development.Metadata(), binding, nil, nil); err == nil {
		t.Fatal("non-download binding accepted")
	}
	var nilManager *Manager
	if _, err := nilManager.ExecuteGraphQL(t.Context(), Metadata{}, graphqlmanifest.Document{}, nil); err == nil {
		t.Fatal("nil manager executed GraphQL")
	}
	if _, err := nilManager.ExecuteRESTUpload(t.Context(), Metadata{}, binding, nil, nil, strings.NewReader("x"), 1, "application/octet-stream"); err == nil {
		t.Fatal("nil manager uploaded a stream")
	}
	if _, err := manager.restURL("/%zz", nil); err == nil {
		t.Fatal("invalid escaped path accepted")
	}
	if _, err := argumentPathValue("id", map[string]any{"id": json.Number("17")}); err != nil {
		t.Fatal(err)
	}
	if err := addQueryValue(url.Values{}, "empty", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := formatQueryNumber(json.Number("not-a-number")); err == nil {
		t.Fatal("invalid JSON number was accepted")
	}
}

func responseForTest(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}
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
