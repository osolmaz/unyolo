package githubapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestReaderInspectsDefaultBranchAndProtection(t *testing.T) {
	t.Parallel()
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer token" {
			t.Fatal("missing authorization")
		}
		switch r.URL.Path {
		case "/repos/owner/repo":
			_, _ = w.Write([]byte(`{"default_branch":"main"}`))
		case "/repos/owner/repo/rules/branches/main":
			_, _ = w.Write([]byte(`[{}]`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer api.Close()
	reader := Reader{BaseURL: mustURL(t, api.URL), HTTPClient: api.Client()}
	branch, err := reader.DefaultBranch(context.Background(), "token", "owner", "repo")
	if err != nil || branch != "main" {
		t.Fatalf("DefaultBranch() = %q, %v", branch, err)
	}
	protected, err := reader.BranchProtected(context.Background(), "token", "owner", "repo", branch)
	if err != nil || !protected {
		t.Fatalf("BranchProtected() = %v, %v", protected, err)
	}
}

func TestReaderFallsBackAndFailsClosed(t *testing.T) {
	t.Parallel()
	tests := map[string]struct {
		handler   http.HandlerFunc
		protected bool
		wantErr   bool
	}{
		"classic": {handler: func(w http.ResponseWriter, r *http.Request) {
			if strings.Contains(r.URL.Path, "/rules/") {
				_, _ = w.Write([]byte(`[]`))
				return
			}
			_, _ = w.Write([]byte(`{"required_status_checks":null}`))
		}, protected: true},
		"absent":    {handler: func(w http.ResponseWriter, r *http.Request) { http.NotFound(w, r) }},
		"forbidden": {handler: func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "denied", http.StatusForbidden) }, wantErr: true},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			api := httptest.NewServer(test.handler)
			defer api.Close()
			got, err := (Reader{BaseURL: mustURL(t, api.URL), HTTPClient: api.Client()}).BranchProtected(t.Context(), "token", "owner", "repo", "main")
			if got != test.protected || (err != nil) != test.wantErr {
				t.Fatalf("BranchProtected() = %v, %v", got, err)
			}
		})
	}
}

func TestReaderRejectsUnsafeResponses(t *testing.T) {
	t.Parallel()
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Query().Get("case") {
		case "large":
			_, _ = w.Write([]byte(`{"default_branch":"` + strings.Repeat("x", maxResponseBytes) + `"}`))
		case "bad":
			_, _ = w.Write([]byte(`{`))
		default:
			http.Error(w, "denied", http.StatusForbidden)
		}
	}))
	defer api.Close()
	reader := Reader{BaseURL: mustURL(t, api.URL), HTTPClient: api.Client()}
	for _, query := range []string{"", "?case=bad", "?case=large"} {
		reader.BaseURL, _ = url.Parse(api.URL + query)
		if _, err := reader.DefaultBranch(t.Context(), "token", "owner", "repo"); err == nil {
			t.Fatalf("query %q was accepted", query)
		}
	}
	if code, ok := StatusCode(StatusError{Code: http.StatusForbidden}); !ok || code != http.StatusForbidden {
		t.Fatalf("StatusCode() = %d, %v", code, ok)
	}
}

func mustURL(t *testing.T, value string) *url.URL {
	t.Helper()
	parsed, err := url.Parse(value)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}
