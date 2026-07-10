package githubdoctor

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	bkdoctor "github.com/osolmaz/brokerkit/doctor"
	"github.com/osolmaz/gh-broker/internal/config"
)

func TestRunWithTokenChecksRepoAndRuleset(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer github-token" {
			t.Fatalf("authorization header was not configured")
		}
		switch r.URL.Path {
		case "/repos/osolmaz/repo":
			_, _ = w.Write([]byte(`{"default_branch":"main"}`))
		case "/repos/osolmaz/repo/rules/branches/main":
			_, _ = w.Write([]byte(`[{}]`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer api.Close()
	oldLookup := lookupIdentity
	lookupIdentity = func(name string) (bkdoctor.Identity, error) {
		if name == "bob" {
			return bkdoctor.Identity{User: name, UID: 1000, GID: 1000}, nil
		}
		return bkdoctor.Identity{User: name, UID: 1001, GID: 1001}, nil
	}
	t.Cleanup(func() { lookupIdentity = oldLookup })
	report, err := Run(context.Background(), config.Config{GitHubToken: "github-token"}, Options{
		AgentUser: "bob", ServiceUser: "gh-broker", Repo: "osolmaz/repo",
		RequireProtection: true, APIBaseURL: mustURL(t, api.URL), HTTPClient: api.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if report.Status != bkdoctor.StatusInconclusive {
		t.Fatalf("report = %+v", report)
	}
	assertCheck(t, report.Checks, "github_repo_visible", bkdoctor.CheckPass)
	assertCheck(t, report.Checks, "github_default_branch_protected", bkdoctor.CheckPass)
}

func TestPermissionCheck(t *testing.T) {
	if got := permissionCheck(map[string]string{"contents": "write", "pull_requests": "write"}); got.Status != bkdoctor.CheckPass {
		t.Fatalf("required permissions = %+v", got)
	}
	if got := permissionCheck(map[string]string{"contents": "write", "pull_requests": "write", "administration": "write"}); got.Status != bkdoctor.CheckFail {
		t.Fatalf("administrative permissions = %+v", got)
	}
	if got := permissionCheck(map[string]string{"contents": "write", "pull_requests": "write", "workflows": "write"}); got.Status != bkdoctor.CheckFail {
		t.Fatalf("unexpected write permissions = %+v", got)
	}
	if got := permissionCheck(map[string]string{"contents": "write", "pull_requests": "write", "issues": "read"}); got.Status != bkdoctor.CheckFail {
		t.Fatalf("unexpected read permissions = %+v", got)
	}
	if got := permissionCheck(map[string]string{"contents": "read"}); got.Status != bkdoctor.CheckFail {
		t.Fatalf("missing permissions = %+v", got)
	}
}

func TestInlineCredentialChecksAreInconclusive(t *testing.T) {
	checks := inlineCredentialChecks(config.Config{ // #nosec G101 -- synthetic values exercise source classification only.
		SharedSecret:        "inline-client-secret",
		GitHubToken:         "inline-github-token",
		GitHubWebhookSecret: "inline-webhook-secret",
		TelegramBotToken:    "inline-telegram-token",
	})
	if len(checks) != 4 {
		t.Fatalf("inline checks = %+v", checks)
	}
	for _, check := range checks {
		if check.Status != bkdoctor.CheckUnknown || !strings.HasPrefix(check.Name, "inline_") {
			t.Fatalf("inline check = %+v", check)
		}
	}
	if checks := inlineCredentialChecks(config.Config{ // #nosec G101 -- synthetic values exercise source classification only.
		SharedSecret: "file-client-secret", SecretsFile: "/etc/gh-broker/secrets",
		GitHubToken: "file-github-token", GitHubTokenFile: "/etc/gh-broker/github-token",
	}); len(checks) != 0 {
		t.Fatalf("file credential checks = %+v", checks)
	}
}

func TestGitHubDoctorTokenMintsAppCredential(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/osolmaz/repo/installation":
			_, _ = w.Write([]byte(`{"id":42}`))
		case "/app/installations/42/access_tokens":
			_, _ = w.Write([]byte(`{"token":"installation-token","permissions":{"contents":"write","pull_requests":"write"}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer api.Close()
	token, checks := githubDoctorToken(context.Background(), config.Config{
		GitHubToken: "stale-fallback-token", GitHubAppID: "12345", GitHubAppPrivateKey: doctorPrivateKey(t),
	}, mustURL(t, api.URL), api.Client(), "osolmaz", "repo")
	if token != "installation-token" {
		t.Fatalf("token = %q", token)
	}
	assertCheck(t, checks, "github_app_jwt", bkdoctor.CheckPass)
	assertCheck(t, checks, "github_installation_token", bkdoctor.CheckPass)
	assertCheck(t, checks, "github_app_permissions", bkdoctor.CheckPass)
}

func TestGitHubDoctorTokenReportsCredentialFailures(t *testing.T) {
	if token, checks := githubDoctorToken(context.Background(), config.Config{}, mustURL(t, "https://api.github.com"), http.DefaultClient, "owner", "repo"); token != "" || checks[0].Status != bkdoctor.CheckFail {
		t.Fatalf("invalid app credential result = %q, %+v", token, checks)
	}
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "denied", http.StatusForbidden)
	}))
	defer api.Close()
	token, checks := githubDoctorToken(context.Background(), config.Config{
		GitHubAppID: "12345", GitHubAppPrivateKey: doctorPrivateKey(t),
	}, mustURL(t, api.URL), api.Client(), "owner", "repo")
	if token != "" {
		t.Fatalf("failed mint token = %q", token)
	}
	assertCheck(t, checks, "github_installation_token", bkdoctor.CheckFail)
}

func TestBranchProtectedFallsBackToClassicProtection(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/rules/") {
			_, _ = w.Write([]byte(`[]`))
			return
		}
		_, _ = w.Write([]byte(`{"required_status_checks":null}`))
	}))
	defer api.Close()
	protected, err := branchProtected(context.Background(), api.Client(), mustURL(t, api.URL), "token", "owner", "repo", "main")
	if err != nil || !protected {
		t.Fatalf("branchProtected() = %t, %v", protected, err)
	}
}

func TestParseRepoAndOptionalProtection(t *testing.T) {
	owner, repo, err := parseRepo("osolmaz/repo")
	if err != nil || owner != "osolmaz" || repo != "repo" {
		t.Fatalf("parseRepo() = %q, %q, %v", owner, repo, err)
	}
	if _, _, err := parseRepo("bad"); err == nil {
		t.Fatal("parseRepo(bad) error = nil")
	}
	check := protectionCheck(false, false, nil)
	if check.Status != bkdoctor.CheckWarn {
		t.Fatalf("optional protection = %+v", check)
	}
}

func TestProtectionCheckDistinguishesAbsentAndInconclusive(t *testing.T) {
	unknown := protectionCheck(true, false, githubStatusError{code: http.StatusForbidden})
	if unknown.Status != bkdoctor.CheckUnknown {
		t.Fatalf("forbidden protection check = %+v", unknown)
	}
	missing := protectionCheck(true, false, githubStatusError{code: http.StatusNotFound})
	if missing.Status != bkdoctor.CheckFail {
		t.Fatalf("missing protection check = %+v", missing)
	}
}

func TestGitHubJSONRejectsUnsafeResponses(t *testing.T) {
	tests := map[string]struct {
		status int
		body   string
	}{
		"status":    {status: http.StatusForbidden, body: `{}`},
		"invalid":   {status: http.StatusOK, body: `{`},
		"oversized": {status: http.StatusOK, body: `{"value":"` + strings.Repeat("x", maxDoctorResponseBytes) + `"}`},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(test.status)
				_, _ = w.Write([]byte(test.body))
			}))
			defer api.Close()
			var payload map[string]any
			if err := githubJSON(context.Background(), api.Client(), mustURL(t, api.URL), "token", &payload); err == nil {
				t.Fatal("githubJSON() error = nil")
			}
		})
	}
}

func doctorPrivateKey(t *testing.T) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
}

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	parsed, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

func assertCheck(t *testing.T, checks []bkdoctor.Check, name string, status bkdoctor.CheckStatus) {
	t.Helper()
	for _, check := range checks {
		if check.Name == name {
			if check.Status != status {
				t.Fatalf("check %s = %+v", name, check)
			}
			return
		}
	}
	t.Fatalf("check %s missing", name)
}
