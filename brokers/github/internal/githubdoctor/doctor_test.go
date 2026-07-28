package githubdoctor

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/osolmaz/unyolo/brokers/github/internal/config"
	"github.com/osolmaz/unyolo/brokers/github/internal/githubauth"
	"github.com/osolmaz/unyolo/credential/store"
	unyolodoctor "github.com/osolmaz/unyolo/internal/host/doctor"
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
			_, _ = w.Write([]byte(`[]`))
		case "/repos/osolmaz/repo/branches/main/protection":
			_, _ = w.Write([]byte(`{"required_status_checks":null}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer api.Close()
	oldLookup := lookupIdentity
	lookupIdentity = func(name string) (unyolodoctor.Identity, error) {
		if name == "bob" {
			return unyolodoctor.Identity{User: name, UID: 1000, GID: 1000}, nil
		}
		return unyolodoctor.Identity{User: name, UID: 1001, GID: 1001}, nil
	}
	t.Cleanup(func() { lookupIdentity = oldLookup })
	report, err := Run(context.Background(), config.Config{Environment: "local", GitHubToken: "github-token", GitHubTokenFile: "/protected/github-token"}, Options{
		AgentUser: "bob", ServiceUser: "gh-broker", Repo: "osolmaz/repo",
		RequireProtection: true, APIBaseURL: mustURL(t, api.URL), HTTPClient: api.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if report.Status != unyolodoctor.StatusInconclusive {
		t.Fatalf("report = %+v", report)
	}
	assertCheck(t, report.Checks, "github_repo_visible", unyolodoctor.CheckPass)
	assertCheck(t, report.Checks, "github_default_branch_protected", unyolodoctor.CheckPass)
}

func TestPermissionCheck(t *testing.T) {
	if got := permissionCheck(map[string]string{"contents": "read"}); got.Status != unyolodoctor.CheckPass {
		t.Fatalf("required permissions = %+v", got)
	}
	if got := permissionCheck(map[string]string{"contents": "write", "pull_requests": "write", "administration": "write"}); got.Status != unyolodoctor.CheckFail {
		t.Fatalf("administrative permissions = %+v", got)
	}
	if got := permissionCheck(map[string]string{}); got.Status != unyolodoctor.CheckFail {
		t.Fatalf("missing permissions = %+v", got)
	}
}

func TestDevelopmentTokenDoctorIsUnsafeInProduction(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/acme/repo":
			_, _ = io.WriteString(w, `{"default_branch":"main"}`)
		case "/repos/acme/repo/rules/branches/main":
			_, _ = io.WriteString(w, `[]`)
		case "/repos/acme/repo/branches/main/protection":
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(api.Close)
	apis, checks := githubDoctorAPI(t.Context(), config.Config{Environment: "production", GitHubToken: "dev-canary", GitHubTokenFile: "/protected/token"},
		mustURL(t, api.URL), api.Client(), "acme", "repo", true)
	if apis.repository == nil || apis.protection == nil {
		t.Fatal("development API unavailable")
	}
	assertCheck(t, checks, "github_development_token", unyolodoctor.CheckFail)
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
		if check.Status != unyolodoctor.CheckUnknown || !strings.HasPrefix(check.Name, "inline_") {
			t.Fatalf("inline check = %+v", check)
		}
	}
	if checks := inlineCredentialChecks(config.Config{ // #nosec G101 -- synthetic values exercise source classification only.
		SharedSecret: "file-client-secret", SecretsFile: "/etc/gh-broker/secrets",
		GitHubToken: "file-github-token", GitHubTokenFile: "/etc/gh-broker/github-token",
		TelegramBotToken: "file-telegram-token", TelegramBotTokenFile: "/etc/gh-broker/telegram-bot-token",
	}); len(checks) != 0 {
		t.Fatalf("file credential checks = %+v", checks)
	}
}

func TestGitHubDoctorAPIMintsAppCredential(t *testing.T) {
	var tokenMints int
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/app":
			_, _ = w.Write([]byte(`{"id":12345}`))
		case "/repos/osolmaz/repo/installation":
			_, _ = w.Write([]byte(`{"id":42}`))
		case "/app/installations/42/access_tokens":
			tokenMints++
			switch tokenMints {
			case 1:
				_, _ = w.Write([]byte(`{"token":"bootstrap-token","expires_at":"2099-07-09T18:00:00Z"}`))
			case 2:
				_, _ = w.Write([]byte(`{"token":"installation-token","expires_at":"2099-07-09T18:00:00Z","permissions":{"contents":"read"}}`))
			default:
				_, _ = w.Write([]byte(`{"token":"protection-token","expires_at":"2099-07-09T18:00:00Z","permissions":{"administration":"read"}}`))
			}
		case "/repos/osolmaz/repo":
			_, _ = w.Write([]byte(`{"id":99,"name":"repo","owner":{"login":"osolmaz"}}`))
		case "/installation/token":
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	defer api.Close()
	apis, checks := githubDoctorAPI(context.Background(), config.Config{
		GitHubAppID: "12345", GitHubAppPrivateKey: doctorPrivateKey(t),
	}, mustURL(t, api.URL), api.Client(), "osolmaz", "repo", true)
	if apis.repository == nil || apis.protection == nil {
		t.Fatal("GitHub doctor API is nil")
	}
	assertCheck(t, checks, "github_app_jwt", unyolodoctor.CheckPass)
	assertCheck(t, checks, "github_installation_token", unyolodoctor.CheckPass)
	assertCheck(t, checks, "github_app_permissions", unyolodoctor.CheckPass)
	assertCheck(t, checks, "github_protection_token", unyolodoctor.CheckPass)
	assertCheck(t, checks, "github_protection_permissions", unyolodoctor.CheckPass)
	if tokenMints != 3 {
		t.Fatalf("installation token mints = %d", tokenMints)
	}
}

func TestGitHubDoctorAPIReportsCredentialFailures(t *testing.T) {
	if apis, checks := githubDoctorAPI(context.Background(), config.Config{}, mustURL(t, "https://api.github.com"), http.DefaultClient, "owner", "repo", true); apis.repository != nil || checks[0].Status != unyolodoctor.CheckFail {
		t.Fatalf("invalid app credential result = %v, %+v", apis, checks)
	}
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "denied", http.StatusForbidden)
	}))
	defer api.Close()
	apis, checks := githubDoctorAPI(context.Background(), config.Config{
		GitHubAppID: "12345", GitHubAppPrivateKey: doctorPrivateKey(t),
	}, mustURL(t, api.URL), api.Client(), "owner", "repo", true)
	if apis.repository != nil {
		t.Fatal("failed GitHub App returned an API client")
	}
	assertCheck(t, checks, "github_app_jwt", unyolodoctor.CheckFail)
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
	manager, err := githubauth.New(githubauth.Config{DevelopmentToken: []byte("token"), DevelopmentTokenFile: "/protected/token", APIBaseURL: mustURL(t, api.URL), HTTPClient: api.Client()})
	if err != nil {
		t.Fatal(err)
	}
	credential, _ := manager.RepositoryCredential(context.Background(), "repo.contents.read", "owner", "repo")
	client, _ := manager.API(credential)
	protected, err := client.BranchProtected(context.Background(), "owner", "repo", "main")
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
	if check.Status != unyolodoctor.CheckWarn {
		t.Fatalf("optional protection = %+v", check)
	}
}

func TestProtectionCheckDistinguishesAbsentAndInconclusive(t *testing.T) {
	unknown := protectionCheck(true, false, githubauth.APIError{Code: "forbidden", StatusCode: http.StatusForbidden})
	if unknown.Status != unyolodoctor.CheckUnknown {
		t.Fatalf("forbidden protection check = %+v", unknown)
	}
	missing := protectionCheck(true, false, githubauth.APIError{Code: "not_found", StatusCode: http.StatusNotFound})
	if missing.Status != unyolodoctor.CheckFail {
		t.Fatalf("missing protection check = %+v", missing)
	}
}

func TestStoredCredentialStatusesReportExactExpiryWithoutValues(t *testing.T) {
	stateDir := t.TempDir()
	store, err := githubauth.OpenUserCredentialStore(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 15, 0, 0, 0, 0, time.UTC)
	payload := map[string]any{
		"user_id": 7, "login": "agent-a", "access_token": []byte("access-canary"), "refresh_token": []byte("refresh-canary"),
		"access_expires_at": now.Add(7 * 24 * time.Hour), "refresh_expires_at": now.Add(30 * 24 * time.Hour),
	}
	encoded, _ := json.Marshal(payload)
	if _, err := store.Put("github-user-7", "github-app-user-token", encoded); err != nil {
		t.Fatal(err)
	}
	if _, err := githubauth.InspectStoredUserCredentials(stateDir); err != nil {
		t.Fatalf("inspect stored credentials: %v", err)
	}
	statuses, check := storedCredentialStatuses(stateDir, now)
	if check == nil || check.Status != unyolodoctor.CheckPass || len(statuses) != 2 {
		t.Fatalf("statuses=%+v check=%+v", statuses, check)
	}
	if statuses[0].ExpiresAt == "" || statuses[0].Source != unyolodoctor.CredentialSourceEncryptedStore {
		t.Fatalf("access status = %+v", statuses[0])
	}
	output, _ := json.Marshal(statuses)
	for _, forbidden := range []string{"agent-a", "access-canary", "refresh-canary"} {
		if strings.Contains(string(output), forbidden) {
			t.Fatalf("stored status leaked %q: %s", forbidden, output)
		}
	}
	if _, err := credentialstore.OpenNamespaceExisting(stateDir, "github-users"); err != nil {
		t.Fatal(err)
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

func assertCheck(t *testing.T, checks []unyolodoctor.Check, name string, status unyolodoctor.CheckStatus) {
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
