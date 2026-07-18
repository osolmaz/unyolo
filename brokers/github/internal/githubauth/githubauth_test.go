package githubauth

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	github "github.com/google/go-github/v88/github"
	"github.com/osolmaz/brokerkit/audit"
	"github.com/osolmaz/brokerkit/credentiallifecycle"
	"github.com/osolmaz/brokerkit/credentialstore"
)

func TestInstallationCredentialsUseExactImmutableCacheTuple(t *testing.T) {
	now := time.Date(2026, 7, 14, 1, 0, 0, 0, time.UTC)
	var requests []map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/repos/acme/private/installation":
			assertAppJWT(t, r)
			_, _ = io.WriteString(w, `{"id":42,"permissions":{"contents":"write","pull_requests":"write"}}`)
		case "/app/installations/42/access_tokens":
			assertAppJWT(t, r)
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			requests = append(requests, body)
			if _, ok := body["repositories"]; ok {
				_, _ = io.WriteString(w, `{"token":"bootstrap-canary","expires_at":"2026-07-14T02:00:00Z"}`)
				return
			}
			_, _ = io.WriteString(w, `{"token":"exact-canary-`+string(rune('0'+len(requests)))+`","expires_at":"2026-07-14T02:00:00Z"}`)
		case "/repos/acme/private":
			if r.Header.Get("Authorization") != "Bearer bootstrap-canary" {
				t.Fatalf("bootstrap authorization = %q", r.Header.Get("Authorization"))
			}
			_, _ = io.WriteString(w, `{"id":99,"name":"private","owner":{"login":"acme"}}`)
		case "/installation/token":
			if r.Header.Get("Authorization") != "Bearer bootstrap-canary" {
				t.Fatalf("revoke authorization = %q", r.Header.Get("Authorization"))
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	manager := newAppTestManager(t, server, func() time.Time { return now })

	first, err := manager.RepositoryCredential(t.Context(), "repo.contents.read", "acme", "private")
	if err != nil {
		t.Fatal(err)
	}
	second, err := manager.RepositoryCredential(t.Context(), "repo.contents.read", "acme", "private")
	if err != nil || first != second {
		t.Fatalf("cache result = %p %p, %v", first, second, err)
	}
	metadata := first.Metadata()
	if metadata.Kind != KindInstallation || metadata.InstallationID != 42 || !slices.Equal(metadata.RepositoryIDs, []int64{99}) || metadata.Permissions["contents"] != "read" {
		t.Fatalf("metadata = %+v", metadata)
	}
	resolvedMetadata, err := manager.ResolveRepository(t.Context(), "repo.contents.read", "acme", "private")
	if err != nil || !slices.Equal(resolvedMetadata.RepositoryIDs, []int64{99}) {
		t.Fatalf("resolved metadata = %+v, %v", resolvedMetadata, err)
	}
	if len(requests) != 2 {
		t.Fatalf("token requests = %d, want bootstrap plus one exact mint", len(requests))
	}
	assertExactTokenRequest(t, requests[1], []int64{99}, map[string]string{"contents": "read"})

	pullRequest, err := manager.RepositoryCredential(t.Context(), "pull_request.create", "acme", "private")
	if err != nil || pullRequest == first {
		t.Fatalf("permission-specific credential = %p, %v", pullRequest, err)
	}
	if len(requests) != 3 {
		t.Fatalf("token requests = %d, want separate permission tuple", len(requests))
	}
	assertExactTokenRequest(t, requests[2], []int64{99}, map[string]string{"pull_requests": "write"})

	direct, err := manager.InstallationCredential(t.Context(), 42, []int64{7, 5, 7}, map[string]string{"issues": "read"})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(direct.Metadata().RepositoryIDs, []int64{5, 7}) {
		t.Fatalf("canonical repository ids = %v", direct.Metadata().RepositoryIDs)
	}
	assertExactTokenRequest(t, requests[3], []int64{5, 7}, map[string]string{"issues": "read"})

	manager.InvalidateInstallation(42, true)
	request, _ := http.NewRequest(http.MethodGet, server.URL, http.NoBody)
	if err := first.AuthorizeAPI(request); err == nil {
		t.Fatal("invalidated cached credential remained usable")
	}
	if _, err := manager.RepositoryCredential(t.Context(), "repo.contents.read", "acme", "private"); err == nil {
		t.Fatal("suspended installation minted a credential")
	}
}

func TestDevelopmentTokenNormalizesProtectedFileNewline(t *testing.T) {
	manager, err := New(Config{DevelopmentToken: []byte("test-token\n"), DevelopmentTokenFile: "/protected/token"})
	if err != nil {
		t.Fatal(err)
	}
	request, _ := http.NewRequest(http.MethodGet, "https://api.github.test", http.NoBody)
	if err := manager.development.AuthorizeAPI(request); err != nil {
		t.Fatal(err)
	}
	if got := request.Header.Get("Authorization"); got != "Bearer test-token" {
		t.Fatalf("authorization = %q", got)
	}
	invalid, err := New(Config{DevelopmentToken: []byte("bad token"), DevelopmentTokenFile: "/protected/token"})
	if err != nil {
		t.Fatal(err)
	}
	if err := invalid.development.AuthorizeAPI(request); err == nil {
		t.Fatal("token with embedded whitespace authorized a request")
	}
}

func TestInstallationCredentialExpiryAndErrorsAreDeterministicAndRedacted(t *testing.T) {
	now := time.Date(2026, 7, 14, 1, 0, 0, 0, time.UTC)
	mints := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/app/installations/42/access_tokens" {
			http.NotFound(w, r)
			return
		}
		mints++
		if mints == 3 {
			http.Error(w, "credential-canary-upstream", http.StatusForbidden)
			return
		}
		expires := "2026-07-14T02:00:00Z"
		if mints > 1 {
			expires = "2026-07-14T03:00:00Z"
		}
		_, _ = io.WriteString(w, `{"token":"credential-canary","expires_at":"`+expires+`"}`)
	}))
	t.Cleanup(server.Close)
	manager := newAppTestManager(t, server, func() time.Time { return now })
	first, err := manager.InstallationCredential(t.Context(), 42, []int64{99}, map[string]string{"contents": "read"})
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(59 * time.Minute)
	second, err := manager.InstallationCredential(t.Context(), 42, []int64{99}, map[string]string{"contents": "read"})
	if err != nil || first == second || mints != 2 {
		t.Fatalf("expiry refresh = %p %p mints=%d err=%v", first, second, mints, err)
	}
	_, err = manager.InstallationCredential(t.Context(), 42, []int64{100}, map[string]string{"contents": "read"})
	if err == nil || strings.Contains(err.Error(), "credential-canary") || !strings.Contains(err.Error(), "forbidden") {
		t.Fatalf("redacted error = %v", err)
	}
	if _, err := manager.InstallationCredential(t.Context(), 0, []int64{1}, nil); err == nil {
		t.Fatal("zero installation id accepted")
	}
	if _, err := manager.InstallationCredential(t.Context(), 1, []int64{1}, map[string]string{"unknown": "write"}); err == nil {
		t.Fatal("unknown permission accepted")
	}
}

func TestInstallationPermissionsSupportPinnedCatalogBeyondSDK(t *testing.T) {
	permissions, err := installationPermissions(map[string]string{"agent_secrets": "write", "issue_fields": "read"}, false)
	if err != nil {
		t.Fatal(err)
	}
	if permissions["agent_secrets"] != "write" || permissions["issue_fields"] != "read" {
		t.Fatalf("permissions = %+v", permissions)
	}
	if _, err := installationPermissions(map[string]string{"not_pinned": "read"}, false); err == nil {
		t.Fatal("unknown permission accepted")
	}
	if permissions, err := installationPermissions(nil, true); err != nil || len(permissions) != 0 {
		t.Fatalf("reviewed empty permissions = %v, %v", permissions, err)
	}
}

func TestReviewedPermissionlessInstallationCredentialSendsExplicitEmptyMap(t *testing.T) {
	now := time.Date(2026, 7, 14, 1, 0, 0, 0, time.UTC)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		var body map[string]any
		if json.NewDecoder(request.Body).Decode(&body) != nil {
			t.Fatal("installation token request was not JSON")
		}
		permissions, found := body["permissions"].(map[string]any)
		if !found || len(permissions) != 0 {
			t.Fatalf("permissions = %#v, want explicit empty object", body["permissions"])
		}
		_, _ = io.WriteString(w, `{"token":"permissionless-canary","expires_at":"2026-07-14T02:00:00Z"}`)
	}))
	t.Cleanup(server.Close)
	manager := newAppTestManager(t, server, func() time.Time { return now })
	credential, err := manager.installationCredential(t.Context(), 42, nil, nil, true)
	if err != nil || !credential.Metadata().AllowEmptyPermissions {
		t.Fatalf("permissionless credential = %+v, %v", credential, err)
	}
}

func TestInstallationInvalidationWinsAgainstConcurrentMint(t *testing.T) {
	now := time.Date(2026, 7, 14, 1, 0, 0, 0, time.UTC)
	mintStarted := make(chan struct{})
	releaseMint := make(chan struct{})
	revoked := make(chan struct{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/app/installations/42/access_tokens":
			close(mintStarted)
			<-releaseMint
			_, _ = io.WriteString(w, `{"token":"racing-installation-canary","expires_at":"2026-07-14T02:00:00Z"}`)
		case "/installation/token":
			revoked <- struct{}{}
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	manager := newAppTestManager(t, server, func() time.Time { return now })

	result := make(chan error, 1)
	go func() {
		_, err := manager.InstallationCredential(t.Context(), 42, []int64{99}, map[string]string{"contents": "read"})
		result <- err
	}()
	<-mintStarted
	manager.InvalidateInstallation(42, true)
	close(releaseMint)
	if err := <-result; err == nil {
		t.Fatal("credential minted across invalidation")
	}
	select {
	case <-revoked:
	case <-time.After(time.Second):
		t.Fatal("credential minted across invalidation was not revoked")
	}
}

func TestAppInstallationPaginationUsesSDKResponseLinks(t *testing.T) {
	var pages []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pages = append(pages, r.URL.Query().Get("page"))
		if r.URL.Query().Get("page") == "2" {
			_, _ = io.WriteString(w, `[{"id":77}]`)
			return
		}
		w.Header().Set("Link", `<`+serverURL(r)+`/app/installations?page=2>; rel="next"`)
		_, _ = io.WriteString(w, `[{"id":42}]`)
	}))
	t.Cleanup(server.Close)
	manager := newAppTestManager(t, server, time.Now)
	ids, err := manager.Installations(t.Context())
	if err != nil || !slices.Equal(ids, []int64{42, 77}) || !slices.Equal(pages, []string{"1", "2"}) {
		t.Fatalf("installations = %v pages=%v err=%v", ids, pages, err)
	}
}

func TestAppCheckAndInstallationForAccount(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assertAppJWT(t, r)
		switch r.URL.Path {
		case "/app":
			_, _ = io.WriteString(w, `{"id":12345}`)
		case "/app/installations":
			_, _ = io.WriteString(w, `[
				{"id":0,"account":{"login":"ignored"}},
				{"id":41,"account":{"login":"ACME"},"suspended_at":"2026-07-14T02:00:00Z"},
				{"id":42,"account":{"login":"Acme"}}
			]`)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	manager := newAppTestManager(t, server, time.Now)

	if err := manager.CheckApp(t.Context()); err != nil {
		t.Fatal(err)
	}
	metadata, err := manager.InstallationForAccount(t.Context(), " acme ")
	if err != nil || metadata.Kind != KindInstallation || metadata.InstallationID != 42 || metadata.APIHost == "" {
		t.Fatalf("account metadata = %+v, %v", metadata, err)
	}
	if _, err := manager.InstallationForAccount(t.Context(), "missing"); err == nil {
		t.Fatal("missing account resolved to an installation")
	}
}

func TestTypedDoctorAPIAndDevelopmentCredential(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/repos/acme/repo":
			_, _ = io.WriteString(w, `{"default_branch":"main"}`)
		case "/repos/acme/empty":
			_, _ = io.WriteString(w, `{}`)
		case "/repos/acme/repo/rules/branches/main":
			_, _ = io.WriteString(w, `[{"type":"deletion"}]`)
		case "/repos/acme/open/rules/branches/main", "/repos/acme/open/branches/main/protection":
			http.NotFound(w, r)
		case "/repos/acme/denied/rules/branches/main":
			http.Error(w, `{"message":"credential-canary"}`, http.StatusForbidden)
		case "/repos/acme/denied/branches/main/protection":
			http.NotFound(w, r)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	base, _ := url.Parse(server.URL)
	manager, err := New(Config{DevelopmentToken: []byte("development-canary"), DevelopmentTokenFile: "/protected/token",
		APIBaseURL: base, WebBaseURL: base, HTTPClient: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	credential, err := manager.RepositoryCredential(t.Context(), "repo.contents.read", "acme", "repo")
	if err != nil || manager.CredentialKind() != KindDevelopmentToken {
		t.Fatalf("development credential = %v, %v", credential, err)
	}
	api, err := manager.API(credential)
	if err != nil {
		t.Fatal(err)
	}
	branch, err := api.DefaultBranch(t.Context(), "acme", "repo")
	if err != nil || branch != "main" {
		t.Fatalf("default branch = %q, %v", branch, err)
	}
	if _, err := api.DefaultBranch(t.Context(), "acme", "empty"); err == nil {
		t.Fatal("empty default branch response accepted")
	}
	protected, err := api.BranchProtected(t.Context(), "acme", "repo", "main")
	if err != nil || !protected {
		t.Fatalf("protected = %t, %v", protected, err)
	}
	protected, err = api.BranchProtected(t.Context(), "acme", "open", "main")
	if err != nil || protected {
		t.Fatalf("open branch protected = %t, %v", protected, err)
	}
	if _, err := api.BranchProtected(t.Context(), "acme", "denied", "main"); err == nil || strings.Contains(err.Error(), "canary") {
		t.Fatalf("branch error was not redacted: %v", err)
	}
	request := httptest.NewRequest(http.MethodGet, server.URL, http.NoBody)
	if err := credential.AuthorizeGit(request); err != nil || !strings.HasPrefix(request.Header.Get("Authorization"), "Basic ") {
		t.Fatalf("git authorization = %q, %v", request.Header.Get("Authorization"), err)
	}
}

func TestUserEnrollmentRefreshRotationAndRevocationAreEncrypted(t *testing.T) {
	now := time.Date(2026, 7, 14, 1, 0, 0, 0, time.UTC)
	var revoked []string
	refreshes := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/user":
			auth := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
			if auth == "" {
				t.Fatal("user verification omitted authorization")
			}
			_, _ = io.WriteString(w, `{"id":7,"login":"bob"}`)
		case "/login/oauth/access_token":
			refreshes++
			if err := r.ParseForm(); err != nil || r.Form.Get("refresh_token") != "refresh-canary-one" || r.Form.Get("client_secret") != "client-secret-canary" {
				t.Fatalf("refresh form = %v, %v", r.Form, err)
			}
			_, _ = io.WriteString(w, `{"access_token":"access-canary-two","expires_in":28800,"refresh_token":"refresh-canary-two","refresh_token_expires_in":15897600,"token_type":"bearer"}`)
		case "/applications/client-id/token":
			username, password, ok := r.BasicAuth()
			if !ok || username != "client-id" || password != "client-secret-canary" {
				t.Fatal("revocation omitted app basic authentication")
			}
			var body struct {
				AccessToken string `json:"access_token"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			revoked = append(revoked, body.AccessToken)
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	stateDir := t.TempDir()
	store, err := credentialstore.Open(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	manager := newUserTestManager(t, server, store, func() time.Time { return now })
	enrollment := UserEnrollment{UserID: 7, Login: "bob", AccessToken: []byte("access-canary-one"), RefreshToken: []byte("refresh-canary-one"),
		AccessExpiresAt: now.Add(time.Hour), RefreshExpiresAt: now.Add(30 * 24 * time.Hour)}
	if err := manager.EnrollUser(t.Context(), enrollment); err != nil {
		t.Fatal(err)
	}
	assertEncryptedStoreCanariesAbsent(t, stateDir, "access-canary-one", "refresh-canary-one")
	credential, err := manager.UserCredential(t.Context(), 7)
	if err != nil {
		t.Fatal(err)
	}
	assertBearer(t, credential, "access-canary-one")
	snapshot, err := manager.CurrentSnapshot(t.Context(), Metadata{Kind: KindUser, UserID: 7}, 3, now)
	if err != nil || snapshot.Generation != 3 || snapshot.CredentialKind != string(KindUser) {
		t.Fatalf("current user snapshot = %+v, %v", snapshot, err)
	}
	cached, err := manager.UserCredential(t.Context(), 7)
	if err != nil || cached != credential {
		t.Fatalf("cached user credential = %p %p, %v", credential, cached, err)
	}

	now = now.Add(59 * time.Minute)
	refreshed, err := manager.UserCredential(t.Context(), 7)
	if err != nil || refreshes != 1 {
		t.Fatalf("refresh credential = %v refreshes=%d", err, refreshes)
	}
	assertBearer(t, refreshed, "access-canary-two")
	if err := credential.AuthorizeAPI(&http.Request{Header: make(http.Header)}); err == nil {
		t.Fatal("old user credential remained active after refresh")
	}
	assertEncryptedStoreCanariesAbsent(t, stateDir, "access-canary-two", "refresh-canary-two")

	if err := manager.RevokeUser(t.Context(), 7); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(revoked, []string{"access-canary-two"}) || store.Exists(userSlot(7)) {
		t.Fatalf("revoked=%v slot_exists=%t", revoked, store.Exists(userSlot(7)))
	}
	if err := refreshed.AuthorizeAPI(&http.Request{Header: make(http.Header)}); err == nil {
		t.Fatal("revoked active credential remained usable")
	}
}

func TestUserRotationAndWebhookInvalidationHaveNoReadback(t *testing.T) {
	now := time.Date(2026, 7, 14, 1, 0, 0, 0, time.UTC)
	var revoked []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/user":
			_, _ = io.WriteString(w, `{"id":7,"login":"bob"}`)
		case "/applications/client-id/token":
			var body struct {
				AccessToken string `json:"access_token"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			revoked = append(revoked, body.AccessToken)
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	store, _ := credentialstore.Open(t.TempDir())
	manager := newUserTestManager(t, server, store, func() time.Time { return now })
	first := UserEnrollment{UserID: 7, Login: "bob", AccessToken: []byte("old-access-canary"), RefreshToken: []byte("old-refresh-canary"), AccessExpiresAt: now.Add(time.Hour), RefreshExpiresAt: now.Add(24 * time.Hour)}
	second := UserEnrollment{UserID: 7, Login: "bob", AccessToken: []byte("new-access-canary"), RefreshToken: []byte("new-refresh-canary"), AccessExpiresAt: now.Add(2 * time.Hour), RefreshExpiresAt: now.Add(48 * time.Hour)}
	if err := manager.EnrollUser(t.Context(), first); err != nil {
		t.Fatal(err)
	}
	if err := manager.RotateUser(t.Context(), second); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(revoked, []string{"old-access-canary"}) {
		t.Fatalf("rotation revoked = %v", revoked)
	}
	active, err := manager.UserCredential(t.Context(), 7)
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.InvalidateUser(7); err != nil {
		t.Fatal(err)
	}
	if store.Exists(userSlot(7)) || active.AuthorizeAPI(&http.Request{Header: make(http.Header)}) == nil {
		t.Fatal("authorization revocation did not immediately invalidate storage and memory")
	}
}

func TestUserLifecycleAuditRecordsProviderRevocationOutcome(t *testing.T) {
	now := time.Date(2026, 7, 14, 1, 0, 0, 0, time.UTC)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/user":
			_, _ = io.WriteString(w, `{"id":7,"login":"agent-a"}`)
		case "/applications/client-id/token":
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	store, err := credentialstore.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	reporter, err := credentiallifecycle.New(audit.New(&output), "gh-broker", "operator-a")
	if err != nil {
		t.Fatal(err)
	}
	base, _ := url.Parse(server.URL)
	manager, err := New(Config{AppClientID: "client-id", AppClientSecret: []byte("client-secret-canary"), APIBaseURL: base, WebBaseURL: base,
		HTTPClient: server.Client(), Store: store, Now: func() time.Time { return now }, Lifecycle: reporter})
	if err != nil {
		t.Fatal(err)
	}
	enrollment := UserEnrollment{UserID: 7, Login: "agent-a", AccessToken: []byte("access-canary"), RefreshToken: []byte("refresh-canary"),
		AccessExpiresAt: now.Add(time.Hour), RefreshExpiresAt: now.Add(24 * time.Hour)}
	if err := manager.EnrollUser(t.Context(), enrollment); err != nil {
		t.Fatal(err)
	}
	if err := manager.RevokeUser(t.Context(), 7); err != nil {
		t.Fatal(err)
	}
	got := output.String()
	for _, want := range []string{`"lifecycle_action":"created"`, `"lifecycle_action":"revoked"`, `"lifecycle_outcome":"succeeded"`, `"previous_id":"github-user:7"`} {
		if !strings.Contains(got, want) {
			t.Fatalf("lifecycle audit missing %s: %s", want, got)
		}
	}
	for _, forbidden := range []string{"access-canary", "refresh-canary", "client-secret-canary"} {
		if strings.Contains(got, forbidden) {
			t.Fatalf("lifecycle audit leaked %q: %s", forbidden, got)
		}
	}
}

func TestUserRotationRevocationFailureRestoresOldCredentialAndAuditsFailure(t *testing.T) {
	now := time.Date(2026, 7, 14, 1, 0, 0, 0, time.UTC)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/user":
			_, _ = io.WriteString(w, `{"id":7,"login":"agent-a"}`)
		case "/applications/client-id/token":
			http.Error(w, "provider-canary", http.StatusServiceUnavailable)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	store, err := credentialstore.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	reporter, _ := credentiallifecycle.New(audit.New(&output), "gh-broker", "operator-a")
	base, _ := url.Parse(server.URL)
	manager, err := New(Config{AppClientID: "client-id", AppClientSecret: []byte("client-secret-canary"), APIBaseURL: base, WebBaseURL: base,
		HTTPClient: server.Client(), Store: store, Now: func() time.Time { return now }, Lifecycle: reporter})
	if err != nil {
		t.Fatal(err)
	}
	old := UserEnrollment{UserID: 7, Login: "agent-a", AccessToken: []byte("old-access-canary"), RefreshToken: []byte("old-refresh-canary"),
		AccessExpiresAt: now.Add(time.Hour), RefreshExpiresAt: now.Add(24 * time.Hour)}
	newValue := UserEnrollment{UserID: 7, Login: "agent-a", AccessToken: []byte("new-access-canary"), RefreshToken: []byte("new-refresh-canary"),
		AccessExpiresAt: now.Add(2 * time.Hour), RefreshExpiresAt: now.Add(48 * time.Hour)}
	if err := manager.EnrollUser(t.Context(), old); err != nil {
		t.Fatal(err)
	}
	if err := manager.RotateUser(t.Context(), newValue); err == nil || strings.Contains(err.Error(), "provider-canary") {
		t.Fatalf("rotation error = %v", err)
	}
	credential, err := manager.UserCredential(t.Context(), 7)
	if err != nil {
		t.Fatal(err)
	}
	assertBearer(t, credential, "old-access-canary")
	got := output.String()
	if !strings.Contains(got, `"lifecycle_action":"rotated"`) || !strings.Contains(got, `"lifecycle_outcome":"failed"`) {
		t.Fatalf("failed rotation audit = %s", got)
	}
	for _, forbidden := range []string{"old-access-canary", "new-access-canary", "provider-canary"} {
		if strings.Contains(got, forbidden) {
			t.Fatalf("failed rotation audit leaked %q: %s", forbidden, got)
		}
	}
}

func TestInspectStoredUserCredentialsReturnsOnlyLifecycleMetadata(t *testing.T) {
	now := time.Date(2026, 7, 14, 1, 0, 0, 0, time.UTC)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/user" {
			_, _ = io.WriteString(w, `{"id":7,"login":"agent-a"}`)
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(server.Close)
	stateDir := t.TempDir()
	store, err := OpenUserCredentialStore(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	base, _ := url.Parse(server.URL)
	manager, err := New(Config{AppClientID: "client-id", AppClientSecret: []byte("client-secret-canary"), APIBaseURL: base, WebBaseURL: base,
		HTTPClient: server.Client(), Store: store, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	enrollment := UserEnrollment{UserID: 7, Login: "agent-a", AccessToken: []byte("access-canary"), RefreshToken: []byte("refresh-canary"),
		AccessExpiresAt: now.Add(time.Hour), RefreshExpiresAt: now.Add(24 * time.Hour)}
	if err := manager.EnrollUser(t.Context(), enrollment); err != nil {
		t.Fatal(err)
	}
	statuses, err := InspectStoredUserCredentials(stateDir)
	if err != nil || len(statuses) != 1 || statuses[0].UserID != 7 || !statuses[0].AccessExpiresAt.Equal(enrollment.AccessExpiresAt) {
		t.Fatalf("statuses = %+v, %v", statuses, err)
	}
	encoded, err := json.Marshal(statuses)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"agent-a", "access-canary", "refresh-canary", "client-secret-canary"} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("stored metadata leaked %q: %s", forbidden, encoded)
		}
	}
}

func TestUserInvalidationWinsAgainstConcurrentRefresh(t *testing.T) {
	now := time.Date(2026, 7, 14, 1, 0, 0, 0, time.UTC)
	refreshStarted := make(chan struct{})
	releaseRefresh := make(chan struct{})
	var once sync.Once
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/user":
			_, _ = io.WriteString(w, `{"id":7,"login":"bob"}`)
		case "/login/oauth/access_token":
			once.Do(func() { close(refreshStarted) })
			<-releaseRefresh
			_, _ = io.WriteString(w, `{"access_token":"refreshed-race-canary","expires_in":28800,"refresh_token":"refreshed-race-refresh","refresh_token_expires_in":15897600,"token_type":"bearer"}`)
		case "/applications/client-id/token":
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	store, err := credentialstore.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	manager := newUserTestManager(t, server, store, func() time.Time { return now })
	enrollment := UserEnrollment{UserID: 7, Login: "bob", AccessToken: []byte("stale-race-canary"), RefreshToken: []byte("stale-race-refresh"),
		AccessExpiresAt: now.Add(time.Hour), RefreshExpiresAt: now.Add(24 * time.Hour)}
	if err := manager.EnrollUser(t.Context(), enrollment); err != nil {
		t.Fatal(err)
	}
	now = now.Add(59 * time.Minute)
	type credentialResult struct {
		credential *Credential
		err        error
	}
	result := make(chan credentialResult, 1)
	go func() {
		credential, credentialErr := manager.UserCredential(t.Context(), 7)
		result <- credentialResult{credential: credential, err: credentialErr}
	}()
	<-refreshStarted
	invalidated := make(chan error, 1)
	go func() { invalidated <- manager.InvalidateUser(7) }()
	select {
	case err := <-invalidated:
		t.Fatalf("invalidation did not serialize with credential refresh: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	close(releaseRefresh)
	loaded := <-result
	if loaded.err != nil {
		t.Fatalf("serialized credential refresh failed: %v", loaded.err)
	}
	if err := <-invalidated; err != nil {
		t.Fatal(err)
	}
	if store.Exists(userSlot(7)) {
		t.Fatal("concurrent refresh resurrected invalidated user credential")
	}
	if loaded.credential.AuthorizeAPI(&http.Request{Header: make(http.Header)}) == nil {
		t.Fatal("credential loaded before invalidation remained active")
	}
}

func TestWebhookValidationAndInvalidationMetadata(t *testing.T) {
	secret := []byte("webhook-secret-canary")
	cases := []struct {
		event string
		body  string
		check func(*testing.T, WebhookEvent)
	}{
		{event: "installation", body: `{"action":"suspend","installation":{"id":42}}`, check: func(t *testing.T, event WebhookEvent) {
			if !event.DisableInstallation || !event.InvalidateInstallation || event.InstallationID != 42 {
				t.Fatalf("event = %+v", event)
			}
		}},
		{event: "installation_repositories", body: `{"action":"removed","installation":{"id":42},"repositories_removed":[{"full_name":"acme/private"}]}`, check: func(t *testing.T, event WebhookEvent) {
			if !event.InvalidateInstallation || event.Repository != "acme/private" {
				t.Fatalf("event = %+v", event)
			}
		}},
		{event: "github_app_authorization", body: `{"action":"revoked","sender":{"id":7,"login":"bob"}}`, check: func(t *testing.T, event WebhookEvent) {
			if event.RevokedUserID != 7 {
				t.Fatalf("event = %+v", event)
			}
		}},
		{event: "repository", body: `{"action":"renamed","installation":{"id":42},"repository":{"full_name":"acme/renamed"}}`, check: func(t *testing.T, event WebhookEvent) {
			if !event.InvalidateInstallation || event.InstallationID != 42 || event.Repository != "acme/renamed" {
				t.Fatalf("event = %+v", event)
			}
		}},
		{event: "push", body: `{"ref":"refs/heads/main","repository":{"full_name":"acme/repo"}}`, check: func(t *testing.T, event WebhookEvent) {
			if event.Action != "" || event.Event != "push" {
				t.Fatalf("event = %+v", event)
			}
		}},
	}
	for _, test := range cases {
		t.Run(test.event, func(t *testing.T) {
			body := []byte(test.body)
			headers := http.Header{"X-Github-Event": {test.event}, "X-Github-Delivery": {"delivery"}, "X-Hub-Signature-256": {webhookSignature(secret, body)}}
			event, err := ParseWebhook(headers, body, secret)
			if err != nil {
				t.Fatal(err)
			}
			test.check(t, event)
		})
	}
	body := []byte(cases[0].body)
	headers := http.Header{"X-Github-Event": {"installation"}, "X-Github-Delivery": {"delivery"}, "X-Hub-Signature-256": {webhookSignature([]byte("wrong"), body)}}
	if _, err := ParseWebhook(headers, body, secret); !errors.Is(err, ErrWebhookSignature) || strings.Contains(err.Error(), "canary") {
		t.Fatalf("signature error = %v", err)
	}
}

func TestDevelopmentTokenAndURLValidationFailClosed(t *testing.T) {
	if _, err := New(Config{DevelopmentToken: []byte("canary")}); err == nil {
		t.Fatal("inline development credential accepted")
	}
	badURL, _ := url.Parse("http://github.example.com/api/v3")
	if _, err := New(Config{DevelopmentToken: []byte("canary"), DevelopmentTokenFile: "/protected/token", APIBaseURL: badURL}); err == nil {
		t.Fatal("insecure non-local API URL accepted")
	}
	if got := (APIError{Code: "forbidden", StatusCode: 403}).Error(); strings.Contains(got, "canary") || len(got) > 100 {
		t.Fatalf("API error is not bounded: %q", got)
	}
	response := &http.Response{StatusCode: http.StatusTooManyRequests}
	err := classifyAPIError(&github.RateLimitError{Response: response, Rate: github.Rate{Reset: github.Timestamp{Time: time.Unix(10, 0)}}})
	var apiErr APIError
	if !errors.As(err, &apiErr) || apiErr.Code != "rate_limited" || apiErr.RateReset.Unix() != 10 {
		t.Fatalf("rate limit classification = %#v", err)
	}
}

func TestDecodeUserEnrollmentIsStrictAndBounded(t *testing.T) {
	data := []byte(`{"user_id":7,"login":"bob","access_token":"access-canary","refresh_token":"refresh-canary","access_expires_at":"2026-07-14T12:00:00Z","refresh_expires_at":"2026-10-14T12:00:00Z"}`)
	enrollment, err := DecodeUserEnrollment(data)
	if err != nil || enrollment.UserID != 7 || string(enrollment.AccessToken) != "access-canary" {
		t.Fatalf("enrollment = %+v, %v", enrollment, err)
	}
	zeroStored(&enrollment)
	for _, invalid := range [][]byte{
		nil,
		[]byte(`{"user_id":7,"unknown":true}`),
		[]byte(`{"user_id":7,"user_id":8}`),
		bytes.Repeat([]byte("x"), maxOAuthBodyBytes+1),
	} {
		if _, err := DecodeUserEnrollment(invalid); err == nil {
			t.Fatalf("invalid enrollment accepted: %q", invalid[:min(len(invalid), 80)])
		}
	}
	var nilCredential *Credential
	if nilCredential.Metadata().Kind != "" || nilCredential.AuthorizeAPI(nil) == nil || nilCredential.AuthorizeGit(nil) == nil {
		t.Fatal("nil credential did not fail closed")
	}
}

func TestCredentialBoundaryHelpersFailClosed(t *testing.T) {
	var manager *Manager
	if manager.CredentialKind() != KindDevelopmentToken {
		t.Fatal("nil manager credential kind changed")
	}
	for _, call := range []func() error{
		func() error { return manager.CheckApp(t.Context()) },
		func() error { _, err := manager.RepositoryCredential(t.Context(), "op", "owner", "repo"); return err },
		func() error { _, err := manager.ResolveRepository(t.Context(), "op", "owner", "repo"); return err },
		func() error { _, err := manager.InstallationCredential(t.Context(), 1, []int64{1}, nil); return err },
		func() error { _, err := manager.UserCredential(t.Context(), 1); return err },
		func() error { return manager.EnrollUser(t.Context(), UserEnrollment{}) },
		func() error { return manager.RotateUser(t.Context(), UserEnrollment{}) },
		func() error { return manager.RevokeUser(t.Context(), 1) },
		func() error { _, err := manager.API(nil); return err },
		func() error { _, err := manager.Installations(t.Context()); return err },
	} {
		if err := call(); err == nil {
			t.Fatal("nil manager operation succeeded")
		}
	}
	manager.EnableInstallation(1)
	manager.InvalidateInstallation(1, true)
	if err := manager.InvalidateUser(1); err != nil {
		t.Fatal(err)
	}
	for status, want := range map[int]string{401: "unauthorized", 403: "forbidden", 404: "not_found", 409: "conflict", 422: "validation_failed", 429: "rate_limited", 500: "upstream_error"} {
		if got := statusCodeName(status); got != want {
			t.Fatalf("status %d = %q, want %q", status, got, want)
		}
	}
	if status, ok := StatusCode(APIError{Code: "conflict", StatusCode: 409}); !ok || status != 409 || IsNotFound(APIError{Code: "conflict", StatusCode: 409}) {
		t.Fatal("API error status helpers failed")
	}
	if !IsNotFound(APIError{Code: "not_found", StatusCode: 404}) {
		t.Fatal("not-found API error was not recognized")
	}
	if _, ok := StatusCode(errors.New("plain")); ok || responseStatus(nil) != 0 || (APIError{Code: "unavailable"}).Error() != "GitHub API request failed (unavailable)" {
		t.Fatal("plain and status-less errors changed")
	}
	if err := classifyAPIError(errors.New("credential-canary")); strings.Contains(err.Error(), "canary") {
		t.Fatalf("plain upstream error leaked details: %v", err)
	}
	abuse := classifyAPIError(&github.AbuseRateLimitError{Response: &http.Response{StatusCode: http.StatusForbidden}})
	var abuseAPIError APIError
	if !errors.As(abuse, &abuseAPIError) || abuseAPIError.Code != "secondary_rate_limited" {
		t.Fatalf("secondary rate limit = %v", abuse)
	}
	for _, operation := range []string{"git.fetch", "git.push.force", "git.ref.delete"} {
		if permissions, err := permissionsForOperation(operation); err != nil || len(permissions) == 0 {
			t.Fatalf("permissions for %q = %v, %v", operation, permissions, err)
		}
	}
	if _, err := permissionsForOperation("unknown.operation"); err == nil {
		t.Fatal("unknown operation received a credential binding")
	}
	if canonicalRepositoryIDs([]int64{1, 0}) != nil || installationPermissionMap(nil) != nil {
		t.Fatal("invalid repository ids or nil permissions were accepted")
	}
	redirectRequest := httptest.NewRequest(http.MethodGet, "https://example.test", http.NoBody)
	if !errors.Is(stopRedirect(redirectRequest, nil), http.ErrUseLastResponse) {
		t.Fatal("redirect policy changed")
	}
	badWebURL, _ := url.Parse("http://github.example.test/?query=1")
	if _, err := normalizeWebURL(badWebURL); err == nil || clonePermissions(nil) != nil {
		t.Fatal("invalid web URL or nil permissions changed")
	}
	if transport(nil) == nil || cloneHTTPClient(nil, http.DefaultTransport).Timeout != 30*time.Second {
		t.Fatal("default HTTP transport or timeout changed")
	}
	var api *API
	if _, err := api.DefaultBranch(t.Context(), "owner", "repo"); err == nil {
		t.Fatal("nil API returned a default branch")
	}
	if _, err := api.BranchProtected(t.Context(), "owner", "repo", "main"); err == nil {
		t.Fatal("nil API returned branch protection")
	}
	for _, cfg := range []Config{
		{},
		{AppID: "1", AppPrivateKey: []byte("bad"), DevelopmentToken: []byte("token"), DevelopmentTokenFile: "/protected/token"},
		{AppID: "bad", AppPrivateKey: []byte("bad")},
		{AppID: "1", AppPrivateKey: []byte("bad")},
	} {
		if _, err := New(cfg); err == nil {
			t.Fatalf("invalid config accepted: %+v", cfg)
		}
	}
	provider := newInstallationProvider(nil, &url.URL{Scheme: "https", Host: "api.github.test"}, nil, time.Now, time.Minute, nil)
	oldest := &Credential{token: []byte("oldest")}
	provider.cache["oldest"] = cacheEntry{credential: oldest, refreshAt: time.Unix(1, 0)}
	provider.cache["newest"] = cacheEntry{credential: &Credential{token: []byte("newest")}, refreshAt: time.Unix(2, 0)}
	provider.evictOldest()
	if len(provider.cache) != 1 || provider.cache["newest"].credential == nil || oldest.AuthorizeAPI(&http.Request{Header: make(http.Header)}) == nil {
		t.Fatal("oldest credential was not evicted and invalidated")
	}
	provider.disabled[42] = true
	provider.enable(42)
	if provider.disabled[42] {
		t.Fatal("installation was not re-enabled")
	}
	var nilProvider *installationProvider
	nilProvider.enable(42)
	nilProvider.invalidate(42, true)
	if err := nilProvider.revokeCredential(t.Context(), nil); err == nil {
		t.Fatal("revokeCredential(nil) error = nil, want unavailable")
	}
	var nilOpaqueCredential *Credential
	nilOpaqueCredential.invalidate()
	if firstRepository(nil, nil) != nil || repositoryName(nil) != "" {
		t.Fatal("empty webhook repository helpers changed")
	}
	if name := repositoryName(&github.Repository{Name: ptr("repo"), Owner: &github.User{Login: ptr("owner")}}); name != "owner/repo" {
		t.Fatalf("repository name = %q", name)
	}
	if name := repositoryName(&github.Repository{Name: ptr("repo")}); name != "" {
		t.Fatalf("ownerless repository name = %q", name)
	}
}

func newAppTestManager(t *testing.T, server *httptest.Server, now func() time.Time) *Manager {
	t.Helper()
	base, _ := url.Parse(server.URL)
	manager, err := New(Config{AppID: "12345", AppPrivateKey: testPrivateKey(t), APIBaseURL: base, WebBaseURL: base, HTTPClient: server.Client(), Now: now})
	if err != nil {
		t.Fatal(err)
	}
	return manager
}

func newUserTestManager(t *testing.T, server *httptest.Server, store *credentialstore.Store, now func() time.Time) *Manager {
	t.Helper()
	base, _ := url.Parse(server.URL)
	manager, err := New(Config{AppClientID: "client-id", AppClientSecret: []byte("client-secret-canary"), APIBaseURL: base, WebBaseURL: base,
		HTTPClient: server.Client(), Store: store, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	return manager
}

func testPrivateKey(t *testing.T) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
}

func assertAppJWT(t *testing.T, request *http.Request) {
	t.Helper()
	value := strings.TrimPrefix(request.Header.Get("Authorization"), "Bearer ")
	if len(strings.Split(value, ".")) != 3 || request.Header.Get("X-GitHub-Api-Version") != APIVersion {
		t.Fatalf("app authentication headers = %q %q", request.Header.Get("Authorization"), request.Header.Get("X-GitHub-Api-Version"))
	}
}

func assertExactTokenRequest(t *testing.T, body map[string]any, ids []int64, permissions map[string]string) {
	t.Helper()
	if _, exists := body["repositories"]; exists {
		t.Fatalf("exact token used repository names: %v", body)
	}
	rawIDs, _ := body["repository_ids"].([]any)
	gotIDs := make([]int64, 0, len(rawIDs))
	for _, raw := range rawIDs {
		gotIDs = append(gotIDs, int64(raw.(float64)))
	}
	rawPermissions, _ := body["permissions"].(map[string]any)
	gotPermissions := map[string]string{}
	for key, raw := range rawPermissions {
		gotPermissions[key] = raw.(string)
	}
	if !slices.Equal(gotIDs, ids) || !mapsEqual(gotPermissions, permissions) {
		t.Fatalf("exact token body = %v, want ids=%v permissions=%v", body, ids, permissions)
	}
}

func mapsEqual(left, right map[string]string) bool {
	if len(left) != len(right) {
		return false
	}
	for key, value := range left {
		if right[key] != value {
			return false
		}
	}
	return true
}

func assertBearer(t *testing.T, credential *Credential, token string) {
	t.Helper()
	request := &http.Request{Header: make(http.Header)}
	if err := credential.AuthorizeAPI(request); err != nil || request.Header.Get("Authorization") != "Bearer "+token {
		t.Fatalf("credential authorization = %q, %v", request.Header.Get("Authorization"), err)
	}
}

func assertEncryptedStoreCanariesAbsent(t *testing.T, stateDir string, canaries ...string) {
	t.Helper()
	// The store path is intentionally not exported; locate the single encrypted
	// record through the test's temporary state tree.
	files, _ := filepath.Glob(filepath.Join(stateDir, "credential-slots", "*.json"))
	if len(files) != 1 {
		t.Fatalf("encrypted records = %v", files)
	}
	encoded, _ := os.ReadFile(files[0])
	for _, canary := range canaries {
		if bytes.Contains(encoded, []byte(canary)) {
			t.Fatalf("encrypted store leaked %q", canary)
		}
	}
}

func webhookSignature(secret, body []byte) string {
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

func serverURL(request *http.Request) string { return "http://" + request.Host }
