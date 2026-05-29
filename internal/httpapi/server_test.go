package httpapi

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/dutifuldev/gitcba/internal/config"
	"github.com/dutifuldev/gitcba/internal/githubaccess"
)

const testSharedSecret = "0123456789abcdef0123456789abcdef"
const testGitHubToken = "github-token"

func TestGitCompatibleRoutesRequireAuth(t *testing.T) {
	t.Parallel()
	server := newTestServer(t)
	request := httptest.NewRequestWithContext(
		context.Background(),
		http.MethodGet,
		"/dutifuldev/gitcba.git/info/refs?service=git-upload-pack",
		http.NoBody,
	)
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusUnauthorized)
	}
}

func TestHealth(t *testing.T) {
	t.Parallel()
	server := newTestServer(t)
	request := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/healthz", http.NoBody)
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
	}
}

func TestGitRoutesUseGitHubAccessPolicy(t *testing.T) {
	t.Parallel()
	server := newTestServer(t)

	allowed := do(t, server, http.MethodGet, "/dutifuldev/gitcba.git/info/refs?service=git-upload-pack", bearerAuth())
	if allowed.Code != http.StatusOK {
		t.Fatalf("allowed status = %d, body = %s", allowed.Code, allowed.Body.String())
	}

	denied := do(t, server, http.MethodGet, "/outside/repo.git/info/refs?service=git-upload-pack", bearerAuth())
	if denied.Code != http.StatusForbidden {
		t.Fatalf("denied status = %d, want %d", denied.Code, http.StatusForbidden)
	}
}

func TestGitReceivePackAllowsExplicitRepositoryOwner(t *testing.T) {
	t.Parallel()
	server := newTestServer(t)
	response := do(t, server, http.MethodPost, "/openclaw/openclaw.git/git-receive-pack", basicAuth())
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
}

func TestGitReceivePackRejectsMainBranchUpdate(t *testing.T) {
	t.Parallel()
	server := newTestServer(t)
	response := doWithBody(
		t,
		server,
		http.MethodPost,
		"/dutifuldev/gitcba.git/git-receive-pack",
		bearerAuth(),
		receivePackBody("refs/heads/main"),
	)
	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
}

func TestGitReceivePackRejectsDeleteOfMainBranch(t *testing.T) {
	t.Parallel()
	server := newTestServer(t)
	response := doWithBody(
		t,
		server,
		http.MethodPost,
		"/dutifuldev/gitcba.git/git-receive-pack",
		bearerAuth(),
		receivePackCommand("1111111111111111111111111111111111111111", zeroOID(), "refs/heads/main"),
	)
	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
}

func TestGitReceivePackRejectsDefaultBranchUpdate(t *testing.T) {
	t.Parallel()
	server := newTestServerWithDefaultBranch(t, "trunk")
	response := doWithBody(
		t,
		server,
		http.MethodPost,
		"/dutifuldev/gitcba.git/git-receive-pack",
		bearerAuth(),
		receivePackBody("refs/heads/trunk"),
	)
	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
}

func TestGitReceivePackRejectsMultiRefUpdateContainingDefaultBranch(t *testing.T) {
	t.Parallel()
	server := newTestServerWithDefaultBranch(t, "trunk")
	response := doWithBody(
		t,
		server,
		http.MethodPost,
		"/dutifuldev/gitcba.git/git-receive-pack",
		bearerAuth(),
		receivePackCommands(
			commandLine(zeroOID(), "1111111111111111111111111111111111111111", "refs/heads/feature"),
			commandLine(zeroOID(), "2222222222222222222222222222222222222222", "refs/heads/trunk"),
		),
	)
	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
}

func TestGitReceivePackAllowsFeatureBranchUpdate(t *testing.T) {
	t.Parallel()
	var gotGitPush bool
	server := newTestServerWithHandler(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/repos/dutifuldev/gitcba" {
			_, _ = w.Write([]byte(`{"default_branch":"main"}`))
			return
		}
		gotGitPush = r.URL.Path == "/dutifuldev/gitcba.git/git-receive-pack"
		w.WriteHeader(http.StatusOK)
	})
	response := doWithBody(
		t,
		server,
		http.MethodPost,
		"/dutifuldev/gitcba.git/git-receive-pack",
		bearerAuth(),
		receivePackBody("refs/heads/gitcba-smoke"),
	)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	if !gotGitPush {
		t.Fatal("git receive-pack was not proxied")
	}
}

func TestGitReceivePackAllowsTagUpdateWithoutDefaultBranchLookup(t *testing.T) {
	t.Parallel()
	var gotGitPush bool
	server := newTestServerWithHandler(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/repos/dutifuldev/gitcba" {
			t.Fatal("default branch lookup should not run for tag-only updates")
		}
		gotGitPush = r.URL.Path == "/dutifuldev/gitcba.git/git-receive-pack"
		w.WriteHeader(http.StatusOK)
	})
	response := doWithBody(
		t,
		server,
		http.MethodPost,
		"/dutifuldev/gitcba.git/git-receive-pack",
		bearerAuth(),
		receivePackBody("refs/tags/v0.0.1"),
	)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	if !gotGitPush {
		t.Fatal("git receive-pack was not proxied")
	}
}

func TestGitReceivePackFailsClosedWhenDefaultBranchFetchFails(t *testing.T) {
	t.Parallel()
	var gotGitPush bool
	server := newTestServerWithHandler(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/repos/dutifuldev/gitcba" {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		gotGitPush = r.URL.Path == "/dutifuldev/gitcba.git/git-receive-pack"
		w.WriteHeader(http.StatusOK)
	})
	response := doWithBody(
		t,
		server,
		http.MethodPost,
		"/dutifuldev/gitcba.git/git-receive-pack",
		bearerAuth(),
		receivePackBody("refs/heads/feature"),
	)
	if response.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	if gotGitPush {
		t.Fatal("git receive-pack proxied after default branch lookup failure")
	}
}

func TestGitReceivePackFailsClosedWhenDefaultBranchResponseIsInvalid(t *testing.T) {
	t.Parallel()
	var gotGitPush bool
	server := newTestServerWithHandler(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/repos/dutifuldev/gitcba" {
			_, _ = w.Write([]byte(`not json`))
			return
		}
		gotGitPush = r.URL.Path == "/dutifuldev/gitcba.git/git-receive-pack"
		w.WriteHeader(http.StatusOK)
	})
	response := doWithBody(
		t,
		server,
		http.MethodPost,
		"/dutifuldev/gitcba.git/git-receive-pack",
		bearerAuth(),
		receivePackBody("refs/heads/feature"),
	)
	if response.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	if gotGitPush {
		t.Fatal("git receive-pack proxied after invalid default branch response")
	}
}

func TestGitReceivePackRejectsMalformedRequest(t *testing.T) {
	t.Parallel()
	server := newTestServer(t)
	response := doWithBody(
		t,
		server,
		http.MethodPost,
		"/dutifuldev/gitcba.git/git-receive-pack",
		bearerAuth(),
		[]byte("bad"),
	)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusBadRequest)
	}
}

func TestGitReceivePackRejectsMalformedPktLines(t *testing.T) {
	t.Parallel()
	server := newTestServer(t)
	cases := map[string][]byte{
		"short header":       []byte("bad"),
		"bad hex":            []byte("zzzz"),
		"invalid small size": []byte("0003"),
		"truncated body":     []byte("0008ab"),
	}
	for name, body := range cases {
		response := doWithBody(
			t,
			server,
			http.MethodPost,
			"/dutifuldev/gitcba.git/git-receive-pack",
			bearerAuth(),
			body,
		)
		if response.Code != http.StatusBadRequest {
			t.Fatalf("%s status = %d, want %d", name, response.Code, http.StatusBadRequest)
		}
	}
}

func TestGitReceivePackRejectsOversizedRequest(t *testing.T) {
	t.Parallel()
	server := newTestServer(t)
	server.maxReceivePackBytes = 4
	response := doWithBody(
		t,
		server,
		http.MethodPost,
		"/dutifuldev/gitcba.git/git-receive-pack",
		bearerAuth(),
		[]byte("0000extra"),
	)
	if response.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusRequestEntityTooLarge)
	}
}

func TestGitReceivePackPolicyDenialDoesNotCallUpstream(t *testing.T) {
	t.Parallel()
	var upstreamCalls int
	server := newTestServerWithHandler(t, func(w http.ResponseWriter, _ *http.Request) {
		upstreamCalls++
		w.WriteHeader(http.StatusOK)
	})
	response := doWithBody(
		t,
		server,
		http.MethodPost,
		"/outside/repo.git/git-receive-pack",
		bearerAuth(),
		receivePackBody("refs/heads/feature"),
	)
	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusForbidden)
	}
	if upstreamCalls != 0 {
		t.Fatalf("upstream calls = %d, want 0", upstreamCalls)
	}
}

func TestAuditLogDoesNotExposeClientSecretsOrBodies(t *testing.T) {
	t.Parallel()
	var logs bytes.Buffer
	server := newTestServer(t)
	server.logger = slog.New(slog.NewJSONHandler(&logs, nil))
	rawBody := []byte("do-not-log-body")
	response := doWithHeaders(
		t,
		server,
		http.MethodPost,
		"/outside/repo.git/git-receive-pack",
		map[string]string{
			"Authorization": bearerAuth(),
			"Cookie":        "session=do-not-log-cookie",
		},
		rawBody,
	)
	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusForbidden)
	}
	logText := logs.String()
	for _, forbidden := range []string{testSharedSecret, "do-not-log-cookie", string(rawBody)} {
		if strings.Contains(logText, forbidden) {
			t.Fatalf("audit log exposed %q: %s", forbidden, logText)
		}
	}
	for _, expected := range []string{`"operation":"git_receive_pack"`, `"outcome":"denied"`, `"owner":"outside"`, `"repo":"repo"`} {
		if !strings.Contains(logText, expected) {
			t.Fatalf("audit log missing %s: %s", expected, logText)
		}
	}
}

func TestNewConfiguresGitHubHTTPTimeoutAndReceivePackLimit(t *testing.T) {
	t.Parallel()
	server, err := New(config.Config{
		SharedSecret:        testSharedSecret,
		GitHubToken:         testGitHubToken,
		GitHubHTTPTimeout:   7 * time.Second,
		MaxReceivePackBytes: 99,
	}, testGitHubAccess())
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if server.githubClient.Timeout != 7*time.Second {
		t.Fatalf("github timeout = %s, want 7s", server.githubClient.Timeout)
	}
	if server.maxReceivePackBytes != 99 {
		t.Fatalf("max receive-pack bytes = %d, want 99", server.maxReceivePackBytes)
	}
}

func TestPullRequestRouteUsesGitHubShape(t *testing.T) {
	t.Parallel()
	var gotPath string
	server := newTestServerWithHandler(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusCreated)
	})
	response := do(t, server, http.MethodPost, "/repos/dutifuldev/gitcba/pulls", bearerAuth())
	if response.Code != http.StatusCreated {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	if gotPath != "/repos/dutifuldev/gitcba/pulls" {
		t.Fatalf("upstream path = %q, want GitHub pulls path", gotPath)
	}
}

func TestPullRequestPolicyDenialDoesNotCallUpstream(t *testing.T) {
	t.Parallel()
	var upstreamCalls int
	server := newTestServerWithHandler(t, func(w http.ResponseWriter, _ *http.Request) {
		upstreamCalls++
		w.WriteHeader(http.StatusCreated)
	})
	response := do(t, server, http.MethodPost, "/repos/outside/repo/pulls", bearerAuth())
	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusForbidden)
	}
	if upstreamCalls != 0 {
		t.Fatalf("upstream calls = %d, want 0", upstreamCalls)
	}
}

func TestGitProxyUsesServerSideCredential(t *testing.T) {
	t.Parallel()
	var gotAuthorization string
	server := newTestServerWithHandler(t, func(w http.ResponseWriter, r *http.Request) {
		gotAuthorization = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	})
	response := do(t, server, http.MethodGet, "/dutifuldev/gitcba.git/info/refs?service=git-upload-pack", bearerAuth())
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	if gotAuthorization != githubGitAuthorization(testGitHubToken) {
		t.Fatalf("upstream authorization was not server-side GitHub auth")
	}
}

func TestProxyDoesNotForwardClientCredentialHeaders(t *testing.T) {
	t.Parallel()
	var gotAuthorization string
	var gotCookie string
	server := newTestServerWithHandler(t, func(w http.ResponseWriter, r *http.Request) {
		gotAuthorization = r.Header.Get("Authorization")
		gotCookie = r.Header.Get("Cookie")
		w.WriteHeader(http.StatusOK)
	})
	response := doWithHeaders(
		t,
		server,
		http.MethodGet,
		"/dutifuldev/gitcba.git/info/refs?service=git-upload-pack",
		map[string]string{
			"Authorization": bearerAuth(),
			"Cookie":        "session=client-secret",
		},
		nil,
	)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	if gotAuthorization != githubGitAuthorization(testGitHubToken) {
		t.Fatalf("authorization = %q, want server-side GitHub auth", gotAuthorization)
	}
	if gotCookie != "" {
		t.Fatalf("cookie = %q, want stripped", gotCookie)
	}
}

func TestProxyDropsHopByHopHeaders(t *testing.T) {
	t.Parallel()
	var gotConnection string
	server := newTestServerWithHandler(t, func(w http.ResponseWriter, r *http.Request) {
		gotConnection = r.Header.Get("Connection")
		w.Header().Set("Connection", "close")
		w.Header().Set("X-Test-Upstream", "kept")
		w.WriteHeader(http.StatusOK)
	})
	response := doWithHeaders(
		t,
		server,
		http.MethodGet,
		"/dutifuldev/gitcba.git/info/refs?service=git-upload-pack",
		map[string]string{
			"Authorization": bearerAuth(),
			"Connection":    "keep-alive",
		},
		nil,
	)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	if gotConnection != "" {
		t.Fatalf("upstream connection header = %q, want stripped", gotConnection)
	}
	if response.Header().Get("Connection") != "" {
		t.Fatalf("response connection header = %q, want stripped", response.Header().Get("Connection"))
	}
	if response.Header().Get("X-Test-Upstream") != "kept" {
		t.Fatalf("response header missing non-hop upstream header")
	}
}

func TestUnsupportedGitServiceIsRejected(t *testing.T) {
	t.Parallel()
	server := newTestServer(t)
	response := do(t, server, http.MethodGet, "/dutifuldev/gitcba.git/info/refs?service=bad-service", bearerAuth())
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusBadRequest)
	}
}

func TestNoCredentialEndpoints(t *testing.T) {
	t.Parallel()
	server := newTestServer(t)
	for _, path := range []string{"/v1/credentials", "/v1/credentials/cred_123"} {
		response := do(t, server, http.MethodGet, path, bearerAuth())
		if response.Code != http.StatusNotFound {
			t.Fatalf("%s status = %d, want %d", path, response.Code, http.StatusNotFound)
		}
	}
}

func TestNoGitHubAccessEndpoint(t *testing.T) {
	t.Parallel()
	server := newTestServer(t)
	response := do(t, server, http.MethodGet, "/v1/github-access", bearerAuth())
	if response.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusNotFound)
	}
}

func TestReceivePackUpdatedRefsParsesMultipleBranchRefs(t *testing.T) {
	t.Parallel()
	refs, err := receivePackUpdatedRefs(receivePackCommands(
		commandLine(zeroOID(), "1111111111111111111111111111111111111111", "refs/heads/a"),
		commandLine(zeroOID(), "2222222222222222222222222222222222222222", "refs/tags/v1"),
		commandLine(zeroOID(), "3333333333333333333333333333333333333333", "refs/heads/b"),
	))
	if err != nil {
		t.Fatalf("receivePackUpdatedRefs() error = %v", err)
	}
	if strings.Join(refs, ",") != "refs/heads/a,refs/heads/b" {
		t.Fatalf("refs = %v, want branch refs only", refs)
	}
}

func newTestServer(t *testing.T) *Server {
	t.Helper()
	return newTestServerWithDefaultBranch(t, "main")
}

func newTestServerWithDefaultBranch(t *testing.T, defaultBranch string) *Server {
	t.Helper()
	return newTestServerWithHandler(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/repos/dutifuldev/gitcba" || r.URL.Path == "/repos/openclaw/openclaw" {
			_, _ = w.Write([]byte(`{"default_branch":"` + defaultBranch + `"}`))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("proxied"))
	})
}

func newTestServerWithHandler(t *testing.T, handler http.HandlerFunc) *Server {
	t.Helper()
	upstream := httptest.NewServer(handler)
	t.Cleanup(upstream.Close)
	server, err := New(config.Config{
		SharedSecret: testSharedSecret,
		GitHubToken:  testGitHubToken,
	}, testGitHubAccess())
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	upstreamURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	server.githubClient = upstream.Client()
	server.githubGitBaseURL = upstreamURL
	server.githubAPIBaseURL = upstreamURL
	return server
}

func testGitHubAccess() githubaccess.Config {
	return githubaccess.Config{
		Owners: []string{"dutifuldev", "osolmaz"},
		Repositories: []githubaccess.RepositoryRef{
			{Owner: "openclaw", Name: "openclaw"},
		},
	}
}

func do(t *testing.T, server *Server, method string, path string, authorization string) *httptest.ResponseRecorder {
	t.Helper()
	return doWithHeaders(t, server, method, path, map[string]string{"Authorization": authorization}, nil)
}

func doWithBody(
	t *testing.T,
	server *Server,
	method string,
	path string,
	authorization string,
	body []byte,
) *httptest.ResponseRecorder {
	t.Helper()
	return doWithHeaders(t, server, method, path, map[string]string{"Authorization": authorization}, body)
}

func doWithHeaders(
	t *testing.T,
	server *Server,
	method string,
	path string,
	headers map[string]string,
	body []byte,
) *httptest.ResponseRecorder {
	t.Helper()
	var requestBody io.Reader = http.NoBody
	if len(body) > 0 {
		requestBody = bytes.NewReader(body)
	}
	request := httptest.NewRequestWithContext(context.Background(), method, path, requestBody)
	for key, value := range headers {
		request.Header.Set(key, value)
	}
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	return response
}

func bearerAuth() string {
	return "Bearer " + testSharedSecret
}

func basicAuth() string {
	encoded := base64.StdEncoding.EncodeToString([]byte("git:" + testSharedSecret))
	return "Basic " + encoded
}

func receivePackBody(ref string) []byte {
	return receivePackCommand(zeroOID(), "1111111111111111111111111111111111111111", ref)
}

func receivePackCommand(oldOID string, newOID string, ref string) []byte {
	return receivePackCommands(commandLine(oldOID, newOID, ref))
}

func receivePackCommands(lines ...string) []byte {
	var body []byte
	for index, line := range lines {
		if index == 0 {
			line += "\x00 report-status"
		}
		body = append(body, pktLine(line+"\n")...)
	}
	return append(body, []byte("0000")...)
}

func commandLine(oldOID string, newOID string, ref string) string {
	return oldOID + " " + newOID + " " + ref
}

func pktLine(line string) []byte {
	return []byte(fmt.Sprintf("%04x%s", len(line)+4, line))
}

func zeroOID() string {
	return "0000000000000000000000000000000000000000"
}
