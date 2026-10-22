package httpapi

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/osolmaz/unyolo/authorization/budget"
	"github.com/osolmaz/unyolo/authorization/grants"
	"github.com/osolmaz/unyolo/authorization/grants/grantstest"
	"github.com/osolmaz/unyolo/brokers/github/internal/config"
	"github.com/osolmaz/unyolo/brokers/github/internal/githubauth"
	"github.com/osolmaz/unyolo/brokers/github/internal/opcatalog"
	"github.com/osolmaz/unyolo/brokers/github/internal/policy"
	unyoloaudit "github.com/osolmaz/unyolo/telemetry/audit"
)

const testSharedSecret = "0123456789abcdef0123456789abcdef"
const testGitHubToken = "github-token"

func TestGitCompatibleRoutesRequireAuth(t *testing.T) {
	t.Parallel()
	server := newTestServer(t)
	request := httptest.NewRequestWithContext(
		context.Background(),
		http.MethodGet,
		"/osolmaz/gh-broker.git/info/refs?service=git-upload-pack",
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

func TestGitHubWebhookVerifiesSignatureAndAuditsMetadata(t *testing.T) {
	t.Parallel()
	var logs bytes.Buffer
	server := newTestServer(t)
	server.githubWebhookSecret = "webhook-secret"
	server.auditWriter = unyoloaudit.New(&logs)
	body := []byte(`{"action":"added","installation":{"id":42},"repositories_added":[{"full_name":"osolmaz/gh-broker"}]}`)
	response := doWebhook(t, server, body, map[string]string{
		"X-GitHub-Event":      "installation_repositories",
		"X-GitHub-Delivery":   "delivery-1",
		"X-Hub-Signature-256": webhookSignature("webhook-secret", body),
		"Authorization":       "Bearer wrong-agent-secret",
	})
	if response.Code != http.StatusAccepted {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	logText := logs.String()
	for _, want := range []string{`"github_event":"installation_repositories"`, `"github_delivery":"delivery-1"`, `"github_action":"added"`, `"github_installation_id":"42"`, `"target":"osolmaz/gh-broker"`} {
		if !strings.Contains(logText, want) {
			t.Fatalf("webhook audit missing %s: %s", want, logText)
		}
	}
	if strings.Contains(logText, "webhook-secret") || strings.Contains(logText, string(body)) {
		t.Fatalf("webhook audit leaked secret or raw body: %s", logText)
	}
}

func TestGitHubWebhookRejectsInvalidRequests(t *testing.T) {
	t.Parallel()
	body := []byte(`{"action":"created"}`)
	cases := map[string]struct {
		secret  string
		headers map[string]string
		body    []byte
		want    int
	}{
		"not configured": {secret: "", headers: signedWebhookHeaders("webhook-secret", body), body: body, want: http.StatusNotFound},
		"missing event": {secret: "webhook-secret", headers: map[string]string{
			"X-GitHub-Delivery":   "delivery-1",
			"X-Hub-Signature-256": webhookSignature("webhook-secret", body),
		}, body: body, want: http.StatusBadRequest},
		"bad signature": {secret: "webhook-secret", headers: map[string]string{
			"X-GitHub-Event":      "installation",
			"X-GitHub-Delivery":   "delivery-1",
			"X-Hub-Signature-256": webhookSignature("wrong-secret", body),
		}, body: body, want: http.StatusUnauthorized},
		"bad json": {secret: "webhook-secret", headers: signedWebhookHeaders("webhook-secret", []byte(`{`)), body: []byte(`{`), want: http.StatusBadRequest},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			server := newTestServer(t)
			server.githubWebhookSecret = tc.secret
			response := doWebhook(t, server, tc.body, tc.headers)
			if response.Code != tc.want {
				t.Fatalf("status = %d, body = %s, want %d", response.Code, response.Body.String(), tc.want)
			}
		})
	}
}

func TestGitHubWebhookRejectsOversizedBody(t *testing.T) {
	t.Parallel()
	server := newTestServer(t)
	server.githubWebhookSecret = "webhook-secret"
	body := bytes.Repeat([]byte("x"), int(maxWebhookBodyBytes)+1)
	response := doWebhook(t, server, body, signedWebhookHeaders("webhook-secret", body))
	if response.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", response.Code)
	}
}

func TestGitFetchUsesPolicy(t *testing.T) {
	t.Parallel()
	server := newTestServer(t)

	allowed := do(t, server, http.MethodGet, "/osolmaz/gh-broker.git/info/refs?service=git-upload-pack", bearerAuth())
	if allowed.Code != http.StatusOK {
		t.Fatalf("allowed status = %d, body = %s", allowed.Code, allowed.Body.String())
	}

	denied := do(t, server, http.MethodGet, "/outside/repo.git/info/refs?service=git-upload-pack", bearerAuth())
	if denied.Code != http.StatusForbidden {
		t.Fatalf("denied status = %d, want %d", denied.Code, http.StatusForbidden)
	}
}

func TestGitInfoRefsDirectHandler(t *testing.T) {
	t.Parallel()
	var upstreamCalls int
	server := newTestServerWithHandler(t, func(w http.ResponseWriter, _ *http.Request) {
		upstreamCalls++
		w.WriteHeader(http.StatusOK)
	})
	context := newGitContext(t, server, http.MethodGet, "/osolmaz/gh-broker.git/info/refs?service=git-upload-pack", nil)
	if err := server.gitInfoRefs(context); err != nil {
		t.Fatalf("gitInfoRefs() error = %v", err)
	}
	if upstreamCalls != 1 {
		t.Fatalf("upstream calls = %d, want 1", upstreamCalls)
	}

	badContext := newGitContext(t, server, http.MethodGet, "/osolmaz/gh-broker.git/info/refs?service=bad", nil)
	if err := server.gitInfoRefs(badContext); err == nil {
		t.Fatal("gitInfoRefs(bad service) error = nil, want unsupported service")
	}
}

func TestProxyGitDirect(t *testing.T) {
	t.Parallel()
	var gotPath string
	server := newTestServerWithHandler(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
	})
	context := newGitContext(t, server, http.MethodPost, "/osolmaz/gh-broker.git/git-upload-pack", []byte("want refs"))
	if err := server.proxyGit(context); err != nil {
		t.Fatalf("proxyGit() error = %v", err)
	}
	if gotPath != "/osolmaz/gh-broker.git/git-upload-pack" {
		t.Fatalf("upstream path = %q, want upload-pack path", gotPath)
	}
}

func TestGitProxyUsesStreamTimeout(t *testing.T) {
	t.Parallel()
	upstream := httptest.NewServer(withDefaultGitHubSafetyState(func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/osolmaz/gh-broker.git/info/refs" {
			t.Fatalf("upstream path = %q", request.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
		time.Sleep(50 * time.Millisecond)
		_, _ = w.Write([]byte("stream-complete"))
	}))
	t.Cleanup(upstream.Close)
	server, err := New(config.Config{
		ClientID: "bob", SharedSecret: testSharedSecret, GitHubToken: testGitHubToken, GitHubTokenFile: "/protected/github-token",
		GitHubAPIBaseURL: upstream.URL, GitHubWebBaseURL: upstream.URL, StateDir: t.TempDir(),
		GitHubHTTPTimeout: 10 * time.Millisecond, GitHubStreamTimeout: time.Second,
	}, testBrokerPolicy(t))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	t.Cleanup(func() { _ = server.Close() })

	response := do(t, server, http.MethodGet, "/osolmaz/gh-broker.git/info/refs?service=git-upload-pack", bearerAuth())
	if response.Code != http.StatusOK || response.Body.String() != "stream-complete" {
		t.Fatalf("status = %d, body = %q", response.Code, response.Body.String())
	}
}

func TestGitReceivePackDiscoveryUsesPushPolicy(t *testing.T) {
	t.Parallel()
	fetchOnlyPolicy, err := policy.New(policy.Scope{Rules: []policy.Rule{
		{
			ID:         "fetch-only",
			Effect:     policy.EffectAllow,
			Clients:    []string{"bob"},
			Operations: []policy.Operation{policy.OperationGitFetch},
			Targets:    []policy.Target{{Kind: "repo", Owner: "osolmaz", Name: "gh-broker"}},
		},
	}})
	if err != nil {
		t.Fatalf("policy.New() error = %v", err)
	}
	server := newTestServerWithPolicyAndHandler(t, fetchOnlyPolicy, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	fetch := do(t, server, http.MethodGet, "/osolmaz/gh-broker.git/info/refs?service=git-upload-pack", bearerAuth())
	if fetch.Code != http.StatusOK {
		t.Fatalf("fetch discovery status = %d, body = %s", fetch.Code, fetch.Body.String())
	}
	push := do(t, server, http.MethodGet, "/osolmaz/gh-broker.git/info/refs?service=git-receive-pack", bearerAuth())
	if push.Code != http.StatusForbidden {
		t.Fatalf("receive-pack discovery status = %d, want %d", push.Code, http.StatusForbidden)
	}
}

func TestGitUploadPackPostRouteUsesPolicy(t *testing.T) {
	t.Parallel()
	var gotPath string
	server := newTestServerWithHandler(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
	})
	response := doWithBody(t, server, http.MethodPost, "/osolmaz/gh-broker.git/git-upload-pack", bearerAuth(), []byte("want refs"))
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	if gotPath != "/osolmaz/gh-broker.git/git-upload-pack" {
		t.Fatalf("upstream path = %q, want upload-pack path", gotPath)
	}
}

func TestGitReceivePackRejectsBadOID(t *testing.T) {
	t.Parallel()
	server := newTestServer(t)
	response := doWithBody(
		t,
		server,
		http.MethodPost,
		"/osolmaz/gh-broker.git/git-receive-pack",
		bearerAuth(),
		receivePackPayload("not-an-oid", oid("2"), "refs/heads/bob/work"),
	)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
}

func TestGitReceivePackRejectsTagUpdateByDefault(t *testing.T) {
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
		"/osolmaz/gh-broker.git/git-receive-pack",
		bearerAuth(),
		receivePackPayload(zeroOID(), oid("1"), "refs/tags/v0.1.0"),
	)
	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	if upstreamCalls != 0 {
		t.Fatalf("upstream calls = %d, want 0", upstreamCalls)
	}
}

func TestGitReceivePackEmptyRequestStillUsesPolicy(t *testing.T) {
	t.Parallel()
	var gotGitPush bool
	server := newTestServerWithHandler(t, func(w http.ResponseWriter, r *http.Request) {
		gotGitPush = r.URL.Path == "/osolmaz/gh-broker.git/git-receive-pack"
		w.WriteHeader(http.StatusOK)
	})
	response := doWithBody(
		t,
		server,
		http.MethodPost,
		"/osolmaz/gh-broker.git/git-receive-pack",
		bearerAuth(),
		[]byte("0000"),
	)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	if !gotGitPush {
		t.Fatal("empty receive-pack was not proxied after policy allow")
	}
}

func TestGitReceivePackAllowsFeatureBranchCreate(t *testing.T) {
	t.Parallel()
	var gotGitPush bool
	server := newTestServerWithHandler(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/compare/") {
			t.Fatal("branch creation should not compare ancestry")
		}
		gotGitPush = r.URL.Path == "/osolmaz/gh-broker.git/git-receive-pack"
		w.WriteHeader(http.StatusOK)
	})
	response := doWithBody(
		t,
		server,
		http.MethodPost,
		"/osolmaz/gh-broker.git/git-receive-pack",
		bearerAuth(),
		receivePackCreate("refs/heads/bob/work"),
	)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	if !gotGitPush {
		t.Fatal("git receive-pack was not proxied")
	}
}

func TestGitReceivePackAllowsShallowFeatureBranchCreate(t *testing.T) {
	t.Parallel()
	var gotGitPush bool
	server := newTestServerWithHandler(t, func(w http.ResponseWriter, r *http.Request) {
		gotGitPush = r.URL.Path == "/osolmaz/gh-broker.git/git-receive-pack"
		w.WriteHeader(http.StatusOK)
	})
	body := append(
		pktLine("shallow "+oid("3")+"\n"),
		receivePackPayload(zeroOID(), oid("1"), "refs/heads/bob/work")...,
	)
	response := doWithBody(
		t,
		server,
		http.MethodPost,
		"/osolmaz/gh-broker.git/git-receive-pack",
		bearerAuth(),
		body,
	)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	if !gotGitPush {
		t.Fatal("shallow receive-pack was not proxied")
	}
}

func TestGitReceivePackAllowsFeatureBranchUpdateWithForcePolicy(t *testing.T) {
	t.Parallel()
	var gotGitPush bool
	server := newTestServerWithHandler(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/compare/") {
			t.Fatal("branch update should not compare ancestry before upload")
		}
		gotGitPush = r.URL.Path == "/osolmaz/gh-broker.git/git-receive-pack"
		w.WriteHeader(http.StatusOK)
	})
	response := doWithBody(
		t,
		server,
		http.MethodPost,
		"/osolmaz/gh-broker.git/git-receive-pack",
		bearerAuth(),
		receivePackPayload(oid("1"), oid("2"), "refs/heads/agent/work"),
	)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	if !gotGitPush {
		t.Fatal("git receive-pack was not proxied")
	}
}

func TestGitReceivePackExistingBranchUpdateRequiresForcePolicy(t *testing.T) {
	t.Parallel()
	fastForwardOnlyPolicy, err := policy.New(policy.Scope{Rules: []policy.Rule{
		{
			ID:         "fast-forward-only",
			Effect:     policy.EffectAllow,
			Clients:    []string{"bob"},
			Operations: []policy.Operation{policy.OperationGitPushFastForward},
			Targets:    []policy.Target{{Kind: "repo", Owner: "osolmaz", Name: "gh-broker"}},
			Attrs:      map[string][]string{"refs": {"refs/heads/agent/*"}},
		},
	}})
	if err != nil {
		t.Fatalf("policy.New() error = %v", err)
	}
	var upstreamCalls int
	server := newTestServerWithPolicyAndHandler(t, fastForwardOnlyPolicy, func(w http.ResponseWriter, _ *http.Request) {
		upstreamCalls++
		w.WriteHeader(http.StatusOK)
	})
	response := doWithBody(
		t,
		server,
		http.MethodPost,
		"/osolmaz/gh-broker.git/git-receive-pack",
		bearerAuth(),
		receivePackPayload(oid("1"), oid("2"), "refs/heads/agent/work"),
	)
	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	if upstreamCalls != 0 {
		t.Fatalf("upstream calls = %d, want 0", upstreamCalls)
	}
}

func TestGitReceivePackRejectsMainBranchByPolicy(t *testing.T) {
	t.Parallel()
	var gotGitPush bool
	server := newTestServerWithHandler(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/compare/") {
			t.Fatal("denied branch update should not compare ancestry")
		}
		gotGitPush = r.URL.Path == "/osolmaz/gh-broker.git/git-receive-pack"
		w.WriteHeader(http.StatusOK)
	})
	response := doWithBody(
		t,
		server,
		http.MethodPost,
		"/osolmaz/gh-broker.git/git-receive-pack",
		bearerAuth(),
		receivePackPayload(oid("1"), oid("2"), "refs/heads/main"),
	)
	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	if gotGitPush {
		t.Fatal("git receive-pack proxied after policy denial")
	}
}

func TestGitReceivePackAllowsDirectMainForSpecificRepo(t *testing.T) {
	t.Parallel()
	var gotGitPush bool
	server := newTestServerWithHandler(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/compare/") {
			t.Fatal("direct branch update should not compare ancestry before upload")
		}
		gotGitPush = r.URL.Path == "/osolmaz/direct-main.git/git-receive-pack"
		w.WriteHeader(http.StatusOK)
	})
	response := doWithBody(
		t,
		server,
		http.MethodPost,
		"/osolmaz/direct-main.git/git-receive-pack",
		bearerAuth(),
		receivePackPayload(oid("1"), oid("2"), "refs/heads/main"),
	)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	if !gotGitPush {
		t.Fatal("direct main push was not proxied")
	}
}

func TestGitReceivePackDeniesUnsupportedRefUpdate(t *testing.T) {
	t.Parallel()
	var gotGitPush bool
	server := newTestServerWithHandler(t, func(w http.ResponseWriter, r *http.Request) {
		gotGitPush = r.URL.Path == "/osolmaz/gh-broker.git/git-receive-pack"
		w.WriteHeader(http.StatusOK)
	})
	response := doWithBody(
		t,
		server,
		http.MethodPost,
		"/osolmaz/gh-broker.git/git-receive-pack",
		bearerAuth(),
		receivePackPayload(oid("1"), oid("2"), "refs/notes/commits"),
	)
	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	if gotGitPush {
		t.Fatal("unsupported ref update was proxied")
	}
}

func TestGitReceivePackRejectsRefDelete(t *testing.T) {
	t.Parallel()
	server := newTestServer(t)
	response := doWithBody(
		t,
		server,
		http.MethodPost,
		"/osolmaz/gh-broker.git/git-receive-pack",
		bearerAuth(),
		receivePackPayload(oid("1"), zeroOID(), "refs/heads/bob/work"),
	)
	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
}

func TestGitReceivePackRejectsMalformedRequest(t *testing.T) {
	t.Parallel()
	server := newTestServer(t)
	response := doWithBody(
		t,
		server,
		http.MethodPost,
		"/osolmaz/gh-broker.git/git-receive-pack",
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
			"/osolmaz/gh-broker.git/git-receive-pack",
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
		"/osolmaz/gh-broker.git/git-receive-pack",
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
		receivePackCreate("refs/heads/bob/work"),
	)
	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusForbidden)
	}
	if upstreamCalls != 0 {
		t.Fatalf("upstream calls = %d, want 0", upstreamCalls)
	}
}

func TestGitReceivePackDeniedBranchUpdateDoesNotCompare(t *testing.T) {
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
		receivePackPayload(oid("1"), oid("2"), "refs/heads/bob/work"),
	)
	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	if upstreamCalls != 0 {
		t.Fatalf("upstream calls = %d, want 0", upstreamCalls)
	}
}

func TestPullRequestGitHubShapedAliasIsNotRegistered(t *testing.T) {
	t.Parallel()
	var upstreamCalls int
	server := newTestServerWithHandler(t, func(w http.ResponseWriter, _ *http.Request) {
		upstreamCalls++
		w.WriteHeader(http.StatusCreated)
	})
	response := doWithBody(
		t,
		server,
		http.MethodPost,
		"/repos/osolmaz/gh-broker/pulls",
		bearerAuth(),
		[]byte(`{"title":"work","head":"bob/work","base":"main"}`),
	)
	if response.Code != http.StatusNotFound {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	if upstreamCalls != 0 {
		t.Fatalf("upstream calls = %d, want 0", upstreamCalls)
	}
}

func TestDenyOverridesActiveGrant(t *testing.T) {
	t.Parallel()
	var upstreamCalls int
	server := newTestServerWithPolicyAndHandler(t, denyMainWithRequestPolicy(t), func(w http.ResponseWriter, _ *http.Request) {
		upstreamCalls++
		w.WriteHeader(http.StatusOK)
	})
	result, _, err := server.requestGrant(grantsRequestForMainPush(t))
	if err != nil {
		t.Fatalf("Request() error = %v", err)
	}
	if _, err := grantstest.Approve(server.grants, result.Grant.ID, "operator"); err != nil {
		t.Fatalf("Approve() error = %v", err)
	}
	response := doWithBody(
		t,
		server,
		http.MethodPost,
		"/osolmaz/gh-broker.git/git-receive-pack",
		bearerAuth(),
		receivePackPayload(oid("1"), oid("2"), "refs/heads/main"),
	)
	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d, body = %s, want deny despite grant", response.Code, response.Body.String())
	}
	if upstreamCalls != 0 {
		t.Fatalf("upstream calls = %d, want none", upstreamCalls)
	}
}

func TestGrantBackedReceivePackConsumesGrant(t *testing.T) {
	t.Parallel()
	var upstreamCalls int
	server := newTestServerWithPolicyAndHandler(t, requestMainPushPolicy(t), func(w http.ResponseWriter, _ *http.Request) {
		upstreamCalls++
		w.WriteHeader(http.StatusOK)
	})
	grantID := approveMainPushGrant(t, server)
	response := doWithBody(
		t,
		server,
		http.MethodPost,
		"/osolmaz/gh-broker.git/git-receive-pack",
		bearerAuth(),
		receivePackPayload(oid("1"), oid("2"), "refs/heads/main"),
	)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	if upstreamCalls != 1 {
		t.Fatalf("upstream calls = %d, want 1", upstreamCalls)
	}
	assertGrantUseState(t, server, grantID, grants.StatusConsumed, 1, 0)
}

func TestExecutionGrantOnlyAuthorizesExactNativeRequest(t *testing.T) {
	t.Parallel()
	server := newTestServerWithPolicyAndHandler(t, requestMainPushPolicy(t), func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	request := grantsRequestForMainPush(t)
	request.Metadata = map[string]string{grants.MetadataMode: "execution"}
	result, _, err := server.requestGrant(request)
	if err != nil {
		t.Fatal(err)
	}
	approved, err := grantstest.Approve(server.grants, result.Grant.ID, "operator")
	if err != nil {
		t.Fatal(err)
	}
	exact := policy.Request{Client: "bob", Operation: policy.OperationGitPushForce,
		Target: policy.Target{Kind: "repo", Owner: "osolmaz", Name: "gh-broker"}, Attrs: map[string]string{"ref": "refs/heads/main"}}
	decision, err := server.evaluateBrokerRequest(exact)
	if err != nil || !decision.Allowed || decision.GrantID != approved.ID {
		t.Fatalf("exact execution decision = %+v, %v", decision, err)
	}
	different := exact
	different.Attrs = map[string]string{"ref": "refs/heads/other"}
	decision, err = server.evaluateBrokerRequest(different)
	if err != nil || decision.Allowed || decision.GrantID != "" {
		t.Fatalf("different execution decision = %+v, %v", decision, err)
	}
	reserved, err := server.reserveAuthorizedGrants([]authorizedReceivePackRequest{{Request: exact, Decision: policy.Decision{GrantID: approved.ID}}}, "exact-native-request")
	if err != nil || len(reserved) != 1 {
		t.Fatalf("reserveAuthorizedGrants() = %+v, %v", reserved, err)
	}
	if err := server.commitGrantUses(reserved); err != nil {
		t.Fatal(err)
	}
	decision, err = server.evaluateBrokerRequest(exact)
	if err != nil || decision.Allowed || decision.GrantID != "" {
		t.Fatalf("consumed execution decision = %+v, %v", decision, err)
	}
}

func TestNativeWindowGrantChargesIndependentIdenticalCalls(t *testing.T) {
	t.Parallel()
	server := newTestServer(t)
	request := grantsRequestForMainPush(t)
	request.MaxUses = 2
	result, _, err := server.requestGrant(request)
	if err != nil {
		t.Fatal(err)
	}
	approved, err := grantstest.Approve(server.grants, result.Grant.ID, "operator")
	if err != nil {
		t.Fatal(err)
	}
	first, err := server.reserveNativeGrantUse(approved.ID)
	if err != nil || len(first) != 1 {
		t.Fatalf("first reservation = %+v, %v", first, err)
	}
	if err := server.commitGrantUses(first); err != nil {
		t.Fatal(err)
	}
	second, err := server.reserveNativeGrantUse(approved.ID)
	if err != nil || len(second) != 1 {
		t.Fatalf("second reservation = %+v, %v", second, err)
	}
	if first[0].Use.RequestID == second[0].Use.RequestID {
		t.Fatal("independent native calls shared one use identity")
	}
	if err := server.commitGrantUses(second); err != nil {
		t.Fatal(err)
	}
	assertGrantUseState(t, server, approved.ID, grants.StatusConsumed, 2, 0)
}

func TestGitReceivePackWaitsForApprovalAndContinues(t *testing.T) {
	t.Parallel()
	var upstreamCalls int
	server := newTestServerWithPolicyAndHandler(t, requestTagPushPolicy(t), func(w http.ResponseWriter, _ *http.Request) {
		upstreamCalls++
		w.WriteHeader(http.StatusOK)
	})
	server.operatorConfigured = true
	body := receivePackCreate("refs/tags/v1.0.0")

	responses := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		responses <- doWithBody(t, server, http.MethodPost, "/osolmaz/gh-broker.git/git-receive-pack", bearerAuth(), body)
	}()
	grant := waitForGitApproval(t, server, 1)
	if approvalCount(t, server) != 1 || upstreamCalls != 0 {
		t.Fatalf("notifications = %d, upstream calls = %d, want 1/0", approvalCount(t, server), upstreamCalls)
	}
	if _, err := grantstest.Approve(server.grants, grant.ID, "operator"); err != nil {
		t.Fatalf("Approve() error = %v", err)
	}
	response := <-responses
	if response.Code != http.StatusOK || upstreamCalls != 1 {
		t.Fatalf("approved push: status = %d, body = %q, upstream calls = %d", response.Code, response.Body.String(), upstreamCalls)
	}
	assertGrantUseState(t, server, grant.ID, grants.StatusConsumed, 1, 0)
}

func TestGitReceivePackGroupsAtomicMultiRefApproval(t *testing.T) {
	t.Parallel()
	brokerPolicy, err := policy.New(policy.Scope{Rules: []policy.Rule{
		{ID: "request-force", Effect: policy.EffectRequest, Clients: []string{"bob"}, Operations: []policy.Operation{policy.OperationGitPushForce}, Targets: []policy.Target{{Kind: "repo", Owner: "osolmaz", Name: "gh-broker"}}, Attrs: map[string][]string{"refs": {"refs/heads/bob/**"}}},
		{ID: "request-delete", Effect: policy.EffectRequest, Clients: []string{"bob"}, Operations: []policy.Operation{policy.OperationGitRefDelete}, Targets: []policy.Target{{Kind: "repo", Owner: "osolmaz", Name: "gh-broker"}}, Attrs: map[string][]string{"refs": {"refs/heads/bob/**"}}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	var forwarded []byte
	server := newTestServerWithPolicyAndHandler(t, brokerPolicy, func(w http.ResponseWriter, r *http.Request) {
		forwarded, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	})
	server.operatorConfigured = true
	body := pktLine(oid("1") + " " + oid("2") + " refs/heads/bob/update\x00report-status atomic\n")
	body = append(body, pktLine(oid("3")+" "+zeroOID()+" refs/heads/bob/delete\n")...)
	body = append(body, []byte("0000")...)

	responses := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		responses <- doWithBody(t, server, http.MethodPost, "/osolmaz/gh-broker.git/git-receive-pack", bearerAuth(), body)
	}()
	grant := waitForGitApproval(t, server, 1)
	if got := grant.Attrs["ref"]; !reflect.DeepEqual(got, []string{"refs/heads/bob/delete", "refs/heads/bob/update"}) {
		t.Fatalf("grouped refs = %v", got)
	}
	if got := grant.Attrs["operation"]; !reflect.DeepEqual(got, []string{"git.push.force", "git.ref.delete"}) {
		t.Fatalf("grouped operations = %v", got)
	}
	commands := grant.Attrs["command"]
	if len(commands) != 2 || !strings.HasPrefix(commands[0], "000000 git.push.force ") || !strings.HasPrefix(commands[1], "000001 git.ref.delete ") {
		t.Fatalf("ordered commands = %v", commands)
	}
	if _, err := grantstest.Approve(server.grants, grant.ID, "operator"); err != nil {
		t.Fatal(err)
	}
	response := <-responses
	if response.Code != http.StatusOK || !bytes.Equal(forwarded, body) {
		t.Fatalf("status=%d forwarded exact body=%t", response.Code, bytes.Equal(forwarded, body))
	}
	if approvalCount(t, server) != 1 {
		t.Fatalf("notifications = %d", approvalCount(t, server))
	}
}

func TestGitReceivePackCreatesFreshApprovalAfterDenial(t *testing.T) {
	t.Parallel()
	var upstreamCalls int
	server := newTestServerWithPolicyAndHandler(t, requestTagPushPolicy(t), func(w http.ResponseWriter, _ *http.Request) {
		upstreamCalls++
		w.WriteHeader(http.StatusOK)
	})
	server.operatorConfigured = true
	body := receivePackCreate("refs/tags/v1.0.0")

	firstResponses := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		firstResponses <- doWithBody(t, server, http.MethodPost, "/osolmaz/gh-broker.git/git-receive-pack", bearerAuth(), body)
	}()
	firstGrant := waitForGitApproval(t, server, 1)
	if _, err := grantstest.Deny(server.grants, firstGrant.ID, "operator"); err != nil {
		t.Fatalf("Deny() error = %v", err)
	}
	first := <-firstResponses
	if first.Code != http.StatusOK || !strings.Contains(first.Body.String(), "approval denied") {
		t.Fatalf("first request: status = %d, body = %q", first.Code, first.Body.String())
	}
	secondResponses := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		secondResponses <- doWithBody(t, server, http.MethodPost, "/osolmaz/gh-broker.git/git-receive-pack", bearerAuth(), body)
	}()
	secondGrant := waitForGitApproval(t, server, 2)
	if _, err := grantstest.Approve(server.grants, secondGrant.ID, "operator"); err != nil {
		t.Fatalf("Approve() error = %v", err)
	}
	second := <-secondResponses
	if second.Code != http.StatusOK || upstreamCalls != 1 {
		t.Fatalf("second request: status = %d, body = %q", second.Code, second.Body.String())
	}
	items, err := server.grants.ListForClient("bob")
	if err != nil || len(items) != 2 || items[1].Status != grants.StatusConsumed {
		t.Fatalf("renewed grants = %+v, error = %v", items, err)
	}
	if items[1].ClientRequestID != items[0].ClientRequestID+"-2" || items[1].ID == items[0].ID {
		t.Fatalf("renewed grant = %+v, previous = %+v", items[1], items[0])
	}
	if approvalCount(t, server) != 2 {
		t.Fatalf("notifications = %d, want 2", approvalCount(t, server))
	}
}

func TestNextGitApprovalRequestID(t *testing.T) {
	t.Parallel()
	base := "git-plan"
	first := time.Date(2026, 7, 20, 1, 0, 0, 0, time.UTC)
	second := first.Add(time.Minute)
	items := []grants.Grant{
		{ClientRequestID: "unrelated", Status: grants.StatusPending, CreatedAt: second},
		{ClientRequestID: base + "-3", Status: grants.StatusDenied, CreatedAt: first},
		{ClientRequestID: base + "-2", Status: grants.StatusPending, CreatedAt: second},
		{ClientRequestID: base + "-3", Status: grants.StatusActive, CreatedAt: first},
		{ClientRequestID: base + "-3", Status: grants.StatusActive, CreatedAt: second},
	}
	if got := nextGitApprovalRequestID(base, nil); got != base {
		t.Fatalf("empty request ID = %q, want %q", got, base)
	}
	if got := nextGitApprovalRequestID(base, items); got != base+"-3" {
		t.Fatalf("active request ID = %q, want %q", got, base+"-3")
	}
	items[len(items)-1].Status = grants.StatusDenied
	if got := nextGitApprovalRequestID(base, items); got != base+"-4" {
		t.Fatalf("renewed request ID = %q, want %q", got, base+"-4")
	}
}

func TestGitApprovalRequestGeneration(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name      string
		requestID string
		want      int
		valid     bool
	}{
		{name: "base", requestID: "git-plan", want: 1, valid: true},
		{name: "generated", requestID: "git-plan-2", want: 2, valid: true},
		{name: "other base", requestID: "other-2"},
		{name: "invalid suffix", requestID: "git-plan-nope"},
		{name: "reserved generation", requestID: "git-plan-1", want: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, valid := gitApprovalRequestGeneration("git-plan", test.requestID)
			if got != test.want || valid != test.valid {
				t.Fatalf("generation = (%d, %t), want (%d, %t)", got, valid, test.want, test.valid)
			}
		})
	}
}

func TestConcurrentGitReceivePackRequestsReuseApproval(t *testing.T) {
	t.Parallel()
	var upstreamCalls atomic.Int32
	server := newTestServerWithPolicyAndHandler(t, requestTagPushPolicy(t), func(w http.ResponseWriter, _ *http.Request) {
		upstreamCalls.Add(1)
		w.WriteHeader(http.StatusOK)
	})
	server.operatorConfigured = true
	body := receivePackCreate("refs/tags/v1.0.0")
	responses := make(chan *httptest.ResponseRecorder, 2)
	for range 2 {
		go func() {
			responses <- doWithBody(t, server, http.MethodPost, "/osolmaz/gh-broker.git/git-receive-pack", bearerAuth(), body)
		}()
	}
	grant := waitForGitApproval(t, server, 1)
	if _, err := grantstest.Approve(server.grants, grant.ID, "operator"); err != nil {
		t.Fatal(err)
	}
	var successful, refused int
	for range 2 {
		response := <-responses
		switch response.Code {
		case http.StatusOK:
			if strings.Contains(response.Body.String(), "approval consumed") {
				refused++
			} else {
				successful++
			}
		case http.StatusConflict:
			refused++
		default:
			t.Errorf("status = %d, body = %q", response.Code, response.Body.String())
		}
	}
	items, err := server.grants.ListForClient("bob")
	if err != nil || len(items) != 1 || items[0].Status != grants.StatusConsumed {
		t.Fatalf("transaction grants = %+v, error = %v", items, err)
	}
	if approvalCount(t, server) != 1 || upstreamCalls.Load() != 1 || successful != 1 || refused != 1 {
		t.Fatalf("notifications=%d upstream=%d success=%d refused=%d", approvalCount(t, server), upstreamCalls.Load(), successful, refused)
	}
}

func TestGitReceivePackReportsUnavailableApprovalChannel(t *testing.T) {
	t.Parallel()
	server := newTestServerWithPolicyAndHandler(t, requestTagPushPolicy(t), func(http.ResponseWriter, *http.Request) {
		t.Fatal("unapproved Git push reached upstream")
	})
	response := doWithBody(t, server, http.MethodPost, "/osolmaz/gh-broker.git/git-receive-pack", bearerAuth(), receivePackCreate("refs/tags/v1.0.0"))
	if response.Code != http.StatusServiceUnavailable || !strings.Contains(response.Body.String(), "approval channel is not configured") {
		t.Fatalf("status = %d, body = %q", response.Code, response.Body.String())
	}
}

func TestGrantBackedReceivePackRetainsGrantOnProxyError(t *testing.T) {
	t.Parallel()
	server := newTestServerWithPolicyAndHandler(t, requestMainPushPolicy(t), func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	server.githubGitClient = &http.Client{Transport: errorRoundTripper{}}
	grantID := approveMainPushGrant(t, server)
	response := doWithBody(
		t,
		server,
		http.MethodPost,
		"/osolmaz/gh-broker.git/git-receive-pack",
		bearerAuth(),
		receivePackPayload(oid("1"), oid("2"), "refs/heads/main"),
	)
	if response.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, body = %s, want upstream proxy error", response.Code, response.Body.String())
	}
	assertGrantUseState(t, server, grantID, grants.StatusActive, 0, 1)
	grant, err := server.grants.Get(grantID)
	if err != nil {
		t.Fatalf("Get(%q) error = %v", grantID, err)
	}
	if !grant.ReservationRetained {
		t.Fatalf("grant = %+v, want retained reservation", grant)
	}
}

func TestGrantBackedReceivePackCommitFailureReturnsError(t *testing.T) {
	t.Parallel()
	var server *Server
	var grantID string
	server = newTestServerWithPolicyAndHandler(t, requestMainPushPolicy(t), func(w http.ResponseWriter, _ *http.Request) {
		uses, err := server.grants.ListUses(grantID)
		if err != nil || len(uses) != 1 {
			t.Fatalf("ListUses() = %+v, %v", uses, err)
		}
		if _, err := server.grants.ReleaseUse(grantID, uses[0].RequestID); err != nil {
			t.Fatalf("ReleaseUse() error = %v", err)
		}
		w.WriteHeader(http.StatusOK)
	})
	grantID = approveMainPushGrant(t, server)
	response := doWithBody(
		t,
		server,
		http.MethodPost,
		"/osolmaz/gh-broker.git/git-receive-pack",
		bearerAuth(),
		receivePackPayload(oid("1"), oid("2"), "refs/heads/main"),
	)
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, body = %s, want grant commit error", response.Code, response.Body.String())
	}
	assertGrantUseState(t, server, grantID, grants.StatusActive, 0, 0)
}

func TestServerCloseStopsOwnedWorkersWithLiveStartContext(t *testing.T) {
	server := newTestServer(t)
	server.operatorConfigured = true
	server.Start(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Close() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not join lifecycle-owned workers")
	}
}

func TestRetainingMultiUseGrantPreservesRemainingAccess(t *testing.T) {
	t.Parallel()
	server := newTestServer(t)
	request := grantsRequestForMainPush(t)
	request.MaxUses = 3
	result, _, err := server.requestGrant(request)
	if err != nil {
		t.Fatalf("Request() error = %v", err)
	}
	if _, err := grantstest.Approve(server.grants, result.Grant.ID, "operator"); err != nil {
		t.Fatalf("Approve() error = %v", err)
	}
	reserved, err := server.grants.ReserveUse(result.Grant.ID, "multi-retained-use", result.Grant.Operation)
	if err != nil {
		t.Fatalf("ReserveUse() error = %v", err)
	}
	if err := server.retainGrantUses([]grants.UseReservation{reserved}); err != nil {
		t.Fatalf("retainGrantUses() error = %v", err)
	}
	stored, err := server.grants.Get(result.Grant.ID)
	if err != nil {
		t.Fatalf("Get(%q) error = %v", result.Grant.ID, err)
	}
	if stored.Status != grants.StatusActive || !stored.ReservationRetained || stored.ReservedCount != 1 {
		t.Fatalf("grant = %+v, want active retained reservation", stored)
	}
	active, err := server.grants.ActivePolicyGrants()
	if err != nil || len(active) != 1 || active[0].UsesLeft != 2 {
		t.Fatalf("active grants = %+v, %v; want two remaining uses", active, err)
	}
}

func TestPreDispatchFailureReleasesGrantUse(t *testing.T) {
	t.Parallel()
	server := newTestServer(t)
	result, _, err := server.requestGrant(grantsRequestForMainPush(t))
	if err != nil {
		t.Fatalf("Request() error = %v", err)
	}
	if _, err := grantstest.Approve(server.grants, result.Grant.ID, "operator"); err != nil {
		t.Fatalf("Approve() error = %v", err)
	}
	reserved, err := server.grants.ReserveUse(result.Grant.ID, "predispatch-use", result.Grant.Operation)
	if err != nil {
		t.Fatalf("ReserveUse() error = %v", err)
	}
	c := server.echo.NewContext(httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/", http.NoBody), httptest.NewRecorder())
	request := policy.Request{Client: "bob", Operation: policy.OperationGitPushForce, Target: policy.Target{Kind: "repo", Owner: "osolmaz", Name: "gh-broker"}}
	decision := policy.Decision{GrantID: result.Grant.ID}
	if err := server.runAuthorizedBrokerRequest(c, request, decision, []grants.UseReservation{reserved}, func(echo.Context) error {
		return errors.New("credential lookup failed")
	}); err == nil {
		t.Fatal("runAuthorizedBrokerRequest() error = nil")
	}
	assertGrantUseState(t, server, result.Grant.ID, grants.StatusActive, 0, 0)
}

func TestReleaseReservedGrantUse(t *testing.T) {
	t.Parallel()
	server := newTestServer(t)
	result, _, err := server.requestGrant(grantsRequestForMainPush(t))
	if err != nil {
		t.Fatalf("Request() error = %v", err)
	}
	if _, err := grantstest.Approve(server.grants, result.Grant.ID, "operator"); err != nil {
		t.Fatalf("Approve() error = %v", err)
	}
	reserved, err := server.grants.ReserveUse(result.Grant.ID, "released-use", result.Grant.Operation)
	if err != nil {
		t.Fatalf("ReserveUse() error = %v", err)
	}
	server.releaseGrantUses([]grants.UseReservation{reserved})
	assertGrantUseState(t, server, result.Grant.ID, grants.StatusActive, 0, 0)
}

func TestGetGrantDirect(t *testing.T) {
	t.Parallel()
	server := newTestServerWithPolicyAndHandler(t, requestPRPolicy(t), func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
	})
	result, _, err := server.requestGrant(grants.Request{
		Client:          "bob",
		ClientRequestID: "get-direct",
		Operation:       string(policy.Operation("pull_request.create")),
		Target:          policy.CoreTarget(policy.Target{Kind: "repo", Owner: "osolmaz", Name: "gh-broker"}),
		Attrs:           map[string][]string{"ref": {"refs/heads/bob/work"}, "head_ref": {"refs/heads/bob/work"}, "base_ref": {"refs/heads/main"}},
		Reason:          "get direct",
		Duration:        5 * time.Minute,
		PendingTimeout:  time.Minute,
		MaxUses:         1,
	})
	if err != nil {
		t.Fatalf("Request() error = %v", err)
	}
	context := newGrantContext(t, server, result.Grant.ID, "bob")
	if err := server.getGrant(context); err != nil {
		t.Fatalf("getGrant() error = %v", err)
	}
	if context.Response().Status != http.StatusOK {
		t.Fatalf("status = %d, want OK", context.Response().Status)
	}
	otherClient := newGrantContext(t, server, result.Grant.ID, "alice")
	if err := server.getGrant(otherClient); err == nil {
		t.Fatal("getGrant(other client) error = nil, want not found")
	}
}

func createGrant(t *testing.T, server *Server, requestID string, reason string) *httptest.ResponseRecorder {
	t.Helper()
	body := fmt.Sprintf(
		`{"client_request_id":%q,"operation":"git.push.force","target":{"kind":"repo","owner":"osolmaz","name":"gh-broker"},"attrs":{"ref":"refs/heads/bob/work"},"reason":%q,"minutes":5}`,
		requestID,
		reason,
	)
	return doWithBody(t, server, http.MethodPost, "/api/grants", bearerAuth(), []byte(body))
}

func TestGrantCreateRejectsInvalidRequests(t *testing.T) {
	t.Parallel()
	server := newTestServerWithPolicyAndHandler(t, requestPRPolicy(t), func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
	})
	noOperator := createGrant(t, server, "missing-operator", "reason")
	if noOperator.Code != http.StatusServiceUnavailable {
		t.Fatalf("no operator status = %d, want service unavailable", noOperator.Code)
	}
	server.operatorConfigured = true
	cases := map[string]struct {
		body string
		want int
	}{
		"bad json":               {body: `{`, want: http.StatusBadRequest},
		"missing reason":         {body: `{"client_request_id":"bad","operation":"pull_request.create","target":{"kind":"repo","owner":"osolmaz","name":"gh-broker"},"attrs":{"ref":"refs/heads/bob/work","head_ref":"refs/heads/bob/work","base_ref":"refs/heads/main"}}`, want: http.StatusBadRequest},
		"non protocol operation": {body: `{"client_request_id":"bad","operation":"pull_request.create","target":{"kind":"repo","owner":"osolmaz","name":"gh-broker"},"attrs":{"ref":"refs/heads/bob/work","head_ref":"refs/heads/bob/work","base_ref":"refs/heads/main"},"reason":"open PR"}`, want: http.StatusBadRequest},
		"not requestable":        {body: `{"client_request_id":"bad","operation":"git.fetch","target":{"kind":"repo","owner":"osolmaz","name":"gh-broker"},"reason":"fetch"}`, want: http.StatusBadRequest},
		"too long":               {body: `{"client_request_id":"bad","operation":"pull_request.create","target":{"kind":"repo","owner":"osolmaz","name":"gh-broker"},"attrs":{"ref":"refs/heads/bob/work","head_ref":"refs/heads/bob/work","base_ref":"refs/heads/main"},"reason":"too long","minutes":99}`, want: http.StatusBadRequest},
	}
	for name, tc := range cases {
		response := doWithBody(t, server, http.MethodPost, "/api/grants", bearerAuth(), []byte(tc.body))
		if response.Code != tc.want {
			t.Fatalf("%s status = %d, body = %s, want %d", name, response.Code, response.Body.String(), tc.want)
		}
	}
}

func TestGrantStoreHTTPError(t *testing.T) {
	t.Parallel()
	cases := map[string]struct {
		err        error
		wantStatus int
	}{
		"idempotency conflict": {err: grants.ErrIdempotencyConflict, wantStatus: http.StatusConflict},
		"capacity":             {err: grants.ErrCapacity, wantStatus: http.StatusTooManyRequests},
		"validation":           {err: errors.New("invalid grant"), wantStatus: http.StatusBadRequest},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			var httpError *echo.HTTPError
			if err := grantStoreHTTPError(tc.err); !errors.As(err, &httpError) || httpError.Code != tc.wantStatus {
				t.Fatalf("grantStoreHTTPError() = %#v, want status %d", err, tc.wantStatus)
			}
		})
	}
}

func TestDecodeGrantCreateDirect(t *testing.T) {
	t.Parallel()
	server := newTestServer(t)
	valid := newBodyContext(t, server, `{"client_request_id":"request-1","operation":"pull_request.create","target":{"kind":"repo","owner":"osolmaz","name":"gh-broker"},"attrs":{"ref":"refs/heads/bob/work"},"reason":"open PR"}`)
	payload, err := decodeGrantCreate(valid)
	if err != nil {
		t.Fatalf("decodeGrantCreate(valid) error = %v", err)
	}
	if payload.ClientRequestID != "request-1" || payload.Reason != "open PR" {
		t.Fatalf("payload = %+v, want decoded request", payload)
	}
	cases := map[string]string{
		"trailing json":             `{"reason":"ok"} {}`,
		"missing reason":            `{"client_request_id":"request-1"}`,
		"missing client request id": `{"reason":"open PR"}`,
		"bad json":                  `{`,
	}
	for name, body := range cases {
		if _, err := decodeGrantCreate(newBodyContext(t, server, body)); err == nil {
			t.Fatalf("%s decodeGrantCreate() error = nil, want error", name)
		}
	}
	oversized := newBodyContext(t, server, strings.Repeat("a", int(maxGrantRequestBodyBytes)+1))
	if _, err := decodeGrantCreate(oversized); err == nil {
		t.Fatal("oversized decodeGrantCreate() error = nil, want error")
	}
}

func TestPlanGrantCreateDirect(t *testing.T) {
	t.Parallel()
	server := newTestServerWithPolicyAndHandler(t, requestPRPolicy(t), func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
	})
	body := `{"client_request_id":"request-1","operation":"git.push.force","target":{"kind":"repo","owner":"osolmaz","name":"gh-broker"},"attrs":{"ref":"refs/heads/bob/work"},"reason":"force push work branch","minutes":5}`
	noOperator := newBodyContext(t, server, body)
	if _, err := server.planGrantCreate(noOperator); err == nil {
		t.Fatal("planGrantCreate(no operator) error = nil, want service unavailable")
	}
	server.operatorConfigured = true
	plan, err := server.planGrantCreate(newBodyContext(t, server, body))
	if err != nil {
		t.Fatalf("planGrantCreate() error = %v", err)
	}
	if plan.request.Client != "bob" || plan.maxUses != usebudget.MaxFiniteUses || plan.duration != 5*time.Minute {
		t.Fatalf("plan = %+v, want requestable bob grant", plan)
	}
	notRequestable := `{"client_request_id":"request-2","operation":"git.fetch","target":{"kind":"repo","owner":"osolmaz","name":"gh-broker"},"reason":"fetch"}`
	if _, err := server.planGrantCreate(newBodyContext(t, server, notRequestable)); err == nil {
		t.Fatal("planGrantCreate(not requestable) error = nil, want forbidden")
	}
}

func TestAPIGrantFromStoreIncludesSafeStatusFields(t *testing.T) {
	t.Parallel()
	expiresAt := time.Date(2026, 7, 9, 12, 0, 0, 0, time.FixedZone("test", 3600))
	api := apiGrantFromStore(grants.Grant{
		ID:               "grant-1",
		Status:           grants.StatusActive,
		Operation:        string(policy.OperationGitPushForce),
		Target:           policy.CoreTarget(policy.Target{Kind: "repo", Owner: "osolmaz", Name: "gh-broker"}),
		Attrs:            map[string][]string{"ref": {"refs/heads/main"}},
		Reason:           "test",
		Duration:         5 * time.Minute,
		MaxUses:          3,
		UsedCount:        1,
		ReservedCount:    1,
		PendingExpiresAt: time.Time{},
		ExpiresAt:        expiresAt,
		ClientRequestID:  "request-1",
	})
	if api.PendingUntil != nil {
		t.Fatalf("PendingUntil = %v, want nil for zero time", api.PendingUntil)
	}
	if api.ExpiresAt == nil || api.ExpiresAt.Location() != time.UTC {
		t.Fatalf("ExpiresAt = %v, want UTC pointer", api.ExpiresAt)
	}
	if api.UsesRemaining != 1 || api.UsedCount != 1 || api.Minutes != 5 {
		t.Fatalf("api grant = %+v, want safe use counters", api)
	}
	if api.Target.Owner != "osolmaz" || api.Target.Name != "gh-broker" || api.ClientRequestID != "request-1" {
		t.Fatalf("api grant = %+v, want target and request id", api)
	}
}

func TestAPITarget(t *testing.T) {
	t.Parallel()
	target := apiTarget(policy.CoreTarget(policy.Target{Kind: "repo", Owner: "osolmaz", Name: "unyolo"}))
	if target.Owner != "osolmaz" || target.Name != "unyolo" || target.Kind != "repo" {
		t.Fatalf("apiTarget() = %+v, want repo target", target)
	}
}

func TestLegacyJSONProxyRoutesAreRemoved(t *testing.T) {
	server := newTestServer(t)
	for _, path := range []string{"/api/repos", "/api/repos/osolmaz/unyolo/contents/README.md"} {
		response := do(t, server, http.MethodGet, path, bearerAuth())
		if response.Code != http.StatusNotFound {
			t.Fatalf("%s status = %d, want 404", path, response.Code)
		}
	}
}

func TestAuditLogDoesNotExposeClientSecretsOrBodies(t *testing.T) {
	t.Parallel()
	var logs bytes.Buffer
	server := newTestServer(t)
	server.auditWriter = unyoloaudit.New(&logs)
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
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusBadRequest)
	}
	logText := logs.String()
	for _, forbidden := range []string{testSharedSecret, "do-not-log-cookie", string(rawBody)} {
		if strings.Contains(logText, forbidden) {
			t.Fatalf("audit log exposed %q: %s", forbidden, logText)
		}
	}
}

func TestAuditLogRecordsPolicyDenialWithoutSecrets(t *testing.T) {
	t.Parallel()
	var logs bytes.Buffer
	server := newTestServer(t)
	server.auditWriter = unyoloaudit.New(&logs)
	response := doWithBody(
		t,
		server,
		http.MethodPost,
		"/outside/repo.git/git-receive-pack",
		bearerAuth(),
		receivePackCreate("refs/heads/bob/work"),
	)
	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusForbidden)
	}
	logText := logs.String()
	for _, expected := range []string{`"operation":"git.push.branch_create"`, `"decision":"denied"`, `"client":"bob"`, `"target":"outside/repo"`} {
		if !strings.Contains(logText, expected) {
			t.Fatalf("audit log missing %s: %s", expected, logText)
		}
	}
	if strings.Contains(logText, testSharedSecret) {
		t.Fatalf("audit log exposed shared secret: %s", logText)
	}
}

func TestAuditLogRecordsActualReceivePackOperation(t *testing.T) {
	t.Parallel()
	var logs bytes.Buffer
	server := newTestServer(t)
	server.auditWriter = unyoloaudit.New(&logs)
	response := doWithBody(
		t,
		server,
		http.MethodPost,
		"/osolmaz/gh-broker.git/git-receive-pack",
		bearerAuth(),
		receivePackCreate("refs/heads/bob/work"),
	)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	logText := logs.String()
	for _, expected := range []string{`"operation":"git.push.branch_create"`, `"decision":"proxied"`, `"matched_rule_ids":["bob-push-branches"]`} {
		if !strings.Contains(logText, expected) {
			t.Fatalf("audit log missing %s: %s", expected, logText)
		}
	}
	if strings.Contains(logText, `"operation":"git.push.fast_forward"`) {
		t.Fatalf("audit log used wrong operation: %s", logText)
	}
}

func TestNewConfiguresGitHubHTTPTimeoutAndReceivePackLimit(t *testing.T) {
	t.Parallel()
	server, err := New(config.Config{
		ClientID:            "bob",
		SharedSecret:        testSharedSecret,
		GitHubToken:         testGitHubToken,
		GitHubTokenFile:     "/protected/github-token",
		StateDir:            t.TempDir(),
		GitHubHTTPTimeout:   7 * time.Second,
		GitHubStreamTimeout: 13 * time.Second,
		MaxReceivePackBytes: 99,
	}, testBrokerPolicy(t))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	t.Cleanup(func() { _ = server.Close() })
	if server.githubClient.Timeout != 7*time.Second {
		t.Fatalf("github timeout = %s, want 7s", server.githubClient.Timeout)
	}
	if server.githubGitClient.Timeout != 13*time.Second {
		t.Fatalf("github git timeout = %s, want 13s", server.githubGitClient.Timeout)
	}
	if server.maxReceivePackBytes != 99 {
		t.Fatalf("max receive-pack bytes = %d, want 99", server.maxReceivePackBytes)
	}
}

func TestGitProxyUsesServerSideCredential(t *testing.T) {
	t.Parallel()
	var gotAuthorization string
	server := newTestServerWithHandler(t, func(w http.ResponseWriter, r *http.Request) {
		gotAuthorization = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	})
	response := do(t, server, http.MethodGet, "/osolmaz/gh-broker.git/info/refs?service=git-upload-pack", bearerAuth())
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	if gotAuthorization != githubGitAuthorization(testGitHubToken) {
		t.Fatalf("upstream authorization was not server-side GitHub auth")
	}
}

func TestGitProxyUsesGitHubAppInstallationToken(t *testing.T) {
	t.Parallel()
	var gotAuthorization string
	var tokenMints int
	server := newTestServerWithHandler(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/osolmaz/gh-broker/installation":
			writeRawJSON(w, `{"id":42}`)
		case "/app/installations/42/access_tokens":
			tokenMints++
			if tokenMints == 1 {
				writeRawJSON(w, `{"token":"ghs_bootstrap","expires_at":"2099-07-09T18:00:00Z"}`)
			} else {
				writeRawJSON(w, `{"token":"ghs_repo_token","expires_at":"2099-07-09T18:00:00Z"}`)
			}
		case "/repos/osolmaz/gh-broker":
			writeRawJSON(w, `{"id":99,"name":"gh-broker","owner":{"login":"osolmaz"}}`)
		case "/installation/token":
			w.WriteHeader(http.StatusNoContent)
		case "/osolmaz/gh-broker.git/info/refs":
			gotAuthorization = r.Header.Get("Authorization")
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected upstream path %s", r.URL.Path)
		}
	})
	server.githubCredentials = newTestGitHubAppManager(t, server)
	response := do(t, server, http.MethodGet, "/osolmaz/gh-broker.git/info/refs?service=git-upload-pack", bearerAuth())
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	if gotAuthorization != githubGitAuthorization("ghs_repo_token") {
		t.Fatalf("authorization = %q, want GitHub App installation git auth", gotAuthorization)
	}
}

func TestAgentDiscoveryAdvertisesGitHubAppOperations(t *testing.T) {
	t.Parallel()
	server := newTestServerWithHandler(t, func(http.ResponseWriter, *http.Request) {
		t.Fatal("credential discovery made an upstream request")
	})
	server.githubCredentials = newTestGitHubAppManager(t, server)

	descriptor := server.discoverAgent("agent")
	if !descriptor.Credential.Ready || descriptor.Credential.Provider != "github" ||
		descriptor.Credential.CredentialKind != string(githubauth.KindInstallation) {
		t.Fatalf("credential descriptor = %+v", descriptor.Credential)
	}
	if len(descriptor.Operations) == 0 {
		t.Fatal("GitHub App discovery advertised no operations")
	}
	for _, operation := range descriptor.Operations {
		descriptor, found := opcatalog.ByName(operation)
		if !found || !descriptor.AgentFacing || descriptor.CredentialKind == string(githubauth.KindUser) {
			t.Fatalf("invalid advertised operation %q", operation)
		}
	}
}

func TestAgentDiscoveryAdvertisesAdminMergeForDevelopmentUserToken(t *testing.T) {
	t.Parallel()
	server := newTestServerWithHandler(t, func(http.ResponseWriter, *http.Request) {
		t.Fatal("credential discovery made an upstream request")
	})
	descriptor := server.discoverAgent("agent")
	if descriptor.Credential.CredentialKind != string(githubauth.KindDevelopmentToken) ||
		!slices.Contains(descriptor.Operations, "pull_request.merge_admin") {
		t.Fatalf("development descriptor = %+v", descriptor)
	}
}

func TestReceivePackUsesWriteAndInspectionInstallationTokens(t *testing.T) {
	t.Parallel()
	var tokenRequests []string
	var gitAuthorization string
	server := newTestServerWithHandler(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/osolmaz/gh-broker/installation":
			writeRawJSON(w, `{"id":42}`)
		case "/app/installations/42/access_tokens":
			body, _ := io.ReadAll(r.Body)
			tokenRequests = append(tokenRequests, string(body))
			writeRawJSON(w, fmt.Sprintf(`{"token":"ghs_token_%d","expires_at":"2099-07-09T18:00:00Z"}`, len(tokenRequests)))
		case "/repos/osolmaz/gh-broker":
			writeRawJSON(w, `{"id":99,"name":"gh-broker","default_branch":"main","owner":{"login":"osolmaz"}}`)
		case "/installation/token":
			w.WriteHeader(http.StatusNoContent)
		case "/repos/osolmaz/gh-broker/rules/branches/bob/work":
			writeRawJSON(w, `[]`)
		case "/repos/osolmaz/gh-broker/branches/bob/work/protection":
			http.NotFound(w, r)
		case "/osolmaz/gh-broker.git/git-receive-pack":
			gitAuthorization = r.Header.Get("Authorization")
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected upstream path %s", r.URL.Path)
		}
	})
	server.githubCredentials = newTestGitHubAppManager(t, server)
	response := doWithBody(t, server, http.MethodPost, "/osolmaz/gh-broker.git/git-receive-pack", bearerAuth(),
		receivePackCreate("refs/heads/bob/work"))
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	if len(tokenRequests) != 3 || !strings.Contains(tokenRequests[0], `"contents":"write"`) ||
		!strings.Contains(tokenRequests[1], `"contents":"write"`) ||
		!strings.Contains(tokenRequests[2], `"administration":"read"`) || !strings.Contains(tokenRequests[2], `"metadata":"read"`) {
		t.Fatalf("installation token requests = %#v", tokenRequests)
	}
	if gitAuthorization != githubGitAuthorization("ghs_token_2") {
		t.Fatalf("git authorization = %q, want repository-scoped write token", gitAuthorization)
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
		"/osolmaz/gh-broker.git/info/refs?service=git-upload-pack",
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
		setCredentialMetadataHeaders(w.Header())
		w.Header().Set("X-Test-Upstream", "kept")
		w.WriteHeader(http.StatusOK)
	})
	response := doWithHeaders(
		t,
		server,
		http.MethodGet,
		"/osolmaz/gh-broker.git/info/refs?service=git-upload-pack",
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
	assertCredentialMetadataHeadersDropped(t, response.Header())
	if response.Header().Get("X-Test-Upstream") != "kept" {
		t.Fatalf("response header missing non-hop upstream header")
	}
}

func TestGitHubCredentialMetadataHeaderPredicate(t *testing.T) {
	t.Parallel()
	for _, header := range []string{
		"Authentication-Info",
		"github-authentication-token-expiration",
		"WWW-Authenticate",
		"X-Accepted-OAuth-Scopes",
		"X-GitHub-Authentication-Token-Expiration",
		"X-GitHub-SSO",
		"X-OAuth-Scopes",
	} {
		if !githubCredentialMetadataHeader(header) {
			t.Fatalf("githubCredentialMetadataHeader(%q) = false, want true", header)
		}
	}
	if githubCredentialMetadataHeader("X-RateLimit-Remaining") {
		t.Fatal("githubCredentialMetadataHeader(rate limit) = true, want false")
	}
}

func TestUnsupportedGitServiceIsRejected(t *testing.T) {
	t.Parallel()
	server := newTestServer(t)
	response := do(t, server, http.MethodGet, "/osolmaz/gh-broker.git/info/refs?service=bad-service", bearerAuth())
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusBadRequest)
	}
}

func TestStatusHelpers(t *testing.T) {
	t.Parallel()
	server := newTestServer(t)
	context := server.echo.NewContext(
		httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/healthz", http.NoBody),
		httptest.NewRecorder(),
	)
	if got := responseStatus(context); got != http.StatusOK {
		t.Fatalf("responseStatus(default) = %d, want OK", got)
	}
	context.Response().Status = http.StatusCreated
	if got := responseStatus(context); got != http.StatusCreated {
		t.Fatalf("responseStatus(created) = %d, want created", got)
	}
	if got := errorStatus(context, echo.NewHTTPError(http.StatusBadGateway, "bad upstream")); got != http.StatusBadGateway {
		t.Fatalf("errorStatus(http error) = %d, want bad gateway", got)
	}
	if got := errorStatus(context, errors.New("plain")); got != http.StatusCreated {
		t.Fatalf("errorStatus(plain) = %d, want response status", got)
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

func TestReceivePackCommandsFromBodyParsesMultipleRefs(t *testing.T) {
	t.Parallel()
	commands, err := receivePackCommandsFromBody(receivePackCommands(
		commandLine(zeroOID(), oid("1"), "refs/heads/a"),
		commandLine(zeroOID(), oid("2"), "refs/tags/v1"),
		commandLine(oid("3"), zeroOID(), "refs/heads/b"),
	))
	if err != nil {
		t.Fatalf("receivePackCommandsFromBody() error = %v", err)
	}
	var refs []string
	for _, command := range commands {
		refs = append(refs, command.Ref)
	}
	if strings.Join(refs, ",") != "refs/heads/a,refs/tags/v1,refs/heads/b" {
		t.Fatalf("refs = %v, want all refs", refs)
	}
}

func newTestServer(t *testing.T) *Server {
	t.Helper()
	return newTestServerWithHandler(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("proxied"))
	})
}

func newTestServerWithHandler(t *testing.T, handler http.HandlerFunc) *Server {
	t.Helper()
	return newTestServerWithPolicyAndHandler(t, testBrokerPolicy(t), handler)
}

func newTestServerWithPolicyAndHandler(t *testing.T, brokerPolicy *policy.Policy, handler http.HandlerFunc) *Server {
	t.Helper()
	return newTestServerWithPolicyAndHandlerInStateDir(t, brokerPolicy, handler, t.TempDir())
}

func newTestServerWithPolicyAndHandlerInStateDir(t *testing.T, brokerPolicy *policy.Policy, handler http.HandlerFunc, stateDir string) *Server {
	t.Helper()
	upstream := httptest.NewServer(withDefaultGitHubSafetyState(handler))
	t.Cleanup(upstream.Close)
	server, err := New(config.Config{
		ClientID: "bob", SharedSecret: testSharedSecret, GitHubToken: testGitHubToken, GitHubTokenFile: "/protected/github-token",
		GitHubAPIBaseURL: upstream.URL, GitHubWebBaseURL: upstream.URL, StateDir: stateDir,
	}, brokerPolicy)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	upstreamURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	writeClient := *upstream.Client()
	server.githubClient = &writeClient
	server.githubClient.CheckRedirect = stopGitHubRedirect
	server.githubGitClient = server.githubClient
	server.githubGitBaseURL = upstreamURL
	server.githubAPIBaseURL = upstreamURL
	return server
}

func withDefaultGitHubSafetyState(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/rules/branches/"):
			_, _ = w.Write([]byte(`[]`))
		case strings.Contains(r.URL.Path, "/branches/") && strings.HasSuffix(r.URL.Path, "/protection"):
			http.NotFound(w, r)
		case strings.HasPrefix(r.URL.Path, "/repos/") && len(strings.Split(strings.Trim(r.URL.Path, "/"), "/")) == 3 && strings.Contains(r.Header.Get("Authorization"), testGitHubToken):
			_, _ = w.Write([]byte(`{"default_branch":"main"}`))
		default:
			next(w, r)
		}
	}
}

func requestPRPolicy(t *testing.T) *policy.Policy {
	t.Helper()
	brokerPolicy, err := policy.New(policy.Scope{Rules: []policy.Rule{
		{
			ID:         "bob-can-request-pr-create",
			Effect:     policy.EffectRequest,
			Clients:    []string{"bob"},
			Operations: []policy.Operation{policy.Operation("pull_request.create")},
			Targets:    []policy.Target{{Kind: "repo", Owner: "osolmaz", Name: "gh-broker"}},
			Attrs: map[string][]string{
				"refs":      {"refs/heads/bob/work"},
				"head_refs": {"refs/heads/bob/work"},
				"base_refs": {"refs/heads/main"},
			},
		},
		{
			ID:         "bob-can-request-force-push",
			Effect:     policy.EffectRequest,
			Clients:    []string{"bob"},
			Operations: []policy.Operation{policy.OperationGitPushForce},
			Targets:    []policy.Target{{Kind: "repo", Owner: "osolmaz", Name: "gh-broker"}},
			Attrs:      map[string][]string{"refs": {"refs/heads/bob/work"}},
		},
	}})
	if err != nil {
		t.Fatalf("policy.New(requestPRPolicy) error = %v", err)
	}
	return brokerPolicy
}

func denyMainWithRequestPolicy(t *testing.T) *policy.Policy {
	t.Helper()
	brokerPolicy, err := policy.New(policy.Scope{Rules: []policy.Rule{
		{
			ID:         "deny-main",
			Effect:     policy.EffectDeny,
			Clients:    []string{"*"},
			Operations: []policy.Operation{policy.OperationGitPushForce},
			Targets:    []policy.Target{{Kind: "repo", Owner: "osolmaz", Name: "gh-broker"}},
			Attrs:      map[string][]string{"refs": {"refs/heads/main"}},
		},
		{
			ID:         "request-main",
			Effect:     policy.EffectRequest,
			Clients:    []string{"bob"},
			Operations: []policy.Operation{policy.OperationGitPushForce},
			Targets:    []policy.Target{{Kind: "repo", Owner: "osolmaz", Name: "gh-broker"}},
			Attrs:      map[string][]string{"refs": {"refs/heads/main"}},
		},
	}})
	if err != nil {
		t.Fatalf("policy.New(denyMainWithRequestPolicy) error = %v", err)
	}
	return brokerPolicy
}

func grantsRequestForMainPush(t *testing.T) grants.Request {
	t.Helper()
	return grants.Request{
		Client:          "bob",
		ClientRequestID: "main-push",
		Operation:       string(policy.OperationGitPushForce),
		Target:          policy.CoreTarget(policy.Target{Kind: "repo", Owner: "osolmaz", Name: "gh-broker"}),
		Attrs:           map[string][]string{"ref": {"refs/heads/main"}},
		Reason:          "test deny over grant",
		Duration:        5 * time.Minute,
		PendingTimeout:  time.Minute,
		MaxUses:         1,
	}
}

func requestMainPushPolicy(t *testing.T) *policy.Policy {
	t.Helper()
	brokerPolicy, err := policy.New(policy.Scope{Rules: []policy.Rule{
		{
			ID:         "request-main",
			Effect:     policy.EffectRequest,
			Clients:    []string{"bob"},
			Operations: []policy.Operation{policy.OperationGitPushForce},
			Targets:    []policy.Target{{Kind: "repo", Owner: "osolmaz", Name: "gh-broker"}},
			Attrs:      map[string][]string{"refs": {"refs/heads/main"}},
		},
	}})
	if err != nil {
		t.Fatalf("policy.New(requestMainPushPolicy) error = %v", err)
	}
	return brokerPolicy
}

func requestTagPushPolicy(t *testing.T) *policy.Policy {
	t.Helper()
	brokerPolicy, err := policy.New(policy.Scope{Rules: []policy.Rule{{
		ID: "request-tag", Effect: policy.EffectRequest, Clients: []string{"bob"},
		Operations: []policy.Operation{policy.OperationGitTagUpdate},
		Targets:    []policy.Target{{Kind: "repo", Owner: "osolmaz", Name: "gh-broker"}},
		Attrs:      map[string][]string{"refs": {"refs/tags/*"}},
	}}})
	if err != nil {
		t.Fatalf("policy.New(requestTagPushPolicy) error = %v", err)
	}
	return brokerPolicy
}

func approveMainPushGrant(t *testing.T, server *Server) string {
	t.Helper()
	result, _, err := server.requestGrant(grantsRequestForMainPush(t))
	if err != nil {
		t.Fatalf("Request() error = %v", err)
	}
	if _, err := grantstest.Approve(server.grants, result.Grant.ID, "operator"); err != nil {
		t.Fatalf("Approve() error = %v", err)
	}
	return result.Grant.ID
}

func assertGrantUseState(t *testing.T, server *Server, grantID string, status grants.Status, usedCount int, reservedCount int) {
	t.Helper()
	grant, err := server.grants.Get(grantID)
	if err != nil {
		t.Fatalf("Get(%q) error = %v", grantID, err)
	}
	if grant.Status != status || grant.UsedCount != usedCount || grant.ReservedCount != reservedCount {
		t.Fatalf("grant = %+v, want status=%s used=%d reserved=%d", grant, status, usedCount, reservedCount)
	}
}

func waitForGitApproval(t *testing.T, server *Server, count int) grants.Grant {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		items, err := server.grants.ListForClient("bob")
		if err != nil {
			t.Fatal(err)
		}
		if len(items) >= count && items[count-1].Status == grants.StatusPending {
			return items[count-1]
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for Git approval %d", count)
	return grants.Grant{}
}

// approvalCount returns the number of approvals that the test client requested.
func approvalCount(t *testing.T, server *Server) int {
	t.Helper()
	items, err := server.grants.ListForClient("bob")
	if err != nil {
		t.Fatal(err)
	}
	return len(items)
}

func testBrokerPolicy(t *testing.T) *policy.Policy {
	t.Helper()
	brokerPolicy, err := policy.New(policy.Scope{Rules: []policy.Rule{
		{
			ID:         "deny-dangerous",
			Effect:     policy.EffectDeny,
			Clients:    []string{"*"},
			Operations: []policy.Operation{policy.OperationGitPushForce, policy.OperationGitRefDelete},
			Targets:    []policy.Target{{Kind: "repo", Owner: "osolmaz", Name: "gh-broker"}},
			Attrs:      map[string][]string{"refs": {"refs/heads/main"}},
		},
		{
			ID:         "bob-repo-read",
			Effect:     policy.EffectAllow,
			Clients:    []string{"bob"},
			Operations: []policy.Operation{policy.OperationGitFetch, policy.Operation("repo.metadata.read")},
			Targets: []policy.Target{
				{Kind: "repo", Owner: "osolmaz", Name: "*"},
				{Kind: "repo", Owner: "openclaw", Name: "openclaw"},
			},
		},
		{
			ID:         "bob-contents-read",
			Effect:     policy.EffectAllow,
			Clients:    []string{"bob"},
			Operations: []policy.Operation{policy.Operation("repo.contents.read")},
			Targets: []policy.Target{
				{Kind: "repo", Owner: "osolmaz", Name: "*"},
				{Kind: "repo", Owner: "openclaw", Name: "openclaw"},
			},
			Attrs: map[string][]string{"paths": {"*", "docs/*"}},
		},
		{
			ID:         "bob-list-repos",
			Effect:     policy.EffectAllow,
			Clients:    []string{"bob"},
			Operations: []policy.Operation{policy.Operation("installation.repo.list")},
			Targets:    []policy.Target{{Kind: "installation"}},
		},
		{
			ID:         "bob-push-advertise",
			Effect:     policy.EffectAllow,
			Clients:    []string{"bob"},
			Operations: []policy.Operation{policy.OperationGitPushAdvertise, policy.OperationGitLFSWrite},
			Targets:    []policy.Target{{Kind: "repo", Owner: "osolmaz", Name: "*"}},
		},
		{
			ID:         "bob-push-branches",
			Effect:     policy.EffectAllow,
			Clients:    []string{"bob"},
			Operations: []policy.Operation{policy.OperationGitPushBranchCreate, policy.OperationGitPushForce},
			Targets:    []policy.Target{{Kind: "repo", Owner: "osolmaz", Name: "*"}},
			Attrs:      map[string][]string{"refs": {"refs/heads/bob/*", "refs/heads/agent/*"}},
		},
		{
			ID:         "bob-pr-create",
			Effect:     policy.EffectAllow,
			Clients:    []string{"bob"},
			Operations: []policy.Operation{policy.Operation("pull_request.create")},
			Targets:    []policy.Target{{Kind: "repo", Owner: "osolmaz", Name: "*"}},
			Attrs: map[string][]string{
				"refs":      {"refs/heads/bob/*", "refs/heads/agent/*"},
				"base_refs": {"refs/heads/main"},
			},
		},
		{
			ID:         "direct-main",
			Effect:     policy.EffectAllow,
			Clients:    []string{"bob"},
			Operations: []policy.Operation{policy.OperationGitPushForce},
			Targets:    []policy.Target{{Kind: "repo", Owner: "osolmaz", Name: "direct-main"}},
			Attrs:      map[string][]string{"refs": {"refs/heads/main"}},
		},
	}})
	if err != nil {
		t.Fatalf("policy.New() error = %v", err)
	}
	return brokerPolicy
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

func doWebhook(t *testing.T, server *Server, body []byte, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/webhooks/github", bytes.NewReader(body))
	for key, value := range headers {
		request.Header.Set(key, value)
	}
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	return response
}

func signedWebhookHeaders(secret string, body []byte) map[string]string {
	return map[string]string{
		"X-GitHub-Event":      "installation",
		"X-GitHub-Delivery":   "delivery-1",
		"X-Hub-Signature-256": webhookSignature(secret, body),
	}
}

func webhookSignature(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

func newGitContext(t *testing.T, server *Server, method string, path string, body []byte) echo.Context {
	t.Helper()
	var requestBody io.Reader = http.NoBody
	if len(body) > 0 {
		requestBody = bytes.NewReader(body)
	}
	request := httptest.NewRequestWithContext(context.Background(), method, path, requestBody)
	request.Header.Set("Authorization", bearerAuth())
	context := server.echo.NewContext(request, httptest.NewRecorder())
	context.Set("gh-broker.client", "bob")
	context.SetParamNames("owner", "repoGit")
	context.SetParamValues("osolmaz", "gh-broker.git")
	return context
}

func newGrantContext(t *testing.T, server *Server, grantID string, client string) echo.Context {
	t.Helper()
	request := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/grants/"+grantID, http.NoBody)
	recorder := httptest.NewRecorder()
	context := server.echo.NewContext(request, recorder)
	context.Set("gh-broker.client", client)
	context.SetParamNames("id")
	context.SetParamValues(grantID)
	return context
}

func newBodyContext(t *testing.T, server *Server, body string) echo.Context {
	t.Helper()
	request := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/grants", strings.NewReader(body))
	context := server.echo.NewContext(request, httptest.NewRecorder())
	context.Set("gh-broker.client", "bob")
	return context
}

func setCredentialMetadataHeaders(header http.Header) {
	header.Set("Authentication-Info", "token-meta")
	header.Set("GitHub-Authentication-Token-Expiration", "2026-07-08T00:00:00Z")
	header.Add("Set-Cookie", "server-side-session=secret")
	header.Add("Set-Cookie2", "server-side-legacy=secret")
	header.Set("WWW-Authenticate", "Bearer")
	header.Set("X-Accepted-OAuth-Scopes", "repo")
	header.Set("X-GitHub-Authentication-Token-Expiration", "2026-07-08T00:00:00Z")
	header.Set("X-GitHub-SSO", "required")
	header.Set("X-OAuth-Scopes", "repo, workflow")
}

func assertCredentialMetadataHeadersDropped(t *testing.T, header http.Header) {
	t.Helper()
	for _, name := range []string{
		"Authentication-Info",
		"GitHub-Authentication-Token-Expiration",
		"Set-Cookie",
		"Set-Cookie2",
		"WWW-Authenticate",
		"X-Accepted-OAuth-Scopes",
		"X-GitHub-Authentication-Token-Expiration",
		"X-GitHub-SSO",
		"X-OAuth-Scopes",
	} {
		if values := header.Values(name); len(values) > 0 {
			t.Fatalf("%s forwarded credential metadata values %v", name, values)
		}
	}
}

func bearerAuth() string {
	return "Bearer " + testSharedSecret
}

func receivePackCreate(ref string) []byte {
	return receivePackPayload(zeroOID(), oid("1"), ref)
}

func receivePackPayload(oldOID string, newOID string, ref string) []byte {
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

func oid(char string) string {
	return strings.Repeat(char, 40)
}

func zeroOID() string {
	return "0000000000000000000000000000000000000000"
}

func newTestGitHubAppManager(t *testing.T, server *Server) *githubauth.Manager {
	t.Helper()
	manager, err := githubauth.New(githubauth.Config{
		AppID: "12345", AppPrivateKey: testGitHubAppPrivateKey(t), APIBaseURL: server.githubAPIBaseURL,
		WebBaseURL: server.githubGitBaseURL, HTTPClient: server.githubClient,
		Now: func() time.Time { return time.Date(2026, 7, 9, 17, 0, 0, 0, time.UTC) },
	})
	if err != nil {
		t.Fatalf("githubauth.New() error = %v", err)
	}
	return manager
}

func testGitHubAppPrivateKey(t *testing.T) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
}

func writeRawJSON(w http.ResponseWriter, body string) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(body))
}

type errorRoundTripper struct{}

func (errorRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("upstream unavailable")
}
