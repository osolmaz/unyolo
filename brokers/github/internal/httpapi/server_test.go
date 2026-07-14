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
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/labstack/echo/v4"
	bkaudit "github.com/osolmaz/brokerkit/audit"
	"github.com/osolmaz/brokerkit/brokers/github/internal/config"
	"github.com/osolmaz/brokerkit/brokers/github/internal/githubauth"
	"github.com/osolmaz/brokerkit/brokers/github/internal/policy"
	"github.com/osolmaz/brokerkit/grants"
	"github.com/osolmaz/brokerkit/notify"
	bktelegram "github.com/osolmaz/brokerkit/notify/telegram"
)

const testSharedSecret = "0123456789abcdef0123456789abcdef"
const testGitHubToken = "github-token"

func TestGitCompatibleRoutesRequireAuth(t *testing.T) {
	t.Parallel()
	server := newTestServer(t)
	request := httptest.NewRequestWithContext(
		context.Background(),
		http.MethodGet,
		"/dutifuldev/gh-broker.git/info/refs?service=git-upload-pack",
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
	server.auditWriter = bkaudit.New(&logs)
	body := []byte(`{"action":"added","installation":{"id":42},"repositories_added":[{"full_name":"dutifuldev/gh-broker"}]}`)
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
	for _, want := range []string{`"github_event":"installation_repositories"`, `"github_delivery":"delivery-1"`, `"github_action":"added"`, `"github_installation_id":"42"`, `"target":"dutifuldev/gh-broker"`} {
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

	allowed := do(t, server, http.MethodGet, "/dutifuldev/gh-broker.git/info/refs?service=git-upload-pack", bearerAuth())
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
	context := newGitContext(t, server, http.MethodGet, "/dutifuldev/gh-broker.git/info/refs?service=git-upload-pack", nil)
	if err := server.gitInfoRefs(context); err != nil {
		t.Fatalf("gitInfoRefs() error = %v", err)
	}
	if upstreamCalls != 1 {
		t.Fatalf("upstream calls = %d, want 1", upstreamCalls)
	}

	badContext := newGitContext(t, server, http.MethodGet, "/dutifuldev/gh-broker.git/info/refs?service=bad", nil)
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
	context := newGitContext(t, server, http.MethodPost, "/dutifuldev/gh-broker.git/git-upload-pack", []byte("want refs"))
	if err := server.proxyGit(context); err != nil {
		t.Fatalf("proxyGit() error = %v", err)
	}
	if gotPath != "/dutifuldev/gh-broker.git/git-upload-pack" {
		t.Fatalf("upstream path = %q, want upload-pack path", gotPath)
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
			Targets:    []policy.Target{{Kind: "repo", Owner: "dutifuldev", Name: "gh-broker"}},
		},
	}})
	if err != nil {
		t.Fatalf("policy.New() error = %v", err)
	}
	server := newTestServerWithPolicyAndHandler(t, fetchOnlyPolicy, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	fetch := do(t, server, http.MethodGet, "/dutifuldev/gh-broker.git/info/refs?service=git-upload-pack", bearerAuth())
	if fetch.Code != http.StatusOK {
		t.Fatalf("fetch discovery status = %d, body = %s", fetch.Code, fetch.Body.String())
	}
	push := do(t, server, http.MethodGet, "/dutifuldev/gh-broker.git/info/refs?service=git-receive-pack", bearerAuth())
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
	response := doWithBody(t, server, http.MethodPost, "/dutifuldev/gh-broker.git/git-upload-pack", bearerAuth(), []byte("want refs"))
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	if gotPath != "/dutifuldev/gh-broker.git/git-upload-pack" {
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
		"/dutifuldev/gh-broker.git/git-receive-pack",
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
		"/dutifuldev/gh-broker.git/git-receive-pack",
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
		gotGitPush = r.URL.Path == "/dutifuldev/gh-broker.git/git-receive-pack"
		w.WriteHeader(http.StatusOK)
	})
	response := doWithBody(
		t,
		server,
		http.MethodPost,
		"/dutifuldev/gh-broker.git/git-receive-pack",
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
		gotGitPush = r.URL.Path == "/dutifuldev/gh-broker.git/git-receive-pack"
		w.WriteHeader(http.StatusOK)
	})
	response := doWithBody(
		t,
		server,
		http.MethodPost,
		"/dutifuldev/gh-broker.git/git-receive-pack",
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
		gotGitPush = r.URL.Path == "/dutifuldev/gh-broker.git/git-receive-pack"
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
		"/dutifuldev/gh-broker.git/git-receive-pack",
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
		gotGitPush = r.URL.Path == "/dutifuldev/gh-broker.git/git-receive-pack"
		w.WriteHeader(http.StatusOK)
	})
	response := doWithBody(
		t,
		server,
		http.MethodPost,
		"/dutifuldev/gh-broker.git/git-receive-pack",
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
			Targets:    []policy.Target{{Kind: "repo", Owner: "dutifuldev", Name: "gh-broker"}},
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
		"/dutifuldev/gh-broker.git/git-receive-pack",
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
		gotGitPush = r.URL.Path == "/dutifuldev/gh-broker.git/git-receive-pack"
		w.WriteHeader(http.StatusOK)
	})
	response := doWithBody(
		t,
		server,
		http.MethodPost,
		"/dutifuldev/gh-broker.git/git-receive-pack",
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
		gotGitPush = r.URL.Path == "/dutifuldev/direct-main.git/git-receive-pack"
		w.WriteHeader(http.StatusOK)
	})
	response := doWithBody(
		t,
		server,
		http.MethodPost,
		"/dutifuldev/direct-main.git/git-receive-pack",
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
		gotGitPush = r.URL.Path == "/dutifuldev/gh-broker.git/git-receive-pack"
		w.WriteHeader(http.StatusOK)
	})
	response := doWithBody(
		t,
		server,
		http.MethodPost,
		"/dutifuldev/gh-broker.git/git-receive-pack",
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
		"/dutifuldev/gh-broker.git/git-receive-pack",
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
		"/dutifuldev/gh-broker.git/git-receive-pack",
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
			"/dutifuldev/gh-broker.git/git-receive-pack",
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
		"/dutifuldev/gh-broker.git/git-receive-pack",
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
		"/repos/dutifuldev/gh-broker/pulls",
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
	if _, err := server.grants.Approve(result.Grant.ID, result.DecisionToken, "operator"); err != nil {
		t.Fatalf("Approve() error = %v", err)
	}
	response := doWithBody(
		t,
		server,
		http.MethodPost,
		"/dutifuldev/gh-broker.git/git-receive-pack",
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
		"/dutifuldev/gh-broker.git/git-receive-pack",
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

func TestGrantBackedReceivePackRetainsGrantOnProxyError(t *testing.T) {
	t.Parallel()
	server := newTestServerWithPolicyAndHandler(t, requestMainPushPolicy(t), func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	server.githubClient = &http.Client{Transport: errorRoundTripper{}}
	grantID := approveMainPushGrant(t, server)
	response := doWithBody(
		t,
		server,
		http.MethodPost,
		"/dutifuldev/gh-broker.git/git-receive-pack",
		bearerAuth(),
		receivePackPayload(oid("1"), oid("2"), "refs/heads/main"),
	)
	if response.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, body = %s, want upstream proxy error", response.Code, response.Body.String())
	}
	assertGrantUseState(t, server, grantID, grants.StatusRevoked, 0, 1)
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
		if _, err := server.grants.ReleaseUse(grantID); err != nil {
			t.Fatalf("ReleaseUse() error = %v", err)
		}
		w.WriteHeader(http.StatusOK)
	})
	grantID = approveMainPushGrant(t, server)
	response := doWithBody(
		t,
		server,
		http.MethodPost,
		"/dutifuldev/gh-broker.git/git-receive-pack",
		bearerAuth(),
		receivePackPayload(oid("1"), oid("2"), "refs/heads/main"),
	)
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, body = %s, want grant commit error", response.Code, response.Body.String())
	}
	assertGrantUseState(t, server, grantID, grants.StatusRevoked, 0, 0)
}

func TestTelegramApprovalActivatesGrant(t *testing.T) {
	t.Parallel()
	server := newTestServerWithPolicyAndHandler(t, requestPRPolicy(t), func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
	})
	telegramState := &fakeTelegramState{chatID: 123, messageID: 77}
	telegramAPI := httptest.NewServer(fakeTelegramHandler(t, telegramState))
	t.Cleanup(telegramAPI.Close)
	telegram, err := bktelegram.NewWithOptions("bot-token", telegramState.chatID, telegramAPI.Client(), telegramAPI.URL, bktelegram.Options{
		PollTimeoutSeconds: 1,
		ApproveText:        "Approve",
		DenyText:           "Deny",
	})
	if err != nil {
		t.Fatalf("NewWithOptions() error = %v", err)
	}
	server.notifier = telegram
	server.telegram = telegram

	created := createTelegramPullRequestGrant(t, server, telegramState)
	stored, err := server.grants.Get(created.ID)
	if err != nil {
		t.Fatalf("Get(%q) error = %v", created.ID, err)
	}
	if stored.Notification == nil || stored.Notification.ChatID != telegramState.chatID || stored.Notification.MessageID != telegramState.messageID {
		t.Fatalf("notification = %+v, want persisted Telegram message", stored.Notification)
	}
	pollTelegramApproval(t, telegram, server)
	server.deliverGrantStatusUpdates(context.Background())
	assertGrantActiveAfterTelegram(t, server, created.ID, telegramState)
}

func TestGrantNotificationIsIdempotent(t *testing.T) {
	t.Parallel()
	server := newTestServerWithPolicyAndHandler(t, requestPRPolicy(t), func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
	})
	notifier := &captureNotifier{}
	server.notifier = notifier

	first := createGrant(t, server, "same-request", "open the work PR")
	second := createGrant(t, server, "same-request", "open the work PR")
	if first.Code != http.StatusCreated || second.Code != http.StatusOK {
		t.Fatalf("statuses = %d, %d, want 201 then 200", first.Code, second.Code)
	}
	if len(notifier.messages) != 1 {
		t.Fatalf("messages = %d, want exactly one", len(notifier.messages))
	}
	if decodeGrantResponse(t, first).ID != decodeGrantResponse(t, second).ID {
		t.Fatal("idempotent request returned different grants")
	}
}

func TestUnresolvedGrantNotificationReclaimsAfterLease(t *testing.T) {
	t.Parallel()
	server := newTestServer(t)
	notifier := &captureNotifier{}
	server.notifier = notifier
	now := time.Date(2026, 7, 10, 1, 2, 3, 0, time.UTC)
	grant, claim := createUnresolvedNotificationClaim(t, server, func() time.Time { return now })
	request := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/grants", http.NoBody)
	echoContext := server.echo.NewContext(request, httptest.NewRecorder())

	if _, _, err := server.notifyPendingGrant(echoContext, grantCreatePlan{}, grant.ID); err == nil {
		t.Fatal("notifyPendingGrant() error = nil, want unresolved delivery")
	}
	if len(notifier.messages) != 0 {
		t.Fatalf("messages = %d, want no duplicate send", len(notifier.messages))
	}
	assertUnresolvedNotificationClaim(t, server, grant.ID, claim.Grant.NotificationClaimedAt)
	now = now.Add(30 * time.Second)
	stored, ref, err := server.notifyPendingGrant(echoContext, grantCreatePlan{}, grant.ID)
	assertReclaimedNotification(t, stored, ref, notifier, claim.DecisionToken, err)
}

func createUnresolvedNotificationClaim(t *testing.T, server *Server, now func() time.Time) (grants.Grant, grants.NotificationClaim) {
	t.Helper()
	server.grants = grants.NewDatabase(server.database, grants.Options{Now: now})
	result, _, err := server.requestGrant(grantsRequestForMainPush(t))
	if err != nil {
		t.Fatalf("Request() error = %v", err)
	}
	claim, claimed, err := server.grants.ClaimNotification(result.Grant.ID, 30*time.Second)
	if err != nil || !claimed {
		t.Fatalf("ClaimNotification() = %+v, %v, %v", claim, claimed, err)
	}
	if _, retained, err := server.grants.RetainNotificationClaim(result.Grant.ID, claim.Grant.NotificationClaimedAt); err != nil || !retained {
		t.Fatalf("RetainNotificationClaim() retained=%v err=%v", retained, err)
	}
	return result.Grant, claim
}

func assertUnresolvedNotificationClaim(t *testing.T, server *Server, id string, claimedAt time.Time) {
	t.Helper()
	stored, err := server.grants.Get(id)
	if err != nil {
		t.Fatalf("Get(%q) error = %v", id, err)
	}
	if stored.Status != grants.StatusPending || !stored.NotificationDeliveryUnresolved || !stored.NotificationClaimedAt.Equal(claimedAt) {
		t.Fatalf("grant = %+v, want original unresolved claim", stored)
	}
}

func assertReclaimedNotification(t *testing.T, stored grants.Grant, ref notify.MessageRef, notifier *captureNotifier, oldToken string, err error) {
	t.Helper()
	if err != nil || stored.Notification == nil || ref.MessageID <= 0 || len(notifier.messages) != 1 {
		t.Fatalf("reclaimed notify = grant:%+v ref:%+v messages:%d err:%v", stored, ref, len(notifier.messages), err)
	}
	if notifier.token == oldToken {
		t.Fatal("reclaimed notification reused the original decision token")
	}
}

func TestGrantNotificationFailureRetainsRequest(t *testing.T) {
	t.Parallel()
	server := newTestServerWithPolicyAndHandler(t, requestPRPolicy(t), func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
	})
	server.notifier = &captureNotifier{sendErr: errors.New("telegram unavailable")}

	response := createGrant(t, server, "failed-notification", "open the work PR")
	if response.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, body = %s, want bad gateway", response.Code, response.Body.String())
	}
	stored, err := server.grants.ListForClient("bob")
	if err != nil {
		t.Fatalf("ListForClient() error = %v", err)
	}
	if len(stored) != 1 || stored[0].Status != grants.StatusPending || !stored[0].NotificationDeliveryUnresolved {
		t.Fatalf("grants = %+v, want one unresolved pending grant", stored)
	}
}

func TestInvalidGrantNotificationReferenceCancelsRequest(t *testing.T) {
	t.Parallel()
	server := newTestServerWithPolicyAndHandler(t, requestPRPolicy(t), func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
	})
	server.notifier = &captureNotifier{invalidRef: true}

	response := createGrant(t, server, "invalid-notification", "open the work PR")
	if response.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, body = %s, want bad gateway", response.Code, response.Body.String())
	}
	stored, err := server.grants.ListForClient("bob")
	if err != nil {
		t.Fatalf("ListForClient() error = %v", err)
	}
	if len(stored) != 1 || stored[0].Status != grants.StatusCanceled {
		t.Fatalf("grants = %+v, want one canceled grant", stored)
	}
}

func TestGrantStatusDeliverySurvivesRestart(t *testing.T) {
	t.Parallel()
	stateDir := t.TempDir()
	cfg := config.Config{ClientID: "bob", SharedSecret: testSharedSecret, GitHubToken: testGitHubToken, GitHubTokenFile: "/protected/github-token", StateDir: stateDir}
	brokerPolicy := requestPRPolicy(t)
	server, err := New(cfg, brokerPolicy)
	if err != nil {
		t.Fatalf("New(first) error = %v", err)
	}
	createdNotifier := &captureNotifier{}
	server.notifier = createdNotifier
	created := createGrant(t, server, "restart-status", "open the work PR")
	if created.Code != http.StatusCreated {
		t.Fatalf("grant create status = %d, body = %s", created.Code, created.Body.String())
	}
	grant := decodeGrantResponse(t, created)
	approveGrant(t, server, grant.ID, createdNotifier.token)
	if err := server.Close(); err != nil {
		t.Fatalf("Close(first) error = %v", err)
	}

	restarted, err := New(cfg, brokerPolicy)
	if err != nil {
		t.Fatalf("New(restarted) error = %v", err)
	}
	t.Cleanup(func() { _ = restarted.Close() })
	statusNotifier := &captureNotifier{}
	restarted.notifier = statusNotifier
	restarted.deliverGrantStatusUpdates(context.Background())
	restarted.deliverGrantStatusUpdates(context.Background())
	if len(statusNotifier.statuses) != 1 || statusNotifier.statuses[0] != "Approved. Access is active." {
		t.Fatalf("statuses = %q, want one durable active update", statusNotifier.statuses)
	}
	stored, err := restarted.grants.Get(grant.ID)
	if err != nil {
		t.Fatalf("Get(%q) error = %v", grant.ID, err)
	}
	if stored.NotificationStatus != string(grants.StatusActive) {
		t.Fatalf("notification status = %q, want active", stored.NotificationStatus)
	}
}

func TestRetainedGrantUseUpdatesOperator(t *testing.T) {
	t.Parallel()
	server := newTestServer(t)
	notifier := &captureNotifier{}
	server.notifier = notifier
	result, _, err := server.requestGrant(grantsRequestForMainPush(t))
	if err != nil {
		t.Fatalf("Request() error = %v", err)
	}
	if _, err := server.grants.SetNotification(result.Grant.ID, notify.MessageRef{Kind: "test", ChatID: 1, MessageID: 9}); err != nil {
		t.Fatalf("SetNotification() error = %v", err)
	}
	if _, err := server.grants.Approve(result.Grant.ID, result.DecisionToken, "operator"); err != nil {
		t.Fatalf("Approve() error = %v", err)
	}
	if _, err := server.grants.ReserveUse(result.Grant.ID); err != nil {
		t.Fatalf("ReserveUse() error = %v", err)
	}
	if _, err := server.grants.RetainUse(result.Grant.ID); err != nil {
		t.Fatalf("RetainUse() error = %v", err)
	}

	server.deliverGrantStatusUpdates(context.Background())
	if len(notifier.statuses) != 1 || !strings.Contains(notifier.statuses[0], "ambiguous") {
		t.Fatalf("statuses = %q, want retained-use warning", notifier.statuses)
	}
}

func TestRetainingMultiUseGrantClosesRemainingAccess(t *testing.T) {
	t.Parallel()
	server := newTestServer(t)
	request := grantsRequestForMainPush(t)
	request.MaxUses = 3
	result, _, err := server.requestGrant(request)
	if err != nil {
		t.Fatalf("Request() error = %v", err)
	}
	if _, err := server.grants.Approve(result.Grant.ID, result.DecisionToken, "operator"); err != nil {
		t.Fatalf("Approve() error = %v", err)
	}
	reserved, err := server.grants.ReserveUse(result.Grant.ID)
	if err != nil {
		t.Fatalf("ReserveUse() error = %v", err)
	}
	if err := server.retainGrantUses([]grants.Grant{reserved}); err != nil {
		t.Fatalf("retainGrantUses() error = %v", err)
	}
	stored, err := server.grants.Get(result.Grant.ID)
	if err != nil {
		t.Fatalf("Get(%q) error = %v", result.Grant.ID, err)
	}
	if stored.Status != grants.StatusRevoked || !stored.ReservationRetained || stored.ReservedCount != 1 {
		t.Fatalf("grant = %+v, want revoked retained reservation", stored)
	}
	assertNoActiveGrants(t, server)
}

func TestPreDispatchFailureReleasesGrantUse(t *testing.T) {
	t.Parallel()
	server := newTestServer(t)
	result, _, err := server.requestGrant(grantsRequestForMainPush(t))
	if err != nil {
		t.Fatalf("Request() error = %v", err)
	}
	if _, err := server.grants.Approve(result.Grant.ID, result.DecisionToken, "operator"); err != nil {
		t.Fatalf("Approve() error = %v", err)
	}
	reserved, err := server.grants.ReserveUse(result.Grant.ID)
	if err != nil {
		t.Fatalf("ReserveUse() error = %v", err)
	}
	c := server.echo.NewContext(httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/", http.NoBody), httptest.NewRecorder())
	request := policy.Request{Client: "bob", Operation: policy.OperationGitPushForce, Target: policy.Target{Kind: "repo", Owner: "dutifuldev", Name: "gh-broker"}}
	decision := policy.Decision{GrantID: result.Grant.ID}
	if err := server.runAuthorizedBrokerRequest(c, request, decision, []grants.Grant{reserved}, func(echo.Context) error {
		return errors.New("credential lookup failed")
	}); err == nil {
		t.Fatal("runAuthorizedBrokerRequest() error = nil")
	}
	assertGrantUseState(t, server, result.Grant.ID, grants.StatusActive, 0, 0)
}

func TestGrantStatusDeliveryRetriesFailedEdit(t *testing.T) {
	t.Parallel()
	server := newTestServer(t)
	notifier := &captureNotifier{updateErr: errors.New("telegram unavailable")}
	server.notifier = notifier
	result, _, err := server.requestGrant(grantsRequestForMainPush(t))
	if err != nil {
		t.Fatalf("Request() error = %v", err)
	}
	if _, err := server.grants.SetNotification(result.Grant.ID, notify.MessageRef{Kind: "test", ChatID: 1, MessageID: 10}); err != nil {
		t.Fatalf("SetNotification() error = %v", err)
	}
	if _, err := server.grants.Approve(result.Grant.ID, result.DecisionToken, "operator"); err != nil {
		t.Fatalf("Approve() error = %v", err)
	}

	server.deliverGrantStatusUpdates(context.Background())
	notifier.updateErr = nil
	server.deliverGrantStatusUpdates(context.Background())
	server.deliverGrantStatusUpdates(context.Background())
	if len(notifier.statuses) != 1 || notifier.statuses[0] != "Approved. Access is active." {
		t.Fatalf("statuses = %q, want one successful retry", notifier.statuses)
	}
}

func TestGrantStatusText(t *testing.T) {
	t.Parallel()
	lifecycle := map[grants.Status]string{
		grants.StatusActive:   "Approved. Access is active.",
		grants.StatusDenied:   "Denied. Access was not granted.",
		grants.StatusExpired:  "Expired. Access is closed.",
		grants.StatusConsumed: "Used. Access is now closed.",
		grants.StatusRevoked:  "Revoked. Access is closed.",
		grants.StatusCanceled: "Canceled. Approval request is closed.",
		grants.StatusPending:  "Grant status changed.",
	}
	for status, want := range lifecycle {
		if got := grantStatusText(grants.StatusUpdate{Status: status}); got != want {
			t.Errorf("grantStatusText(%q) = %q, want %q", status, got, want)
		}
	}
	used := grants.Grant{Status: grants.StatusActive, MaxUses: 3, UsedCount: 1}
	if got := grantStatusText(grants.StatusUpdate{Kind: grants.StatusUpdateUsed, Grant: used}); got != "Used 1 of 3. 2 uses remain." {
		t.Errorf("used status = %q", got)
	}
	used = grants.Grant{Status: grants.StatusActive, MaxUses: 2, UsedCount: 1, ReservedCount: 1}
	if got := grantStatusText(grants.StatusUpdate{Kind: grants.StatusUpdateUsed, Grant: used}); got != "Used 1 of 2. 1 uses remain." {
		t.Errorf("reserved used status = %q", got)
	}
	used.ReservationRetained = true
	if got := grantStatusText(grants.StatusUpdate{Kind: grants.StatusUpdateUsed, Grant: used}); got != "Used. Access is now closed." {
		t.Errorf("retained used status = %q", got)
	}
	used.Status = grants.StatusConsumed
	if got := grantStatusText(grants.StatusUpdate{Kind: grants.StatusUpdateUsedExpired, Grant: used}); got != "Used. Access is now closed." {
		t.Errorf("closed used status = %q", got)
	}
	if got := grantStatusText(grants.StatusUpdate{Kind: grants.StatusUpdateRetainedReservation}); !strings.Contains(got, "ambiguous") {
		t.Errorf("retained status = %q", got)
	}
}

func TestReleaseReservedGrantUse(t *testing.T) {
	t.Parallel()
	server := newTestServer(t)
	result, _, err := server.requestGrant(grantsRequestForMainPush(t))
	if err != nil {
		t.Fatalf("Request() error = %v", err)
	}
	if _, err := server.grants.Approve(result.Grant.ID, result.DecisionToken, "operator"); err != nil {
		t.Fatalf("Approve() error = %v", err)
	}
	reserved, err := server.grants.ReserveUse(result.Grant.ID)
	if err != nil {
		t.Fatalf("ReserveUse() error = %v", err)
	}
	server.releaseGrantUses([]grants.Grant{reserved})
	assertGrantUseState(t, server, result.Grant.ID, grants.StatusActive, 0, 0)
}

func TestWaitForGrantNotificationHonorsCancellation(t *testing.T) {
	t.Parallel()
	server := newTestServer(t)
	result, _, err := server.requestGrant(grantsRequestForMainPush(t))
	if err != nil {
		t.Fatalf("Request() error = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := server.waitForGrantNotification(ctx, result.Grant.ID); err == nil {
		t.Fatal("waitForGrantNotification() error = nil, want cancellation")
	}
}

func TestWaitForGrantNotificationReturnsStoredReference(t *testing.T) {
	t.Parallel()
	server := newTestServer(t)
	result, _, err := server.requestGrant(grantsRequestForMainPush(t))
	if err != nil {
		t.Fatalf("Request() error = %v", err)
	}
	ref := notify.MessageRef{Kind: "test", ChatID: 1, MessageID: 11}
	if _, err := server.grants.SetNotification(result.Grant.ID, ref); err != nil {
		t.Fatalf("SetNotification() error = %v", err)
	}
	stored, got, err := server.waitForGrantNotificationFor(context.Background(), result.Grant.ID, time.Second, time.Millisecond)
	if err != nil || stored.ID != result.Grant.ID || got != ref {
		t.Fatalf("notified wait = grant:%+v ref:%+v err:%v", stored, got, err)
	}
}

func TestWaitForGrantNotificationReturnsTerminalGrant(t *testing.T) {
	t.Parallel()
	server := newTestServer(t)
	terminal, _, err := server.requestGrant(grantsRequestForMainPush(t))
	if err != nil {
		t.Fatalf("Request(terminal) error = %v", err)
	}
	if err := server.grants.Cancel(terminal.Grant.ID); err != nil {
		t.Fatalf("Cancel() error = %v", err)
	}
	stored, got, err := server.waitForGrantNotificationFor(context.Background(), terminal.Grant.ID, time.Second, time.Millisecond)
	if err != nil || stored.Status != grants.StatusCanceled || got.MessageID != 0 {
		t.Fatalf("terminal wait = grant:%+v ref:%+v err:%v", stored, got, err)
	}
}

func TestWaitForGrantNotificationRejectsMissingGrant(t *testing.T) {
	t.Parallel()
	server := newTestServer(t)
	if _, _, err := server.waitForGrantNotificationFor(context.Background(), "missing", time.Second, time.Millisecond); err == nil {
		t.Fatal("missing wait error = nil")
	}
}

func TestWaitForGrantNotificationTimesOut(t *testing.T) {
	t.Parallel()
	server := newTestServer(t)
	pending, _, err := server.requestGrant(grantsRequestForMainPush(t))
	if err != nil {
		t.Fatalf("Request(timeout) error = %v", err)
	}
	if _, _, err := server.waitForGrantNotificationFor(context.Background(), pending.Grant.ID, time.Millisecond, time.Millisecond); err == nil {
		t.Fatal("timeout wait error = nil")
	}
}

func TestGrantNotificationSweeperStopsWithContext(t *testing.T) {
	t.Parallel()
	server := newTestServer(t)
	server.notifier = &captureNotifier{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	server.runGrantNotificationSweeper(ctx)
}

func approveGrant(t *testing.T, server *Server, grantID string, token string) {
	t.Helper()
	decision := server.control.HandleDecision(context.Background(), notify.Decision{
		Action:        notify.ActionApprove,
		GrantID:       grantID,
		DecisionToken: token,
		OperatorID:    42,
		ChatID:        1,
		MessageID:     1,
		MessageText:   "approval",
	})
	if decision.Answer != "Grant approved" {
		t.Fatalf("telegram decision = %+v, want approval", decision)
	}
}

func createTelegramPullRequestGrant(t *testing.T, server *Server, state *fakeTelegramState) apiGrant {
	t.Helper()
	response := createGrant(t, server, "telegram-pr-1", "telegram approval")
	if response.Code != http.StatusCreated {
		t.Fatalf("grant create status = %d, body = %s", response.Code, response.Body.String())
	}
	if state.callbackData == "" {
		t.Fatal("fake Telegram did not capture callback data")
	}
	return decodeGrantResponse(t, response)
}

func pollTelegramApproval(t *testing.T, telegram *bktelegram.Client, server *Server) {
	t.Helper()
	nextOffset, err := telegram.PollOnce(context.Background(), 0, server.control.HandleDecision)
	if err != nil {
		t.Fatalf("PollOnce() error = %v", err)
	}
	if nextOffset != 2 {
		t.Fatalf("next offset = %d, want 2", nextOffset)
	}
}

func assertGrantActiveAfterTelegram(t *testing.T, server *Server, grantID string, state *fakeTelegramState) {
	t.Helper()
	get := do(t, server, http.MethodGet, "/api/grants/"+grantID, bearerAuth())
	if get.Code != http.StatusOK || !strings.Contains(get.Body.String(), `"status":"active"`) {
		t.Fatalf("grant get after telegram = %d %s, want active", get.Code, get.Body.String())
	}
	if !state.answered {
		t.Fatal("fake Telegram callback was not answered")
	}
	if !strings.Contains(strings.Join(state.edits, "\n"), "Approved. Access is active.") {
		t.Fatalf("telegram edits = %q, want approval status edit", state.edits)
	}
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
		Target:          policy.CoreTarget(policy.Target{Kind: "repo", Owner: "dutifuldev", Name: "gh-broker"}),
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
		`{"client_request_id":%q,"operation":"git.push.force","target":{"kind":"repo","owner":"dutifuldev","name":"gh-broker"},"attrs":{"ref":"refs/heads/bob/work"},"reason":%q,"minutes":5}`,
		requestID,
		reason,
	)
	return doWithBody(t, server, http.MethodPost, "/api/grants", bearerAuth(), []byte(body))
}

func TestOperatorInboxSurvivesTelegramNotificationFailure(t *testing.T) {
	server := newTestServerWithPolicyAndHandler(t, requestPRPolicy(t), func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
	})
	server.operatorConfigured = true
	server.notifier = &captureNotifier{sendErr: errors.New("notify failed")}
	response := createGrant(t, server, "operator-inbox-notify-failed", "open the work PR")
	if response.Code != http.StatusCreated {
		t.Fatalf("grant create status = %d, body=%s", response.Code, response.Body.String())
	}
	created := decodeGrantResponse(t, response)
	stored, err := server.grants.Get(created.ID)
	if err != nil || stored.Status != grants.StatusPending || !stored.NotificationDeliveryUnresolved {
		t.Fatalf("stored grant = %+v, err=%v", stored, err)
	}
}

func decodeGrantResponse(t *testing.T, response *httptest.ResponseRecorder) apiGrant {
	t.Helper()
	var payload struct {
		Grant apiGrant `json:"grant"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode grant response: %v", err)
	}
	return payload.Grant
}

func TestGrantCreateRejectsInvalidRequests(t *testing.T) {
	t.Parallel()
	server := newTestServerWithPolicyAndHandler(t, requestPRPolicy(t), func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
	})
	noNotifier := createGrant(t, server, "missing-notifier", "reason")
	if noNotifier.Code != http.StatusServiceUnavailable {
		t.Fatalf("no notifier status = %d, want service unavailable", noNotifier.Code)
	}
	server.notifier = &captureNotifier{}
	cases := map[string]struct {
		body string
		want int
	}{
		"bad json":               {body: `{`, want: http.StatusBadRequest},
		"missing reason":         {body: `{"client_request_id":"bad","operation":"pull_request.create","target":{"kind":"repo","owner":"dutifuldev","name":"gh-broker"},"attrs":{"ref":"refs/heads/bob/work","head_ref":"refs/heads/bob/work","base_ref":"refs/heads/main"}}`, want: http.StatusBadRequest},
		"non protocol operation": {body: `{"client_request_id":"bad","operation":"pull_request.create","target":{"kind":"repo","owner":"dutifuldev","name":"gh-broker"},"attrs":{"ref":"refs/heads/bob/work","head_ref":"refs/heads/bob/work","base_ref":"refs/heads/main"},"reason":"open PR"}`, want: http.StatusBadRequest},
		"not requestable":        {body: `{"client_request_id":"bad","operation":"git.fetch","target":{"kind":"repo","owner":"dutifuldev","name":"gh-broker"},"reason":"fetch"}`, want: http.StatusBadRequest},
		"too long":               {body: `{"client_request_id":"bad","operation":"pull_request.create","target":{"kind":"repo","owner":"dutifuldev","name":"gh-broker"},"attrs":{"ref":"refs/heads/bob/work","head_ref":"refs/heads/bob/work","base_ref":"refs/heads/main"},"reason":"too long","minutes":99}`, want: http.StatusBadRequest},
	}
	for name, tc := range cases {
		response := doWithBody(t, server, http.MethodPost, "/api/grants", bearerAuth(), []byte(tc.body))
		if response.Code != tc.want {
			t.Fatalf("%s status = %d, body = %s, want %d", name, response.Code, response.Body.String(), tc.want)
		}
	}
}

func TestDecodeGrantCreateDirect(t *testing.T) {
	t.Parallel()
	server := newTestServer(t)
	valid := newBodyContext(t, server, `{"client_request_id":"request-1","operation":"pull_request.create","target":{"kind":"repo","owner":"dutifuldev","name":"gh-broker"},"attrs":{"ref":"refs/heads/bob/work"},"reason":"open PR"}`)
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
	body := `{"client_request_id":"request-1","operation":"git.push.force","target":{"kind":"repo","owner":"dutifuldev","name":"gh-broker"},"attrs":{"ref":"refs/heads/bob/work"},"reason":"force push work branch","minutes":5}`
	noNotifier := newBodyContext(t, server, body)
	if _, err := server.planGrantCreate(noNotifier); err == nil {
		t.Fatal("planGrantCreate(no notifier) error = nil, want service unavailable")
	}
	server.notifier = &captureNotifier{}
	plan, err := server.planGrantCreate(newBodyContext(t, server, body))
	if err != nil {
		t.Fatalf("planGrantCreate() error = %v", err)
	}
	if plan.request.Client != "bob" || plan.maxUses != 1 || plan.duration != 5*time.Minute {
		t.Fatalf("plan = %+v, want requestable bob grant", plan)
	}
	notRequestable := `{"client_request_id":"request-2","operation":"git.fetch","target":{"kind":"repo","owner":"dutifuldev","name":"gh-broker"},"reason":"fetch"}`
	if _, err := server.planGrantCreate(newBodyContext(t, server, notRequestable)); err == nil {
		t.Fatal("planGrantCreate(not requestable) error = nil, want forbidden")
	}
}

func TestTelegramDecisionDenyAndErrors(t *testing.T) {
	t.Parallel()
	server := newTestServerWithPolicyAndHandler(t, requestPRPolicy(t), func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
	})
	result, _, err := server.requestGrant(grants.Request{
		Client:          "bob",
		ClientRequestID: "deny-pr",
		Operation:       string(policy.Operation("pull_request.create")),
		Target:          policy.CoreTarget(policy.Target{Kind: "repo", Owner: "dutifuldev", Name: "gh-broker"}),
		Attrs:           map[string][]string{"ref": {"refs/heads/bob/work"}, "head_ref": {"refs/heads/bob/work"}, "base_ref": {"refs/heads/main"}},
		Reason:          "deny test",
		Duration:        5 * time.Minute,
		PendingTimeout:  time.Minute,
		MaxUses:         1,
	})
	if err != nil {
		t.Fatalf("Request() error = %v", err)
	}
	denied := server.control.HandleDecision(context.Background(), notify.Decision{
		Action:        notify.ActionDeny,
		GrantID:       result.Grant.ID,
		DecisionToken: result.DecisionToken,
		OperatorTag:   "operator",
		ChatID:        1,
		MessageID:     1,
		MessageText:   "approval",
	})
	if denied.Answer != "Grant denied" {
		t.Fatalf("deny decision = %+v, want denied", denied)
	}
	replay := server.control.HandleDecision(context.Background(), notify.Decision{
		Action:        notify.ActionApprove,
		GrantID:       result.Grant.ID,
		DecisionToken: result.DecisionToken,
		ChatID:        1,
		MessageID:     1,
		MessageText:   "approval",
	})
	if replay.Answer != "Grant is no longer pending" {
		t.Fatalf("replay decision = %+v, want no longer pending", replay)
	}
}

func TestDenyTelegramGrantDirect(t *testing.T) {
	t.Parallel()
	server := newTestServerWithPolicyAndHandler(t, requestPRPolicy(t), func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
	})
	result, _, err := server.requestGrant(grants.Request{
		Client:          "bob",
		ClientRequestID: "deny-direct",
		Operation:       string(policy.Operation("pull_request.create")),
		Target:          policy.CoreTarget(policy.Target{Kind: "repo", Owner: "dutifuldev", Name: "gh-broker"}),
		Attrs:           map[string][]string{"ref": {"refs/heads/bob/work"}, "head_ref": {"refs/heads/bob/work"}, "base_ref": {"refs/heads/main"}},
		Reason:          "deny direct",
		Duration:        5 * time.Minute,
		PendingTimeout:  time.Minute,
		MaxUses:         1,
	})
	if err != nil {
		t.Fatalf("Request() error = %v", err)
	}
	decision := server.control.HandleDecision(context.Background(), notify.Decision{
		Action:        notify.ActionDeny,
		GrantID:       result.Grant.ID,
		DecisionToken: result.DecisionToken,
		OperatorTag:   "operator",
		ChatID:        1,
		MessageID:     1,
		MessageText:   "approval",
	})
	if decision.Answer != "Grant denied" || decision.Retry {
		t.Fatalf("handleTelegramDecision() = %+v, want denied status", decision)
	}
}

func TestAPIGrantFromStoreIncludesSafeStatusFields(t *testing.T) {
	t.Parallel()
	expiresAt := time.Date(2026, 7, 9, 12, 0, 0, 0, time.FixedZone("test", 3600))
	api := apiGrantFromStore(grants.Grant{
		ID:               "grant-1",
		Status:           grants.StatusActive,
		Operation:        string(policy.OperationGitPushForce),
		Target:           policy.CoreTarget(policy.Target{Kind: "repo", Owner: "dutifuldev", Name: "gh-broker"}),
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
	if api.Target.Owner != "dutifuldev" || api.Target.Name != "gh-broker" || api.ClientRequestID != "request-1" {
		t.Fatalf("api grant = %+v, want target and request id", api)
	}
}

func TestAPITarget(t *testing.T) {
	t.Parallel()
	target := apiTarget(policy.CoreTarget(policy.Target{Kind: "repo", Owner: "osolmaz", Name: "brokerkit"}))
	if target.Owner != "osolmaz" || target.Name != "brokerkit" || target.Kind != "repo" {
		t.Fatalf("apiTarget() = %+v, want repo target", target)
	}
}

func TestLegacyJSONProxyRoutesAreRemoved(t *testing.T) {
	server := newTestServer(t)
	for _, path := range []string{"/api/repos", "/api/repos/osolmaz/brokerkit/contents/README.md"} {
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
	server.auditWriter = bkaudit.New(&logs)
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
	server.auditWriter = bkaudit.New(&logs)
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
	server.auditWriter = bkaudit.New(&logs)
	response := doWithBody(
		t,
		server,
		http.MethodPost,
		"/dutifuldev/gh-broker.git/git-receive-pack",
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
		TelegramBotToken:    "bot-token",
		TelegramChatID:      123,
		GitHubHTTPTimeout:   7 * time.Second,
		MaxReceivePackBytes: 99,
	}, testBrokerPolicy(t))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	t.Cleanup(func() { _ = server.Close() })
	if server.githubClient.Timeout != 7*time.Second {
		t.Fatalf("github timeout = %s, want 7s", server.githubClient.Timeout)
	}
	if server.maxReceivePackBytes != 99 {
		t.Fatalf("max receive-pack bytes = %d, want 99", server.maxReceivePackBytes)
	}
	if server.notifier == nil || server.telegram == nil {
		t.Fatal("telegram notifier was not configured")
	}
}

func TestGitProxyUsesServerSideCredential(t *testing.T) {
	t.Parallel()
	var gotAuthorization string
	server := newTestServerWithHandler(t, func(w http.ResponseWriter, r *http.Request) {
		gotAuthorization = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	})
	response := do(t, server, http.MethodGet, "/dutifuldev/gh-broker.git/info/refs?service=git-upload-pack", bearerAuth())
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
		case "/repos/dutifuldev/gh-broker/installation":
			writeRawJSON(w, `{"id":42}`)
		case "/app/installations/42/access_tokens":
			tokenMints++
			if tokenMints == 1 {
				writeRawJSON(w, `{"token":"ghs_bootstrap","expires_at":"2099-07-09T18:00:00Z"}`)
			} else {
				writeRawJSON(w, `{"token":"ghs_repo_token","expires_at":"2099-07-09T18:00:00Z"}`)
			}
		case "/repos/dutifuldev/gh-broker":
			writeRawJSON(w, `{"id":99,"name":"gh-broker","owner":{"login":"dutifuldev"}}`)
		case "/installation/token":
			w.WriteHeader(http.StatusNoContent)
		case "/dutifuldev/gh-broker.git/info/refs":
			gotAuthorization = r.Header.Get("Authorization")
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected upstream path %s", r.URL.Path)
		}
	})
	server.githubCredentials = newTestGitHubAppManager(t, server)
	response := do(t, server, http.MethodGet, "/dutifuldev/gh-broker.git/info/refs?service=git-upload-pack", bearerAuth())
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	if gotAuthorization != githubGitAuthorization("ghs_repo_token") {
		t.Fatalf("authorization = %q, want GitHub App installation git auth", gotAuthorization)
	}
}

func TestReceivePackUsesWriteAndInspectionInstallationTokens(t *testing.T) {
	t.Parallel()
	var tokenRequests []string
	var gitAuthorization string
	server := newTestServerWithHandler(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/dutifuldev/gh-broker/installation":
			writeRawJSON(w, `{"id":42}`)
		case "/app/installations/42/access_tokens":
			body, _ := io.ReadAll(r.Body)
			tokenRequests = append(tokenRequests, string(body))
			writeRawJSON(w, fmt.Sprintf(`{"token":"ghs_token_%d","expires_at":"2099-07-09T18:00:00Z"}`, len(tokenRequests)))
		case "/repos/dutifuldev/gh-broker":
			writeRawJSON(w, `{"id":99,"name":"gh-broker","default_branch":"main","owner":{"login":"dutifuldev"}}`)
		case "/installation/token":
			w.WriteHeader(http.StatusNoContent)
		case "/repos/dutifuldev/gh-broker/rules/branches/bob/work":
			writeRawJSON(w, `[]`)
		case "/repos/dutifuldev/gh-broker/branches/bob/work/protection":
			http.NotFound(w, r)
		case "/dutifuldev/gh-broker.git/git-receive-pack":
			gitAuthorization = r.Header.Get("Authorization")
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected upstream path %s", r.URL.Path)
		}
	})
	server.githubCredentials = newTestGitHubAppManager(t, server)
	response := doWithBody(t, server, http.MethodPost, "/dutifuldev/gh-broker.git/git-receive-pack", bearerAuth(),
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
		"/dutifuldev/gh-broker.git/info/refs?service=git-upload-pack",
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
		"/dutifuldev/gh-broker.git/info/refs?service=git-upload-pack",
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
	response := do(t, server, http.MethodGet, "/dutifuldev/gh-broker.git/info/refs?service=bad-service", bearerAuth())
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

func newTestServerWithStateDir(t *testing.T, stateDir string) *Server {
	t.Helper()
	return newTestServerWithPolicyAndHandlerInStateDir(t, testBrokerPolicy(t), func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("proxied"))
	}, stateDir)
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
			Targets:    []policy.Target{{Kind: "repo", Owner: "dutifuldev", Name: "gh-broker"}},
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
			Targets:    []policy.Target{{Kind: "repo", Owner: "dutifuldev", Name: "gh-broker"}},
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
			Targets:    []policy.Target{{Kind: "repo", Owner: "dutifuldev", Name: "gh-broker"}},
			Attrs:      map[string][]string{"refs": {"refs/heads/main"}},
		},
		{
			ID:         "request-main",
			Effect:     policy.EffectRequest,
			Clients:    []string{"bob"},
			Operations: []policy.Operation{policy.OperationGitPushForce},
			Targets:    []policy.Target{{Kind: "repo", Owner: "dutifuldev", Name: "gh-broker"}},
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
		Target:          policy.CoreTarget(policy.Target{Kind: "repo", Owner: "dutifuldev", Name: "gh-broker"}),
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
			Targets:    []policy.Target{{Kind: "repo", Owner: "dutifuldev", Name: "gh-broker"}},
			Attrs:      map[string][]string{"refs": {"refs/heads/main"}},
		},
	}})
	if err != nil {
		t.Fatalf("policy.New(requestMainPushPolicy) error = %v", err)
	}
	return brokerPolicy
}

func approveMainPushGrant(t *testing.T, server *Server) string {
	t.Helper()
	result, _, err := server.requestGrant(grantsRequestForMainPush(t))
	if err != nil {
		t.Fatalf("Request() error = %v", err)
	}
	if _, err := server.grants.Approve(result.Grant.ID, result.DecisionToken, "operator"); err != nil {
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

func assertNoActiveGrants(t *testing.T, server *Server) {
	t.Helper()
	active, err := server.grants.ActivePolicyGrants()
	if err != nil {
		t.Fatalf("ActivePolicyGrants() error = %v", err)
	}
	if len(active) != 0 {
		t.Fatalf("active grants = %+v, want none", active)
	}
}

type captureNotifier struct {
	messages   []notify.ApprovalMessage
	statuses   []string
	token      string
	sendErr    error
	updateErr  error
	invalidRef bool
}

func (n *captureNotifier) SendApproval(_ context.Context, msg notify.ApprovalMessage) (notify.MessageRef, error) {
	if n.sendErr != nil {
		return notify.MessageRef{}, n.sendErr
	}
	n.token = msg.DecisionToken
	stored := msg
	stored.DecisionToken = ""
	n.messages = append(n.messages, stored)
	if n.invalidRef {
		return notify.MessageRef{}, nil
	}
	return notify.MessageRef{Kind: "test", ChatID: 1, MessageID: len(n.messages), Text: msg.Text}, nil
}

func (n *captureNotifier) UpdateStatus(_ context.Context, _ notify.MessageRef, status string) error {
	if n.updateErr != nil {
		return n.updateErr
	}
	n.statuses = append(n.statuses, status)
	return nil
}

type fakeTelegramState struct {
	chatID       int64
	messageID    int
	callbackData string
	messageText  string
	updateSent   bool
	answered     bool
	edits        []string
}

func fakeTelegramHandler(t *testing.T, state *fakeTelegramState) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/sendMessage"):
			payload := decodeJSONMap(t, r)
			state.messageText, _ = payload["text"].(string)
			state.callbackData = firstCallbackData(t, payload)
			writeTelegramJSON(t, w, map[string]any{
				"ok": true,
				"result": map[string]any{
					"message_id": state.messageID,
					"chat":       map[string]any{"id": state.chatID},
				},
			})
		case strings.HasSuffix(r.URL.Path, "/getUpdates"):
			result := []map[string]any{}
			if state.callbackData != "" && !state.updateSent {
				state.updateSent = true
				result = append(result, map[string]any{
					"update_id": 1,
					"callback_query": map[string]any{
						"id":   "callback-1",
						"data": state.callbackData,
						"from": map[string]any{"id": 42, "username": "operator"},
						"message": map[string]any{
							"message_id": state.messageID,
							"text":       state.messageText,
							"chat":       map[string]any{"id": state.chatID},
						},
					},
				})
			}
			writeTelegramJSON(t, w, map[string]any{"ok": true, "result": result})
		case strings.HasSuffix(r.URL.Path, "/answerCallbackQuery"):
			state.answered = true
			writeTelegramJSON(t, w, map[string]any{"ok": true, "result": true})
		case strings.HasSuffix(r.URL.Path, "/editMessageText"):
			payload := decodeJSONMap(t, r)
			if text, _ := payload["text"].(string); text != "" {
				state.edits = append(state.edits, text)
			}
			writeTelegramJSON(t, w, map[string]any{"ok": true, "result": true})
		default:
			t.Fatalf("unexpected Telegram path %s", r.URL.Path)
		}
	}
}

func decodeJSONMap(t *testing.T, r *http.Request) map[string]any {
	t.Helper()
	var payload map[string]any
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		t.Fatalf("decode Telegram payload: %v", err)
	}
	return payload
}

func firstCallbackData(t *testing.T, payload map[string]any) string {
	t.Helper()
	replyMarkup, ok := payload["reply_markup"].(map[string]any)
	if !ok {
		t.Fatalf("reply_markup missing from payload: %+v", payload)
	}
	keyboard, ok := replyMarkup["inline_keyboard"].([]any)
	if !ok || len(keyboard) == 0 {
		t.Fatalf("inline_keyboard missing from payload: %+v", payload)
	}
	row, ok := keyboard[0].([]any)
	if !ok || len(row) == 0 {
		t.Fatalf("inline_keyboard row missing from payload: %+v", payload)
	}
	button, ok := row[0].(map[string]any)
	if !ok {
		t.Fatalf("button missing from payload: %+v", payload)
	}
	callbackData, _ := button["callback_data"].(string)
	return callbackData
}

func writeTelegramJSON(t *testing.T, w http.ResponseWriter, payload map[string]any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		t.Fatalf("write Telegram response: %v", err)
	}
}

func testBrokerPolicy(t *testing.T) *policy.Policy {
	t.Helper()
	brokerPolicy, err := policy.New(policy.Scope{Rules: []policy.Rule{
		{
			ID:         "deny-dangerous",
			Effect:     policy.EffectDeny,
			Clients:    []string{"*"},
			Operations: []policy.Operation{policy.OperationGitPushForce, policy.OperationGitRefDelete},
			Targets:    []policy.Target{{Kind: "repo", Owner: "dutifuldev", Name: "gh-broker"}},
			Attrs:      map[string][]string{"refs": {"refs/heads/main"}},
		},
		{
			ID:         "bob-repo-read",
			Effect:     policy.EffectAllow,
			Clients:    []string{"bob"},
			Operations: []policy.Operation{policy.OperationGitFetch, policy.Operation("repo.metadata.read")},
			Targets: []policy.Target{
				{Kind: "repo", Owner: "dutifuldev", Name: "*"},
				{Kind: "repo", Owner: "openclaw", Name: "openclaw"},
			},
		},
		{
			ID:         "bob-contents-read",
			Effect:     policy.EffectAllow,
			Clients:    []string{"bob"},
			Operations: []policy.Operation{policy.Operation("repo.contents.read")},
			Targets: []policy.Target{
				{Kind: "repo", Owner: "dutifuldev", Name: "*"},
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
			Operations: []policy.Operation{policy.OperationGitPushAdvertise},
			Targets:    []policy.Target{{Kind: "repo", Owner: "dutifuldev", Name: "*"}},
		},
		{
			ID:         "bob-push-branches",
			Effect:     policy.EffectAllow,
			Clients:    []string{"bob"},
			Operations: []policy.Operation{policy.OperationGitPushBranchCreate, policy.OperationGitPushForce},
			Targets:    []policy.Target{{Kind: "repo", Owner: "dutifuldev", Name: "*"}},
			Attrs:      map[string][]string{"refs": {"refs/heads/bob/*", "refs/heads/agent/*"}},
		},
		{
			ID:         "bob-pr-create",
			Effect:     policy.EffectAllow,
			Clients:    []string{"bob"},
			Operations: []policy.Operation{policy.Operation("pull_request.create")},
			Targets:    []policy.Target{{Kind: "repo", Owner: "dutifuldev", Name: "*"}},
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
			Targets:    []policy.Target{{Kind: "repo", Owner: "dutifuldev", Name: "direct-main"}},
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
	context.SetParamValues("dutifuldev", "gh-broker.git")
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
