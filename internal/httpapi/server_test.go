package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/osolmaz/brokerkit/grants"
	"github.com/osolmaz/brokerkit/notify"
	bktelegram "github.com/osolmaz/brokerkit/notify/telegram"
	"github.com/osolmaz/gh-broker/internal/config"
	"github.com/osolmaz/gh-broker/internal/policy"
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

func TestPullRequestRouteValidatesPolicyAndUsesGitHubShape(t *testing.T) {
	t.Parallel()
	var gotPath string
	server := newTestServerWithHandler(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusCreated)
	})
	response := doWithBody(
		t,
		server,
		http.MethodPost,
		"/api/repos/dutifuldev/gh-broker/pulls",
		bearerAuth(),
		[]byte(`{"title":"work","head":"bob/work","base":"main","body":"ready"}`),
	)
	if response.Code != http.StatusCreated {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	if gotPath != "/repos/dutifuldev/gh-broker/pulls" {
		t.Fatalf("upstream path = %q, want GitHub pulls path", gotPath)
	}
}

func TestPullRequestRejectsForkHeadSyntax(t *testing.T) {
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
		[]byte(`{"title":"work","head":"evil:bob/work","base":"main"}`),
	)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	if upstreamCalls != 0 {
		t.Fatalf("upstream calls = %d, want 0", upstreamCalls)
	}
}

func TestPullRequestRejectsLongTitle(t *testing.T) {
	t.Parallel()
	server := newTestServer(t)
	body := []byte(`{"title":"` + strings.Repeat("a", 257) + `","head":"bob/work","base":"main"}`)
	response := doWithBody(t, server, http.MethodPost, "/api/repos/dutifuldev/gh-broker/pulls", bearerAuth(), body)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
}

func TestPullRequestPolicyDenialDoesNotCallUpstream(t *testing.T) {
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
		"/api/repos/dutifuldev/gh-broker/pulls",
		bearerAuth(),
		[]byte(`{"title":"work","head":"bob/work","base":"develop"}`),
	)
	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	if upstreamCalls != 0 {
		t.Fatalf("upstream calls = %d, want 0", upstreamCalls)
	}
}

func TestGrantRequestApproveAndUsePullRequestGrant(t *testing.T) {
	t.Parallel()
	var upstreamCalls int
	server := newTestServerWithPolicyAndHandler(t, requestPRPolicy(t), func(w http.ResponseWriter, _ *http.Request) {
		upstreamCalls++
		w.WriteHeader(http.StatusCreated)
	})
	notifier := &captureNotifier{}
	server.notifier = notifier

	assertPullRequestNeedsGrant(t, server, "work")
	grant := createPullRequestGrant(t, server, notifier, "pr-1")
	approveGrant(t, server, grant.ID, notifier.token)
	assertGrantBackedPullRequestConsumed(t, server, grant.ID, &upstreamCalls)
}

func TestDenyOverridesActiveGrant(t *testing.T) {
	t.Parallel()
	var upstreamCalls int
	server := newTestServerWithPolicyAndHandler(t, denyMainWithRequestPolicy(t), func(w http.ResponseWriter, _ *http.Request) {
		upstreamCalls++
		w.WriteHeader(http.StatusOK)
	})
	result, _, err := server.grants.Request(grantsRequestForMainPush(t))
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
	pollTelegramApproval(t, telegram, server)
	assertGrantActiveAfterTelegram(t, server, created.ID, telegramState)
}

func assertPullRequestNeedsGrant(t *testing.T, server *Server, title string) {
	t.Helper()
	response := createPullRequest(t, server, title)
	if response.Code != http.StatusConflict {
		t.Fatalf("pull request status = %d, body = %s, want grant required", response.Code, response.Body.String())
	}
}

func createPullRequestGrant(t *testing.T, server *Server, notifier *captureNotifier, requestID string) apiGrant {
	t.Helper()
	response := createGrant(t, server, requestID, "open the work PR")
	if response.Code != http.StatusCreated {
		t.Fatalf("grant create status = %d, body = %s", response.Code, response.Body.String())
	}
	if strings.Contains(response.Body.String(), notifier.token) || strings.Contains(response.Body.String(), "decision_token") {
		t.Fatalf("grant create response leaked decision token: %s", response.Body.String())
	}
	if len(notifier.messages) != 1 || notifier.token == "" {
		t.Fatalf("notifier messages = %+v token=%q, want one approval with token", notifier.messages, notifier.token)
	}
	return decodeGrantResponse(t, response)
}

func approveGrant(t *testing.T, server *Server, grantID string, token string) {
	t.Helper()
	decision := server.handleTelegramDecision(context.Background(), notify.Decision{
		Action:        notify.ActionApprove,
		GrantID:       grantID,
		DecisionToken: token,
		OperatorID:    42,
	})
	if decision.Answer != "Grant approved" {
		t.Fatalf("telegram decision = %+v, want approval", decision)
	}
}

func assertGrantBackedPullRequestConsumed(t *testing.T, server *Server, grantID string, upstreamCalls *int) {
	t.Helper()
	after := createPullRequest(t, server, "work")
	if after.Code != http.StatusCreated {
		t.Fatalf("after approval status = %d, body = %s", after.Code, after.Body.String())
	}
	if *upstreamCalls != 1 {
		t.Fatalf("upstream calls = %d, want one grant-backed request", *upstreamCalls)
	}
	list := do(t, server, http.MethodGet, "/api/grants", bearerAuth())
	if list.Code != http.StatusOK || !strings.Contains(list.Body.String(), grantID) || strings.Contains(list.Body.String(), "decision_token") {
		t.Fatalf("grant list response = %d %s, want grant without decision token", list.Code, list.Body.String())
	}
	get := do(t, server, http.MethodGet, "/api/grants/"+grantID, bearerAuth())
	if get.Code != http.StatusOK || !strings.Contains(get.Body.String(), `"status":"consumed"`) {
		t.Fatalf("grant get after use = %d %s, want consumed", get.Code, get.Body.String())
	}
	assertPullRequestNeedsGrant(t, server, "again")
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
	nextOffset, err := telegram.PollOnce(context.Background(), 0, server.handleTelegramDecision)
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

func createPullRequest(t *testing.T, server *Server, title string) *httptest.ResponseRecorder {
	t.Helper()
	body := fmt.Sprintf(`{"title":%q,"head":"bob/work","base":"main"}`, title)
	return doWithBody(t, server, http.MethodPost, "/api/repos/dutifuldev/gh-broker/pulls", bearerAuth(), []byte(body))
}

func createGrant(t *testing.T, server *Server, requestID string, reason string) *httptest.ResponseRecorder {
	t.Helper()
	body := fmt.Sprintf(
		`{"client_request_id":%q,"operation":"pr.create","target":{"kind":"repo","owner":"dutifuldev","name":"gh-broker"},"attrs":{"ref":"refs/heads/bob/work","head_ref":"refs/heads/bob/work","base_ref":"refs/heads/main"},"reason":%q,"minutes":5}`,
		requestID,
		reason,
	)
	return doWithBody(t, server, http.MethodPost, "/api/grants", bearerAuth(), []byte(body))
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
		"bad json":        {body: `{`, want: http.StatusBadRequest},
		"missing reason":  {body: `{"client_request_id":"bad","operation":"pr.create","target":{"kind":"repo","owner":"dutifuldev","name":"gh-broker"},"attrs":{"ref":"refs/heads/bob/work","head_ref":"refs/heads/bob/work","base_ref":"refs/heads/main"}}`, want: http.StatusBadRequest},
		"not requestable": {body: `{"client_request_id":"bad","operation":"git.fetch","target":{"kind":"repo","owner":"dutifuldev","name":"gh-broker"},"reason":"fetch"}`, want: http.StatusForbidden},
		"too long":        {body: `{"client_request_id":"bad","operation":"pr.create","target":{"kind":"repo","owner":"dutifuldev","name":"gh-broker"},"attrs":{"ref":"refs/heads/bob/work","head_ref":"refs/heads/bob/work","base_ref":"refs/heads/main"},"reason":"too long","minutes":99}`, want: http.StatusBadRequest},
	}
	for name, tc := range cases {
		response := doWithBody(t, server, http.MethodPost, "/api/grants", bearerAuth(), []byte(tc.body))
		if response.Code != tc.want {
			t.Fatalf("%s status = %d, body = %s, want %d", name, response.Code, response.Body.String(), tc.want)
		}
	}
}

func TestTelegramDecisionDenyAndErrors(t *testing.T) {
	t.Parallel()
	server := newTestServerWithPolicyAndHandler(t, requestPRPolicy(t), func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
	})
	result, _, err := server.grants.Request(grants.Request{
		Client:          "bob",
		ClientRequestID: "deny-pr",
		Operation:       string(policy.OperationPullRequestCreate),
		Target:          policy.CoreTarget(policy.Target{Kind: "repo", Owner: "dutifuldev", Name: "gh-broker"}),
		Attrs:           map[string]string{"ref": "refs/heads/bob/work", "head_ref": "refs/heads/bob/work", "base_ref": "refs/heads/main"},
		Reason:          "deny test",
		Duration:        5 * time.Minute,
		PendingTimeout:  time.Minute,
		MaxUses:         1,
	})
	if err != nil {
		t.Fatalf("Request() error = %v", err)
	}
	denied := server.handleTelegramDecision(context.Background(), notify.Decision{
		Action:        notify.ActionDeny,
		GrantID:       result.Grant.ID,
		DecisionToken: result.DecisionToken,
		OperatorTag:   "operator",
	})
	if denied.Answer != "Grant denied" {
		t.Fatalf("deny decision = %+v, want denied", denied)
	}
	replay := server.handleTelegramDecision(context.Background(), notify.Decision{
		Action:        notify.ActionApprove,
		GrantID:       result.Grant.ID,
		DecisionToken: result.DecisionToken,
	})
	if replay.Answer != "Grant is no longer pending" {
		t.Fatalf("replay decision = %+v, want no longer pending", replay)
	}
	if got := grantDecisionAnswer(grants.ErrInvalidDecisionToken); got != "Grant decision token did not match" {
		t.Fatalf("invalid token answer = %q", got)
	}
	if got := grantDecisionAnswer(grants.ErrNotFound); got != "Grant not found" {
		t.Fatalf("not found answer = %q", got)
	}
	if got := grantDecisionAnswer(context.Canceled); got != "Grant decision failed" {
		t.Fatalf("generic answer = %q", got)
	}
}

func TestPullRequestRejectsMalformedBody(t *testing.T) {
	t.Parallel()
	server := newTestServer(t)
	response := doWithBody(
		t,
		server,
		http.MethodPost,
		"/api/repos/dutifuldev/gh-broker/pulls",
		bearerAuth(),
		[]byte(`{"head":"bad branch","base":"main"}`),
	)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
}

func TestListReposFiltersByPolicy(t *testing.T) {
	t.Parallel()
	var gotPath string
	server := newTestServerWithHandler(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		if r.URL.Query().Get("per_page") != "100" {
			t.Fatalf("per_page = %q, want 100", r.URL.Query().Get("per_page"))
		}
		_, _ = w.Write([]byte(`[
			{"name":"gh-broker","full_name":"dutifuldev/gh-broker","owner":{"login":"dutifuldev"}},
			{"name":"repo","full_name":"outside/repo","owner":{"login":"outside"}}
		]`))
	})
	response := do(t, server, http.MethodGet, "/api/repos", bearerAuth())
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	if gotPath != "/user/repos" {
		t.Fatalf("upstream path = %q, want /user/repos", gotPath)
	}
	var repos []struct {
		FullName string `json:"full_name"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &repos); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if len(repos) != 1 || repos[0].FullName != "dutifuldev/gh-broker" {
		t.Fatalf("repos = %+v, want only policy-allowed repo", repos)
	}
}

func TestListReposUsesInstallationEndpointForInstallationToken(t *testing.T) {
	t.Parallel()
	var gotPath string
	server := newTestServerWithHandler(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_, _ = w.Write([]byte(`{"repositories":[
			{"name":"gh-broker","full_name":"dutifuldev/gh-broker","owner":{"login":"dutifuldev"}}
		]}`))
	})
	server.githubToken = "ghs_installation_token"
	response := do(t, server, http.MethodGet, "/api/repos", bearerAuth())
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	if gotPath != "/installation/repositories" {
		t.Fatalf("upstream path = %q, want installation repositories endpoint", gotPath)
	}
}

func TestListReposFallsBackBetweenUserAndInstallationEndpoints(t *testing.T) {
	t.Parallel()
	var gotPaths []string
	server := newTestServerWithHandler(t, func(w http.ResponseWriter, r *http.Request) {
		gotPaths = append(gotPaths, r.URL.Path)
		if r.URL.Path == "/user/repos" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		_, _ = w.Write([]byte(`{"repositories":[
			{"name":"gh-broker","full_name":"dutifuldev/gh-broker","owner":{"login":"dutifuldev"}}
		]}`))
	})
	response := do(t, server, http.MethodGet, "/api/repos", bearerAuth())
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	if strings.Join(gotPaths, ",") != "/user/repos,/installation/repositories" {
		t.Fatalf("upstream paths = %v, want user then installation fallback", gotPaths)
	}
}

func TestListReposDropsStaleContentLength(t *testing.T) {
	t.Parallel()
	upstreamBody := `[
		{"name":"gh-broker","full_name":"dutifuldev/gh-broker","owner":{"login":"dutifuldev"}},
		{"name":"repo","full_name":"outside/repo","owner":{"login":"outside"}}
	]`
	server := newTestServerWithHandler(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", strconv.Itoa(len(upstreamBody)))
		w.Header().Set("Link", `<https://api.github.com/user/repos?page=2>; rel="next"`)
		_, _ = w.Write([]byte(upstreamBody))
	})
	response := do(t, server, http.MethodGet, "/api/repos", bearerAuth())
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	if response.Header().Get("Content-Length") == strconv.Itoa(len(upstreamBody)) {
		t.Fatalf("Content-Length copied from unfiltered upstream response")
	}
	if values := response.Header().Values("Link"); len(values) > 0 {
		t.Fatalf("Link copied from unfiltered upstream response: %v", values)
	}
	var repos []struct {
		FullName string `json:"full_name"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &repos); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if len(repos) != 1 || repos[0].FullName != "dutifuldev/gh-broker" {
		t.Fatalf("repos = %+v, want filtered response body", repos)
	}
}

func TestListReposDropsCredentialMetadataHeaders(t *testing.T) {
	t.Parallel()
	server := newTestServerWithHandler(t, func(w http.ResponseWriter, _ *http.Request) {
		setCredentialMetadataHeaders(w.Header())
		w.Header().Set("X-RateLimit-Remaining", "42")
		_, _ = w.Write([]byte(`[
			{"name":"gh-broker","full_name":"dutifuldev/gh-broker","owner":{"login":"dutifuldev"}}
		]`))
	})
	response := do(t, server, http.MethodGet, "/api/repos", bearerAuth())
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	assertCredentialMetadataHeadersDropped(t, response.Header())
	if got := response.Header().Get("X-RateLimit-Remaining"); got != "42" {
		t.Fatalf("X-RateLimit-Remaining = %q, want forwarded rate-limit header", got)
	}
}

func TestListReposSupportsInstallationPayload(t *testing.T) {
	t.Parallel()
	server := newTestServerWithHandler(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"repositories":[
			{"name":"gh-broker","full_name":"dutifuldev/gh-broker","owner":{"login":"dutifuldev"}},
			{"full_name":"outside/repo"}
		]}`))
	})
	response := do(t, server, http.MethodGet, "/api/repos?per_page=500&page=2", bearerAuth())
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	var payload struct {
		Repositories []struct {
			FullName string `json:"full_name"`
		} `json:"repositories"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if len(payload.Repositories) != 1 || payload.Repositories[0].FullName != "dutifuldev/gh-broker" {
		t.Fatalf("payload = %+v, want filtered installation repositories", payload)
	}
}

func TestListReposForwardsUpstreamError(t *testing.T) {
	t.Parallel()
	server := newTestServerWithHandler(t, func(w http.ResponseWriter, _ *http.Request) {
		setCredentialMetadataHeaders(w.Header())
		w.Header().Set("X-RateLimit-Remaining", "42")
		w.WriteHeader(http.StatusTeapot)
		_, _ = w.Write([]byte("upstream error"))
	})
	response := do(t, server, http.MethodGet, "/api/repos", bearerAuth())
	if response.Code != http.StatusTeapot || !strings.Contains(response.Body.String(), "upstream error") {
		t.Fatalf("status/body = %d %q, want upstream error", response.Code, response.Body.String())
	}
	assertCredentialMetadataHeadersDropped(t, response.Header())
	if got := response.Header().Get("X-RateLimit-Remaining"); got != "42" {
		t.Fatalf("X-RateLimit-Remaining = %q, want forwarded rate-limit header", got)
	}
}

func TestListReposRejectsInvalidUpstreamJSON(t *testing.T) {
	t.Parallel()
	server := newTestServerWithHandler(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"unexpected":true}`))
	})
	response := do(t, server, http.MethodGet, "/api/repos", bearerAuth())
	if response.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
}

func TestReadContentsRootUsesContentsEndpoint(t *testing.T) {
	t.Parallel()
	var gotPath string
	server := newTestServerWithHandler(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
	})
	response := do(t, server, http.MethodGet, "/api/repos/dutifuldev/gh-broker/contents", bearerAuth())
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	if gotPath != "/repos/dutifuldev/gh-broker/contents" {
		t.Fatalf("upstream path = %q, want root contents path", gotPath)
	}
}

func TestReadContentsRouteUsesGitHubContentsPath(t *testing.T) {
	t.Parallel()
	var gotPath string
	var gotQuery string
	server := newTestServerWithHandler(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotQuery = r.URL.RawQuery
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"name":"README.md"}`))
	})
	response := do(t, server, http.MethodGet, "/api/repos/dutifuldev/gh-broker/contents/docs/README.md?ref=main", bearerAuth())
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	if gotPath != "/repos/dutifuldev/gh-broker/contents/docs/README.md" {
		t.Fatalf("upstream path = %q, want contents path", gotPath)
	}
	if gotQuery != "ref=main" {
		t.Fatalf("upstream query = %q, want ref=main", gotQuery)
	}
}

func TestReadContentsDoesNotFollowGitHubRedirects(t *testing.T) {
	t.Parallel()
	var paths []string
	server := newTestServerWithHandler(t, func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		if r.URL.Path == "/repos/dutifuldev/gh-broker/contents/README.md" {
			http.Redirect(w, r, "/repos/outside/private/contents/README.md", http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	response := do(t, server, http.MethodGet, "/api/repos/dutifuldev/gh-broker/contents/README.md", bearerAuth())
	if response.Code != http.StatusFound {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	if strings.Join(paths, ",") != "/repos/dutifuldev/gh-broker/contents/README.md" {
		t.Fatalf("upstream paths = %v, want only original policy-checked contents request", paths)
	}
}

func TestReadContentsAllowsLiteralPercentPath(t *testing.T) {
	t.Parallel()
	var gotPath string
	server := newTestServerWithHandler(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
	})
	response := do(t, server, http.MethodGet, "/api/repos/dutifuldev/gh-broker/contents/100%25.md", bearerAuth())
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	if gotPath != "/repos/dutifuldev/gh-broker/contents/100%.md" {
		t.Fatalf("upstream path = %q, want literal percent path", gotPath)
	}
}

func TestReadContentsRejectsDotSegments(t *testing.T) {
	t.Parallel()
	var upstreamCalls int
	server := newTestServerWithHandler(t, func(w http.ResponseWriter, _ *http.Request) {
		upstreamCalls++
		w.WriteHeader(http.StatusOK)
	})
	for _, path := range []string{
		"/api/repos/dutifuldev/gh-broker/contents/../issues",
		"/api/repos/dutifuldev/gh-broker/contents/docs/%2e%2e/issues",
		"/api/repos/dutifuldev/gh-broker/contents/docs/./README.md",
		"/api/repos/dutifuldev/gh-broker/contents/docs%2Fsecret",
		"/api/repos/dutifuldev/gh-broker/contents/docs%2F..%2Fissues",
	} {
		response := do(t, server, http.MethodGet, path, bearerAuth())
		if response.Code != http.StatusBadRequest {
			t.Fatalf("%s status = %d, body = %s", path, response.Code, response.Body.String())
		}
	}
	if upstreamCalls != 0 {
		t.Fatalf("upstream calls = %d, want 0", upstreamCalls)
	}
}

func TestRepoRoutesRejectUnsafeRouteSegments(t *testing.T) {
	t.Parallel()
	var upstreamCalls int
	server := newTestServerWithHandler(t, func(w http.ResponseWriter, _ *http.Request) {
		upstreamCalls++
		w.WriteHeader(http.StatusOK)
	})
	for _, path := range []string{
		"/api/repos/dutifuldev/%2e%2e/contents/README.md",
		"/api/repos/dutifuldev/foo%2Fbar/contents/README.md",
		"/api/repos/%2e%2e/gh-broker/contents/README.md",
		"/dutifuldev/foo%2Fbar.git/info/refs?service=git-upload-pack",
		"/dutifuldev/../info/refs?service=git-upload-pack",
	} {
		response := do(t, server, http.MethodGet, path, bearerAuth())
		if response.Code != http.StatusBadRequest {
			t.Fatalf("%s status = %d, body = %s", path, response.Code, response.Body.String())
		}
	}
	if upstreamCalls != 0 {
		t.Fatalf("upstream calls = %d, want 0", upstreamCalls)
	}
}

func TestReadContentsRefUsesPolicy(t *testing.T) {
	t.Parallel()
	brokerPolicy, err := policy.New(policy.Scope{Rules: []policy.Rule{
		{
			ID:         "bob-main-contents",
			Effect:     policy.EffectAllow,
			Clients:    []string{"bob"},
			Operations: []policy.Operation{policy.OperationContentsRead},
			Targets:    []policy.Target{{Kind: "repo", Owner: "dutifuldev", Name: "gh-broker"}},
			Attrs:      map[string][]string{"paths": {"*"}, "refs": {"main"}},
		},
	}})
	if err != nil {
		t.Fatalf("policy.New() error = %v", err)
	}
	var upstreamCalls int
	server := newTestServerWithPolicyAndHandler(t, brokerPolicy, func(w http.ResponseWriter, _ *http.Request) {
		upstreamCalls++
		w.WriteHeader(http.StatusOK)
	})
	allowed := do(t, server, http.MethodGet, "/api/repos/dutifuldev/gh-broker/contents/README.md?ref=main", bearerAuth())
	if allowed.Code != http.StatusOK {
		t.Fatalf("allowed status = %d, body = %s", allowed.Code, allowed.Body.String())
	}
	denied := do(t, server, http.MethodGet, "/api/repos/dutifuldev/gh-broker/contents/README.md?ref=private-branch", bearerAuth())
	if denied.Code != http.StatusForbidden {
		t.Fatalf("denied status = %d, body = %s", denied.Code, denied.Body.String())
	}
	if upstreamCalls != 1 {
		t.Fatalf("upstream calls = %d, want only the allowed contents read", upstreamCalls)
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
	server.logger = slog.New(slog.NewJSONHandler(&logs, nil))
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
	for _, expected := range []string{`"operation":"git.push.branch_create"`, `"outcome":"denied"`, `"client":"bob"`, `"owner":"outside"`, `"repo":"repo"`} {
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
	server.logger = slog.New(slog.NewJSONHandler(&logs, nil))
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
	for _, expected := range []string{`"operation":"git.push.branch_create"`, `"outcome":"proxied"`, `"matched_rules":["bob-push-branches"]`} {
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
		StateDir:            t.TempDir(),
		TelegramBotToken:    "bot-token",
		TelegramChatID:      123,
		GitHubHTTPTimeout:   7 * time.Second,
		MaxReceivePackBytes: 99,
	}, testBrokerPolicy(t))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
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

func TestUnsupportedGitServiceIsRejected(t *testing.T) {
	t.Parallel()
	server := newTestServer(t)
	response := do(t, server, http.MethodGet, "/dutifuldev/gh-broker.git/info/refs?service=bad-service", bearerAuth())
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
	upstream := httptest.NewServer(handler)
	t.Cleanup(upstream.Close)
	server, err := New(config.Config{
		ClientID:     "bob",
		SharedSecret: testSharedSecret,
		GitHubToken:  testGitHubToken,
		StateDir:     t.TempDir(),
	}, brokerPolicy)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	upstreamURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	server.githubClient = upstream.Client()
	server.githubClient.CheckRedirect = stopGitHubRedirect
	server.githubGitBaseURL = upstreamURL
	server.githubAPIBaseURL = upstreamURL
	return server
}

func requestPRPolicy(t *testing.T) *policy.Policy {
	t.Helper()
	brokerPolicy, err := policy.New(policy.Scope{Rules: []policy.Rule{
		{
			ID:         "bob-can-request-pr-create",
			Effect:     policy.EffectRequest,
			Clients:    []string{"bob"},
			Operations: []policy.Operation{policy.OperationPullRequestCreate},
			Targets:    []policy.Target{{Kind: "repo", Owner: "dutifuldev", Name: "gh-broker"}},
			Attrs: map[string][]string{
				"refs":      {"refs/heads/bob/work"},
				"head_refs": {"refs/heads/bob/work"},
				"base_refs": {"refs/heads/main"},
			},
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
		Attrs:           map[string]string{"ref": "refs/heads/main"},
		Reason:          "test deny over grant",
		Duration:        5 * time.Minute,
		PendingTimeout:  time.Minute,
		MaxUses:         1,
	}
}

type captureNotifier struct {
	messages []notify.ApprovalMessage
	statuses []string
	token    string
}

func (n *captureNotifier) SendApproval(_ context.Context, msg notify.ApprovalMessage) (notify.MessageRef, error) {
	n.token = msg.DecisionToken
	stored := msg
	stored.DecisionToken = ""
	n.messages = append(n.messages, stored)
	return notify.MessageRef{Kind: "test", ChatID: 1, MessageID: len(n.messages), Text: msg.Text}, nil
}

func (n *captureNotifier) UpdateStatus(_ context.Context, _ notify.MessageRef, status string) error {
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
			Operations: []policy.Operation{policy.OperationGitFetch, policy.OperationRepoMetadataRead},
			Targets: []policy.Target{
				{Kind: "repo", Owner: "dutifuldev", Name: "*"},
				{Kind: "repo", Owner: "openclaw", Name: "openclaw"},
			},
		},
		{
			ID:         "bob-contents-read",
			Effect:     policy.EffectAllow,
			Clients:    []string{"bob"},
			Operations: []policy.Operation{policy.OperationContentsRead},
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
			Operations: []policy.Operation{policy.OperationInstallationReposList},
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
			Operations: []policy.Operation{policy.OperationPullRequestCreate},
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
