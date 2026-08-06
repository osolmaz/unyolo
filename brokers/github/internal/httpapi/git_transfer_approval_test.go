package httpapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	usebudget "github.com/osolmaz/unyolo/authorization/budget"
	corepolicy "github.com/osolmaz/unyolo/authorization/policy"
	"github.com/osolmaz/unyolo/brokers/github/internal/policy"
	gitx "github.com/osolmaz/unyolo/git/protocol"
)

func requestFetchPolicy(t *testing.T) *policy.Policy {
	t.Helper()
	brokerPolicy, err := policy.New(policy.Scope{Rules: []policy.Rule{{
		ID: "request-fetch", Effect: policy.EffectRequest, Clients: []string{"bob"},
		Operations: []policy.Operation{policy.OperationGitFetch, policy.OperationGitLFSWrite, policy.OperationGitPushAdvertise},
		Targets:    []policy.Target{{Kind: "repo", Owner: "osolmaz", Name: "gh-broker"}},
		GrantPolicy: &corepolicy.GrantPolicy{
			Mode: "window", DefaultMinutes: 60, MaxMinutes: 120, RequestTTLMinutes: 15,
			DefaultMaxUses: usebudget.MaxFiniteUses, MaxUses: usebudget.MaxFiniteUses,
		},
	}}})
	if err != nil {
		t.Fatalf("policy.New(requestFetchPolicy) error = %v", err)
	}
	return brokerPolicy
}

func TestGitFetchApprovalProxiesAfterApproval(t *testing.T) {
	t.Parallel()
	var upstreamCalls int
	server := newTestServerWithPolicyAndHandler(t, requestFetchPolicy(t), func(w http.ResponseWriter, _ *http.Request) {
		upstreamCalls++
		_, _ = w.Write([]byte("pack"))
	})
	notifier := &captureNotifier{}
	server.notifier = notifier

	responses := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		responses <- do(t, server, http.MethodGet, "/osolmaz/gh-broker.git/info/refs?service=git-upload-pack", bearerAuth())
	}()
	grant, token := waitForGitApproval(t, server, notifier, 1)
	if grant.Operation != "git.fetch" || grant.Reason != "Git fetch requires approval" {
		t.Fatalf("grant = %+v", grant)
	}
	if _, err := server.grants.Approve(grant.ID, token, "operator"); err != nil {
		t.Fatalf("Approve() error = %v", err)
	}
	response := <-responses
	if response.Code != http.StatusOK || upstreamCalls != 1 {
		t.Fatalf("status = %d, upstream calls = %d, body = %q", response.Code, upstreamCalls, response.Body.String())
	}

	// The active window grant covers the follow-up upload-pack without a new approval.
	followUp := doWithBody(t, server, http.MethodPost, "/osolmaz/gh-broker.git/git-upload-pack", bearerAuth(), []byte("wants"))
	if followUp.Code != http.StatusOK || upstreamCalls != 2 {
		t.Fatalf("follow-up status = %d, upstream calls = %d, body = %q", followUp.Code, upstreamCalls, followUp.Body.String())
	}
	items, err := server.grants.ListForClient("bob")
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 {
		t.Fatalf("grants = %d, want 1 shared window grant", len(items))
	}
}

func TestGitFetchApprovalDenied(t *testing.T) {
	t.Parallel()
	server := newTestServerWithPolicyAndHandler(t, requestFetchPolicy(t), func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	notifier := &captureNotifier{}
	server.notifier = notifier

	responses := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		responses <- do(t, server, http.MethodGet, "/osolmaz/gh-broker.git/info/refs?service=git-upload-pack", bearerAuth())
	}()
	grant, token := waitForGitApproval(t, server, notifier, 1)
	if _, err := server.grants.Deny(grant.ID, token, "operator"); err != nil {
		t.Fatalf("Deny() error = %v", err)
	}
	response := <-responses
	if response.Code != http.StatusForbidden || !strings.Contains(response.Body.String(), "approval denied") {
		t.Fatalf("status = %d, body = %q", response.Code, response.Body.String())
	}
}

func TestGitFetchRetriesSharePendingApproval(t *testing.T) {
	t.Parallel()
	var upstreamCalls int
	server := newTestServerWithPolicyAndHandler(t, requestFetchPolicy(t), func(w http.ResponseWriter, _ *http.Request) {
		upstreamCalls++
		w.WriteHeader(http.StatusOK)
	})
	notifier := &captureNotifier{}
	server.notifier = notifier

	responses := make(chan *httptest.ResponseRecorder, 2)
	go func() {
		responses <- do(t, server, http.MethodGet, "/osolmaz/gh-broker.git/info/refs?service=git-upload-pack", bearerAuth())
	}()
	grant, token := waitForGitApproval(t, server, notifier, 1)
	go func() {
		responses <- do(t, server, http.MethodGet, "/osolmaz/gh-broker.git/info/refs?service=git-upload-pack", bearerAuth())
	}()
	// Give the retry a moment to attach, then confirm no duplicate grant exists.
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		items, err := server.grants.ListForClient("bob")
		if err != nil {
			t.Fatal(err)
		}
		if len(items) > 1 {
			t.Fatalf("retry created a duplicate grant: %+v", items)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, err := server.grants.Approve(grant.ID, token, "operator"); err != nil {
		t.Fatalf("Approve() error = %v", err)
	}
	for range 2 {
		response := <-responses
		if response.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %q", response.Code, response.Body.String())
		}
	}
	if upstreamCalls != 2 {
		t.Fatalf("upstream calls = %d, want 2", upstreamCalls)
	}
	items, err := server.grants.ListForClient("bob")
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 {
		t.Fatalf("grants = %d, want 1", len(items))
	}
}

func TestGitLFSWriteCreatesSeparateApprovalFromFetch(t *testing.T) {
	t.Parallel()
	server := newTestServerWithPolicyAndHandler(t, requestFetchPolicy(t), func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.git-lfs+json")
		_, _ = w.Write([]byte(`{"objects":[]}`))
	})
	notifier := &captureNotifier{}
	server.notifier = notifier

	fetchResponses := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		fetchResponses <- do(t, server, http.MethodGet, "/osolmaz/gh-broker.git/info/refs?service=git-upload-pack", bearerAuth())
	}()
	fetchGrant, fetchToken := waitForGitApproval(t, server, notifier, 1)

	// A combined fetch+LFS-write rule must not collide the LFS write request
	// with the pending fetch approval.
	lfsResponses := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		lfsResponses <- doWithBody(t, server, http.MethodPost, "/osolmaz/gh-broker.git/info/lfs/objects/batch", bearerAuth(),
			[]byte(`{"operation":"upload","objects":[]}`))
	}()
	lfsGrant, lfsToken := waitForGitApproval(t, server, notifier, 2)
	if lfsGrant.ID == fetchGrant.ID || lfsGrant.Operation != "git.lfs.write" {
		t.Fatalf("LFS write approval = %+v, want its own grant", lfsGrant)
	}
	if _, err := server.grants.Approve(lfsGrant.ID, lfsToken, "operator"); err != nil {
		t.Fatalf("Approve() error = %v", err)
	}
	lfsResponse := <-lfsResponses
	if lfsResponse.Code != http.StatusOK {
		t.Fatalf("LFS write status = %d, body = %q", lfsResponse.Code, lfsResponse.Body.String())
	}
	if _, err := server.grants.Approve(fetchGrant.ID, fetchToken, "operator"); err != nil {
		t.Fatalf("Approve() error = %v", err)
	}
	fetchResponse := <-fetchResponses
	if fetchResponse.Code != http.StatusOK {
		t.Fatalf("fetch status = %d, body = %q", fetchResponse.Code, fetchResponse.Body.String())
	}
}

func TestGitFetchApprovalRequiresChannel(t *testing.T) {
	t.Parallel()
	server := newTestServerWithPolicyAndHandler(t, requestFetchPolicy(t), func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	response := do(t, server, http.MethodGet, "/osolmaz/gh-broker.git/info/refs?service=git-upload-pack", bearerAuth())
	if response.Code != http.StatusServiceUnavailable || !strings.Contains(response.Body.String(), "approval channel is not configured") {
		t.Fatalf("status = %d, body = %q", response.Code, response.Body.String())
	}
}

func TestGitLFSWriteBatchApprovalProxiesAfterApproval(t *testing.T) {
	t.Parallel()
	oid := strings.Repeat("b", 64)
	server := newTestServerWithPolicyAndHandler(t, requestFetchPolicy(t), func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.git-lfs+json")
		_, _ = w.Write([]byte(`{"objects":[{"oid":"` + oid + `","size":4}]}`))
	})
	notifier := &captureNotifier{}
	server.notifier = notifier

	responses := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		responses <- doWithBody(t, server, http.MethodPost, "/osolmaz/gh-broker.git/info/lfs/objects/batch", bearerAuth(),
			[]byte(`{"operation":"upload","objects":[{"oid":"`+oid+`","size":4}]}`))
	}()
	grant, token := waitForGitApproval(t, server, notifier, 1)
	if grant.Operation != "git.lfs.write" || grant.Reason != "Git LFS write requires approval" {
		t.Fatalf("grant = %+v", grant)
	}
	if _, err := server.grants.Approve(grant.ID, token, "operator"); err != nil {
		t.Fatalf("Approve() error = %v", err)
	}
	response := <-responses
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %q", response.Code, response.Body.String())
	}
}

func TestGitPushAdvertiseApprovalProxiesAfterApproval(t *testing.T) {
	t.Parallel()
	var upstreamCalls int
	server := newTestServerWithPolicyAndHandler(t, requestFetchPolicy(t), func(w http.ResponseWriter, _ *http.Request) {
		upstreamCalls++
		advertisement, err := gitx.AppendPktLineString(nil, "# service=git-receive-pack\n")
		if err != nil {
			t.Fatal(err)
		}
		advertisement = gitx.AppendFlushPkt(advertisement)
		advertisement, err = gitx.AppendPktLineString(advertisement, strings.Repeat("1", 40)+" refs/heads/main\x00report-status ofs-delta\n")
		if err != nil {
			t.Fatal(err)
		}
		advertisement = gitx.AppendFlushPkt(advertisement)
		_, _ = w.Write(advertisement)
	})
	notifier := &captureNotifier{}
	server.notifier = notifier

	responses := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		responses <- do(t, server, http.MethodGet, "/osolmaz/gh-broker.git/info/refs?service=git-receive-pack", bearerAuth())
	}()
	grant, token := waitForGitApproval(t, server, notifier, 1)
	if grant.Operation != "git.push.advertise" || grant.Reason != "Git push discovery requires approval" {
		t.Fatalf("grant = %+v", grant)
	}
	if _, err := server.grants.Approve(grant.ID, token, "operator"); err != nil {
		t.Fatalf("Approve() error = %v", err)
	}
	response := <-responses
	if response.Code != http.StatusOK || upstreamCalls != 1 {
		t.Fatalf("status = %d, upstream calls = %d, body = %q", response.Code, upstreamCalls, response.Body.String())
	}
}

func TestGitFetchWithoutRuleStillDenied(t *testing.T) {
	t.Parallel()
	empty, err := policy.New(policy.Scope{Rules: []policy.Rule{{
		ID: "unrelated", Effect: policy.EffectAllow, Clients: []string{"bob"},
		Operations: []policy.Operation{policy.OperationGitPushAdvertise},
		Targets:    []policy.Target{{Kind: "repo", Owner: "osolmaz", Name: "gh-broker"}},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	server := newTestServerWithPolicyAndHandler(t, empty, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	response := do(t, server, http.MethodGet, "/osolmaz/gh-broker.git/info/refs?service=git-upload-pack", bearerAuth())
	if response.Code != http.StatusForbidden || !strings.Contains(response.Body.String(), "no matching policy rule") {
		t.Fatalf("status = %d, body = %q", response.Code, response.Body.String())
	}
}
