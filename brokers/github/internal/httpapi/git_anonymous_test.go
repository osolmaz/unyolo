package httpapi

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	usebudget "github.com/osolmaz/unyolo/authorization/budget"
	corepolicy "github.com/osolmaz/unyolo/authorization/policy"
	"github.com/osolmaz/unyolo/brokers/github/internal/policy"
	unyoloaudit "github.com/osolmaz/unyolo/telemetry/audit"
)

func anonymousFirstFetchPolicy(t *testing.T) *policy.Policy {
	t.Helper()
	brokerPolicy, err := policy.New(policy.Scope{Rules: []policy.Rule{
		{
			ID: "anonymous-fetch", Effect: policy.EffectAllow, Clients: []string{"bob"},
			Operations:     []policy.Operation{policy.OperationGitFetch},
			Targets:        []policy.Target{{Kind: "repo", Owner: "*", Name: "*"}},
			CredentialUses: []corepolicy.CredentialUse{corepolicy.CredentialUseNone},
		},
		{
			ID: "managed-fetch", Effect: policy.EffectRequest, Clients: []string{"bob"},
			Operations:     []policy.Operation{policy.OperationGitFetch},
			Targets:        []policy.Target{{Kind: "repo", Owner: "*", Name: "*"}},
			CredentialUses: []corepolicy.CredentialUse{corepolicy.CredentialUseManaged},
			GrantPolicy: &corepolicy.GrantPolicy{
				Mode: string(corepolicy.GrantModeWindow), DefaultMinutes: 60, MaxMinutes: 120, RequestTTLMinutes: 15,
				DefaultMaxUses: usebudget.MaxFiniteUses, MaxUses: usebudget.MaxFiniteUses,
			},
		},
	}})
	if err != nil {
		t.Fatalf("policy.New() error = %v", err)
	}
	return brokerPolicy
}

func TestPublicGitHubFetchUsesNoManagedCredential(t *testing.T) {
	t.Parallel()
	var upstreamCalls atomic.Int32
	server := newTestServerWithPolicyAndHandler(t, anonymousFirstFetchPolicy(t), func(w http.ResponseWriter, request *http.Request) {
		upstreamCalls.Add(1)
		for _, header := range []string{"Authorization", "Proxy-Authorization", "Cookie", "Cookie2"} {
			if value := request.Header.Get(header); value != "" {
				t.Errorf("anonymous request carried %s", header)
			}
		}
		_, _ = w.Write([]byte("public-pack"))
	})
	var auditLog bytes.Buffer
	server.auditWriter = unyoloaudit.New(&auditLog)
	response := doWithHeaders(t, server, http.MethodGet, "/public/repo.git/info/refs?service=git-upload-pack", map[string]string{
		"Authorization": "Bearer " + testSharedSecret,
		"Cookie":        "agent-cookie=secret",
	}, nil)
	if response.Code != http.StatusOK || response.Body.String() != "public-pack" || upstreamCalls.Load() != 1 {
		t.Fatalf("status = %d, body = %q, upstream calls = %d", response.Code, response.Body.String(), upstreamCalls.Load())
	}
	if !strings.Contains(auditLog.String(), `"auth_mode":"none"`) {
		t.Fatalf("anonymous fetch audit = %q", auditLog.String())
	}
	grants, err := server.grants.ListForClient("bob")
	if err != nil || len(grants) != 0 {
		t.Fatalf("anonymous fetch grants = %+v, %v", grants, err)
	}
}

func TestPrivateGitHubFetchFallsBackToApprovedManagedCredential(t *testing.T) {
	t.Parallel()
	var anonymousCalls atomic.Int32
	var managedCalls atomic.Int32
	var managedBody atomic.Value
	server := newTestServerWithPolicyAndHandler(t, anonymousFirstFetchPolicy(t), func(w http.ResponseWriter, request *http.Request) {
		body := new(bytes.Buffer)
		_, _ = body.ReadFrom(request.Body)
		if request.Header.Get("Authorization") == "" {
			anonymousCalls.Add(1)
			http.NotFound(w, request)
			return
		}
		managedCalls.Add(1)
		managedBody.Store(body.String())
		if request.Header.Get("Authorization") != githubGitAuthorization(testGitHubToken) {
			t.Errorf("managed request did not use the configured GitHub credential")
		}
		_, _ = w.Write([]byte("private-pack"))
	})
	notifier := &captureNotifier{}
	server.notifier = notifier

	responses := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		responses <- doWithBody(t, server, http.MethodPost, "/private/repo.git/git-upload-pack", bearerAuth(), []byte("wants-private"))
	}()
	grant, token := waitForGitApproval(t, server, notifier, 1)
	if anonymousCalls.Load() != 1 || managedCalls.Load() != 0 {
		t.Fatalf("calls before approval: anonymous=%d managed=%d", anonymousCalls.Load(), managedCalls.Load())
	}
	if _, err := server.grants.Approve(grant.ID, token, "operator"); err != nil {
		t.Fatalf("Approve() error = %v", err)
	}
	response := <-responses
	if response.Code != http.StatusOK || response.Body.String() != "private-pack" {
		t.Fatalf("status = %d, body = %q", response.Code, response.Body.String())
	}
	if anonymousCalls.Load() != 1 || managedCalls.Load() != 1 || managedBody.Load() != "wants-private" {
		t.Fatalf("calls after approval: anonymous=%d managed=%d body=%v", anonymousCalls.Load(), managedCalls.Load(), managedBody.Load())
	}
}

func TestAnonymousGitHubUpstreamFailureDoesNotRequestApproval(t *testing.T) {
	t.Parallel()
	for _, status := range []int{http.StatusTooManyRequests, http.StatusInternalServerError} {
		status := status
		t.Run(http.StatusText(status), func(t *testing.T) {
			server := newTestServerWithPolicyAndHandler(t, anonymousFirstFetchPolicy(t), func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(status)
			})
			notifier := &captureNotifier{}
			server.notifier = notifier
			response := do(t, server, http.MethodGet, "/public/repo.git/info/refs?service=git-upload-pack", bearerAuth())
			if response.Code != status {
				t.Fatalf("status = %d, body = %q", response.Code, response.Body.String())
			}
			if len(notifier.messages) != 0 {
				t.Fatalf("upstream failure created approval: %+v", notifier.messages)
			}
		})
	}
}

func TestAnonymousGitHubTransportFailureDoesNotRequestApproval(t *testing.T) {
	t.Parallel()
	server := newTestServerWithPolicyAndHandler(t, anonymousFirstFetchPolicy(t), func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	server.githubGitClient = &http.Client{Transport: errorRoundTripper{}}
	notifier := &captureNotifier{}
	server.notifier = notifier
	response := do(t, server, http.MethodGet, "/public/repo.git/info/refs?service=git-upload-pack", bearerAuth())
	if response.Code != http.StatusBadGateway || len(notifier.messages) != 0 {
		t.Fatalf("status = %d, approvals = %+v", response.Code, notifier.messages)
	}
}

func TestPublicGitHubLFSBatchUsesAnonymousFetchPolicy(t *testing.T) {
	t.Parallel()
	var upstreamCalls atomic.Int32
	server := newTestServerWithPolicyAndHandler(t, anonymousFirstFetchPolicy(t), func(w http.ResponseWriter, request *http.Request) {
		upstreamCalls.Add(1)
		if request.Header.Get("Authorization") != "" || request.Header.Get("Cookie") != "" || request.Header.Get("Cookie2") != "" {
			t.Error("anonymous Git LFS request carried a credential")
		}
		body := new(bytes.Buffer)
		_, _ = body.ReadFrom(request.Body)
		if body.String() != `{"operation":"download","objects":[]}` {
			t.Errorf("anonymous Git LFS body = %q", body.String())
		}
		w.Header().Set("Content-Type", "application/vnd.git-lfs+json")
		_, _ = w.Write([]byte(`{"objects":[]}`))
	})
	response := doWithHeaders(t, server, http.MethodPost, "/public/repo.git/info/lfs/objects/batch", map[string]string{
		"Authorization": bearerAuth(), "Cookie2": "legacy-cookie=secret",
	}, []byte(`{"operation":"download","objects":[]}`))
	if response.Code != http.StatusOK || upstreamCalls.Load() != 1 {
		t.Fatalf("status = %d, calls = %d, body = %q", response.Code, upstreamCalls.Load(), response.Body.String())
	}
	grants, err := server.grants.ListForClient("bob")
	if err != nil || len(grants) != 0 {
		t.Fatalf("anonymous LFS grants = %+v, %v", grants, err)
	}
}

func TestAnonymousGitHubRedirectIsNotFollowedOrEscalated(t *testing.T) {
	t.Parallel()
	var redirectedCalls atomic.Int32
	redirected := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		redirectedCalls.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(redirected.Close)
	server := newTestServerWithPolicyAndHandler(t, anonymousFirstFetchPolicy(t), func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", redirected.URL+"/credential-target")
		w.WriteHeader(http.StatusFound)
	})
	notifier := &captureNotifier{}
	server.notifier = notifier
	response := do(t, server, http.MethodGet, "/public/repo.git/info/refs?service=git-upload-pack", bearerAuth())
	if response.Code != http.StatusFound || redirectedCalls.Load() != 0 || len(notifier.messages) != 0 {
		t.Fatalf("status = %d, redirected calls = %d, approvals = %d", response.Code, redirectedCalls.Load(), len(notifier.messages))
	}
}

func TestAnonymousGitHubFetchRejectsOversizedReplayBody(t *testing.T) {
	t.Parallel()
	var upstreamCalls atomic.Int32
	server := newTestServerWithPolicyAndHandler(t, anonymousFirstFetchPolicy(t), func(w http.ResponseWriter, _ *http.Request) {
		upstreamCalls.Add(1)
		w.WriteHeader(http.StatusOK)
	})
	response := doWithBody(t, server, http.MethodPost, "/public/repo.git/git-upload-pack", bearerAuth(),
		bytes.Repeat([]byte("x"), maxAnonymousGitReadRequestBytes+1))
	if response.Code != http.StatusRequestEntityTooLarge || upstreamCalls.Load() != 0 {
		t.Fatalf("status = %d, upstream calls = %d", response.Code, upstreamCalls.Load())
	}
}
