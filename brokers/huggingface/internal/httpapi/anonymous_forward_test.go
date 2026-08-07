package httpapi

import (
	"bytes"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const anonymousFirstHFPolicy = `{"rules":[
	{"id":"anonymous-fetch","effect":"allow","clients":["agent"],"operations":["git.fetch"],"targets":[{"kind":"repo","type":"*","owner":"*","name":"*"}],"credential_use":["none"]},
	{"id":"managed-fetch","effect":"request","clients":["agent"],"operations":["git.fetch"],"targets":[{"kind":"repo","type":"*","owner":"*","name":"*"}],"credential_use":["managed"],"grant_policy":{"default_minutes":5,"max_minutes":5,"request_ttl_minutes":5,"default_max_uses":2,"max_uses":2}}
]}`

func TestPublicHuggingFaceFetchUsesNoManagedCredential(t *testing.T) {
	t.Parallel()
	var calls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		calls.Add(1)
		for _, header := range []string{"Authorization", "Proxy-Authorization", "Cookie", "Cookie2"} {
			if value := request.Header.Get(header); value != "" {
				t.Errorf("anonymous request carried %s", header)
			}
		}
		_, _ = w.Write([]byte("public-pack"))
	}))
	defer upstream.Close()
	var auditLog bytes.Buffer
	handler := newTestHandler(t, t.TempDir(), upstream.URL, &auditLog, anonymousFirstHFPolicy)
	request := httptest.NewRequest(http.MethodGet, "/datasets/public/repo.git/info/refs?service=git-upload-pack", nil)
	request.Header.Set("Authorization", "Bearer "+testSecret)
	request.Header.Set("Cookie", "agent-cookie=secret")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || response.Body.String() != "public-pack" || calls.Load() != 1 {
		t.Fatalf("status = %d, body = %q, calls = %d", response.Code, response.Body.String(), calls.Load())
	}
	if !strings.Contains(auditLog.String(), `"auth_mode":"none"`) {
		t.Fatalf("anonymous fetch audit = %q", auditLog.String())
	}
	grants, err := handler.grants.ListForClient("agent")
	if err != nil || len(grants) != 0 {
		t.Fatalf("anonymous fetch grants = %+v, %v", grants, err)
	}
}

func TestPrivateHuggingFaceFetchFallsBackToApprovedManagedCredential(t *testing.T) {
	t.Parallel()
	var anonymousCalls atomic.Int32
	var managedCalls atomic.Int32
	wantAuthorization := "Basic " + base64.StdEncoding.EncodeToString([]byte("x-access-token:"+testToken))
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") == "" {
			anonymousCalls.Add(1)
			http.NotFound(w, request)
			return
		}
		managedCalls.Add(1)
		if request.Header.Get("Authorization") != wantAuthorization {
			t.Errorf("managed request authorization = %q", request.Header.Get("Authorization"))
		}
		body := new(bytes.Buffer)
		_, _ = body.ReadFrom(request.Body)
		if body.String() != "wants-private" {
			t.Errorf("managed request body = %q", body.String())
		}
		_, _ = w.Write([]byte("private-pack"))
	}))
	defer upstream.Close()
	handler := newTestHandler(t, t.TempDir(), upstream.URL, &bytes.Buffer{}, anonymousFirstHFPolicy)
	notifier := &captureGrantNotifier{}
	handler.notifier = notifier

	path := "/datasets/private/repo.git/git-upload-pack"
	first := httptest.NewRequest(http.MethodPost, path, strings.NewReader("wants-private"))
	first.Header.Set("Authorization", "Bearer "+testSecret)
	firstResponse := httptest.NewRecorder()
	handler.ServeHTTP(firstResponse, first)
	if firstResponse.Code != http.StatusForbidden || anonymousCalls.Load() != 1 || managedCalls.Load() != 0 {
		t.Fatalf("first status = %d, anonymous = %d, managed = %d, body = %q", firstResponse.Code, anonymousCalls.Load(), managedCalls.Load(), firstResponse.Body.String())
	}
	grants, err := handler.grants.ListForClient("agent")
	if err != nil || len(grants) != 1 {
		t.Fatalf("pending grants = %+v, %v", grants, err)
	}
	claim, claimed, err := handler.grants.ClaimNotification(grants[0].ID, 5*time.Minute)
	if err != nil || !claimed {
		t.Fatalf("ClaimNotification() = %+v, %v, %v", claim, claimed, err)
	}
	if _, err := handler.grants.Approve(claim.Grant.ID, claim.DecisionToken, "operator"); err != nil {
		t.Fatalf("Approve() error = %v", err)
	}

	retry := httptest.NewRequest(http.MethodPost, path, strings.NewReader("wants-private"))
	retry.Header.Set("Authorization", "Bearer "+testSecret)
	retryResponse := httptest.NewRecorder()
	handler.ServeHTTP(retryResponse, retry)
	if retryResponse.Code != http.StatusOK || retryResponse.Body.String() != "private-pack" {
		t.Fatalf("retry status = %d, body = %q", retryResponse.Code, retryResponse.Body.String())
	}
	if anonymousCalls.Load() != 2 || managedCalls.Load() != 1 {
		t.Fatalf("retry calls: anonymous = %d, managed = %d", anonymousCalls.Load(), managedCalls.Load())
	}
}

func TestAnonymousHuggingFaceUpstreamFailureDoesNotRequestApproval(t *testing.T) {
	t.Parallel()
	for _, status := range []int{http.StatusTooManyRequests, http.StatusInternalServerError} {
		status := status
		t.Run(http.StatusText(status), func(t *testing.T) {
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(status)
			}))
			defer upstream.Close()
			handler := newTestHandler(t, t.TempDir(), upstream.URL, &bytes.Buffer{}, anonymousFirstHFPolicy)
			notifier := &captureGrantNotifier{}
			handler.notifier = notifier
			request := httptest.NewRequest(http.MethodGet, "/public/repo.git/info/refs?service=git-upload-pack", nil)
			request.Header.Set("Authorization", "Bearer "+testSecret)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != status {
				t.Fatalf("status = %d, body = %q", response.Code, response.Body.String())
			}
			messages, _ := notifier.snapshot()
			if len(messages) != 0 {
				t.Fatalf("upstream failure created approval: %+v", messages)
			}
		})
	}
}

func TestAnonymousHuggingFaceTransportFailureDoesNotRequestApproval(t *testing.T) {
	t.Parallel()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	handler := newTestHandler(t, t.TempDir(), upstream.URL, &bytes.Buffer{}, anonymousFirstHFPolicy)
	upstream.Close()
	notifier := &captureGrantNotifier{}
	handler.notifier = notifier
	request := httptest.NewRequest(http.MethodGet, "/public/repo.git/info/refs?service=git-upload-pack", nil)
	request.Header.Set("Authorization", "Bearer "+testSecret)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	messages, _ := notifier.snapshot()
	if response.Code != http.StatusBadGateway || len(messages) != 0 {
		t.Fatalf("status = %d, approvals = %d", response.Code, len(messages))
	}
}

func TestAnonymousHuggingFaceFetchRejectsOversizedReplayBody(t *testing.T) {
	t.Parallel()
	var calls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	handler := newTestHandler(t, t.TempDir(), upstream.URL, &bytes.Buffer{}, anonymousFirstHFPolicy)
	request := httptest.NewRequest(http.MethodPost, "/public/repo.git/git-upload-pack",
		bytes.NewReader(bytes.Repeat([]byte("x"), int(maxAnonymousGitReadRequestBytes)+1)))
	request.Header.Set("Authorization", "Bearer "+testSecret)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusRequestEntityTooLarge || calls.Load() != 0 {
		t.Fatalf("status = %d, calls = %d", response.Code, calls.Load())
	}
}

func TestPublicHuggingFaceLFSBatchUsesAnonymousFetchPolicy(t *testing.T) {
	t.Parallel()
	var calls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		calls.Add(1)
		if request.Header.Get("Authorization") != "" {
			t.Error("anonymous LFS request carried authorization")
		}
		w.Header().Set("Content-Type", "application/vnd.git-lfs+json")
		_, _ = w.Write([]byte(`{"objects":[]}`))
	}))
	defer upstream.Close()
	handler := newTestHandler(t, t.TempDir(), upstream.URL, &bytes.Buffer{}, anonymousFirstHFPolicy)
	request := httptest.NewRequest(http.MethodPost, "/datasets/public/repo.git/info/lfs/objects/batch",
		strings.NewReader(`{"operation":"download","objects":[]}`))
	request.Header.Set("Authorization", "Bearer "+testSecret)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || calls.Load() != 1 {
		t.Fatalf("status = %d, calls = %d, body = %q", response.Code, calls.Load(), response.Body.String())
	}
	grants, err := handler.grants.ListForClient("agent")
	if err != nil || len(grants) != 0 {
		t.Fatalf("anonymous LFS grants = %+v, %v", grants, err)
	}
}

func TestPublicHuggingFaceXetResponseIsRefusedWithoutApproval(t *testing.T) {
	t.Parallel()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "" {
			t.Error("anonymous Xet request carried authorization")
		}
		w.Header().Set("Content-Type", "application/vnd.git-lfs+json")
		_, _ = w.Write([]byte(`{"transfer":"xet","objects":[]}`))
	}))
	defer upstream.Close()
	handler := newTestHandler(t, t.TempDir(), upstream.URL, &bytes.Buffer{}, anonymousFirstHFPolicy)
	notifier := &captureGrantNotifier{}
	handler.notifier = notifier
	request := httptest.NewRequest(http.MethodPost, "/datasets/public/repo.git/info/lfs/objects/batch",
		strings.NewReader(`{"operation":"download","objects":[]}`))
	request.Header.Set("Authorization", "Bearer "+testSecret)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	messages, _ := notifier.snapshot()
	if response.Code != http.StatusNotImplemented || len(messages) != 0 {
		t.Fatalf("status = %d, approvals = %d, body = %q", response.Code, len(messages), response.Body.String())
	}
}

func TestAnonymousHuggingFaceRedirectIsNotFollowedOrEscalated(t *testing.T) {
	t.Parallel()
	var redirectedCalls atomic.Int32
	redirected := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		redirectedCalls.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer redirected.Close()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", redirected.URL+"/credential-target")
		w.WriteHeader(http.StatusFound)
	}))
	defer upstream.Close()
	handler := newTestHandler(t, t.TempDir(), upstream.URL, &bytes.Buffer{}, anonymousFirstHFPolicy)
	notifier := &captureGrantNotifier{}
	handler.notifier = notifier
	request := httptest.NewRequest(http.MethodGet, "/public/repo.git/info/refs?service=git-upload-pack", nil)
	request.Header.Set("Authorization", "Bearer "+testSecret)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	messages, _ := notifier.snapshot()
	if response.Code != http.StatusFound || redirectedCalls.Load() != 0 || len(messages) != 0 {
		t.Fatalf("status = %d, redirected calls = %d, approvals = %d", response.Code, redirectedCalls.Load(), len(messages))
	}
}
