package httpapi

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/osolmaz/brokerkit/brokers/github/internal/policy"
	gitx "github.com/osolmaz/brokerkit/git/protocol"
	"github.com/osolmaz/brokerkit/git/server"
)

func TestGitHandlerHidesAgentAndWebhookRoutes(t *testing.T) {
	server := newTestServer(t)
	handler, err := server.GitHandler()
	if err != nil {
		t.Fatal(err)
	}
	identity := httptest.NewRequest(http.MethodGet, gitserver.IdentityPath, nil)
	identity.SetBasicAuth("brokerkit", testSharedSecret)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, identity)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"provider":"github"`) {
		t.Fatalf("identity = %d %q", response.Code, response.Body.String())
	}
	for _, route := range []string{"/api/agent/v1/operations", "/api/grants", "/webhooks/github", "/healthz"} {
		response = httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, route, nil))
		if response.Code != http.StatusNotFound {
			t.Fatalf("%s returned %d", route, response.Code)
		}
	}
}

func TestGitHubGitRoute(t *testing.T) {
	t.Parallel()
	tests := []struct {
		method string
		path   string
		want   bool
	}{
		{http.MethodGet, "/owner/repo.git/info/refs", true},
		{http.MethodGet, "/owner/repo/info/refs", true},
		{http.MethodPost, "/owner/repo.git/git-upload-pack", true},
		{http.MethodPost, "/owner/repo/git-upload-pack", true},
		{http.MethodPost, "/owner/repo.git/git-receive-pack", true},
		{http.MethodPost, "/owner/repo.git/info/lfs/objects/batch", true},
		{http.MethodGet, "/owner/repo.git/info/lfs/objects/" + strings.Repeat("a", 64), true},
		{http.MethodDelete, "/owner/repo.git/info/lfs/objects/" + strings.Repeat("a", 64), false},
		{http.MethodGet, "/owner/repo.git/git-receive-pack", false},
		{http.MethodPost, "/owner/repo/info/refs", false},
		{http.MethodPost, "/owner/repo.git/git-receive-pack/extra", false},
	}
	for _, test := range tests {
		if got := githubGitRoute(test.method, test.path); got != test.want {
			t.Errorf("githubGitRoute(%q, %q) = %t, want %t", test.method, test.path, got, test.want)
		}
	}
}

func TestReceivePackAdvertisementRemovesThinPack(t *testing.T) {
	t.Parallel()
	advertisement, err := gitx.AppendPktLineString(nil, "# service=git-receive-pack\n")
	if err != nil {
		t.Fatal(err)
	}
	advertisement = gitx.AppendFlushPkt(advertisement)
	advertisement, err = gitx.AppendPktLineString(advertisement, strings.Repeat("1", 40)+" refs/heads/main\x00report-status thin-pack ofs-delta\n")
	if err != nil {
		t.Fatal(err)
	}
	advertisement = gitx.AppendFlushPkt(advertisement)
	server := newTestServerWithHandler(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(advertisement)
	})
	response := do(t, server, http.MethodGet, "/dutifuldev/gh-broker.git/info/refs?service=git-receive-pack", bearerAuth())
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %q", response.Code, response.Body.String())
	}
	if bytes.Contains(response.Body.Bytes(), []byte("thin-pack")) || !bytes.Contains(response.Body.Bytes(), []byte("ofs-delta")) {
		t.Fatalf("rewritten advertisement = %q", response.Body.Bytes())
	}
}

func TestReceivePackAdvertisementRejectsMalformedUpstream(t *testing.T) {
	t.Parallel()
	server := newTestServerWithHandler(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("bad"))
	})
	response := do(t, server, http.MethodGet, "/dutifuldev/gh-broker.git/info/refs?service=git-receive-pack", bearerAuth())
	if response.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, body = %q", response.Code, response.Body.String())
	}
}

func TestReceivePackAdvertisementPreservesUpstreamRefusal(t *testing.T) {
	t.Parallel()
	server := newTestServerWithHandler(t, func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "denied", http.StatusForbidden)
	})
	response := do(t, server, http.MethodGet, "/dutifuldev/gh-broker.git/info/refs?service=git-receive-pack", bearerAuth())
	if response.Code != http.StatusForbidden || !strings.Contains(response.Body.String(), "denied") {
		t.Fatalf("response = %d %q", response.Code, response.Body.String())
	}
}

func TestGitHubLFSBatchKeepsSignedActionInsideBroker(t *testing.T) {
	t.Parallel()
	oid := strings.Repeat("a", 64)
	var actionAuthorization string
	server := newTestServerWithHandler(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/dutifuldev/gh-broker.git/info/lfs/objects/batch":
			w.Header().Set("Content-Type", "application/vnd.git-lfs+json")
			_, _ = w.Write([]byte(`{"objects":[{"oid":"` + oid + `","size":4,"actions":{"download":{"href":"http://` + r.Host + `/signed/download","header":{"Authorization":"storage-secret"}}}}]}`))
		case "/signed/download":
			actionAuthorization = r.Header.Get("Authorization")
			_, _ = w.Write([]byte("data"))
		default:
			t.Fatalf("unexpected upstream path %s", r.URL.Path)
		}
	})
	response := doWithBody(t, server, http.MethodPost, "/dutifuldev/gh-broker.git/info/lfs/objects/batch", bearerAuth(), []byte(`{"operation":"download","objects":[{"oid":"`+oid+`","size":4}]}`))
	if response.Code != http.StatusOK {
		t.Fatalf("batch status = %d, body = %s", response.Code, response.Body.String())
	}
	var payload struct {
		Objects []struct {
			Actions map[string]struct {
				Href   string            `json:"href"`
				Header map[string]string `json:"header"`
			} `json:"actions"`
		} `json:"objects"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	action := payload.Objects[0].Actions["download"]
	if action.Header != nil || strings.Contains(action.Href, "storage-secret") || !strings.Contains(action.Href, githubLFSActionQuery+"=") {
		t.Fatalf("rewritten action = %+v", action)
	}
	parsed, err := url.Parse(action.Href)
	if err != nil {
		t.Fatal(err)
	}
	download := do(t, server, http.MethodGet, parsed.RequestURI(), bearerAuth())
	if download.Code != http.StatusOK || download.Body.String() != "data" {
		t.Fatalf("download = %d %q", download.Code, download.Body.String())
	}
	if actionAuthorization != "storage-secret" {
		t.Fatalf("signed action authorization = %q", actionAuthorization)
	}
}

func TestGitHubLFSBatchDecompressesUpstreamResponse(t *testing.T) {
	t.Parallel()
	server := newTestServerWithHandler(t, func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
			t.Fatal("transport did not negotiate gzip")
		}
		w.Header().Set("Content-Encoding", "gzip")
		writer := gzip.NewWriter(w)
		_, _ = writer.Write([]byte(`{"objects":[]}`))
		if err := writer.Close(); err != nil {
			t.Fatal(err)
		}
	})
	response := doWithHeaders(t, server, http.MethodPost, "/dutifuldev/gh-broker.git/info/lfs/objects/batch", map[string]string{
		"Authorization":   bearerAuth(),
		"Accept-Encoding": "gzip",
	}, []byte(`{"operation":"download"}`))
	if response.Code != http.StatusOK || response.Body.String() != `{"objects":[]}` {
		t.Fatalf("response = %d %q", response.Code, response.Body.String())
	}
}

func TestGitHubLFSRejectsUnknownAndOversizedBatch(t *testing.T) {
	t.Parallel()
	server := newTestServer(t)
	unknown := doWithBody(t, server, http.MethodPost, "/dutifuldev/gh-broker.git/info/lfs/objects/batch", bearerAuth(), []byte(`{"operation":"remove"}`))
	if unknown.Code != http.StatusBadRequest {
		t.Fatalf("unknown operation status = %d", unknown.Code)
	}
	oversized := doWithBody(t, server, http.MethodPost, "/dutifuldev/gh-broker.git/info/lfs/objects/batch", bearerAuth(), []byte(strings.Repeat("x", maxGitHubLFSBatch+1)))
	if oversized.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized status = %d", oversized.Code)
	}
}

func TestGitHubLFSWritesUseDedicatedPolicyOperation(t *testing.T) {
	t.Parallel()
	if operation, ok := gitTransportOperation("upload"); !ok || operation != policy.OperationGitLFSWrite {
		t.Fatalf("upload operation = %q, %t", operation, ok)
	}
	server := newTestServer(t)
	created := time.Now().UTC()
	for index := range maxGitHubLFSActions + 1 {
		server.storeGitHubLFSAction(strconv.Itoa(index), githubLFSAction{created: created.Add(time.Duration(index) * time.Millisecond)})
	}
	if len(server.lfsActions) != maxGitHubLFSActions {
		t.Fatalf("stored actions = %d, want %d", len(server.lfsActions), maxGitHubLFSActions)
	}
	if _, found := server.lfsActions["0"]; found {
		t.Fatal("oldest LFS action was not evicted")
	}
}

func TestGitHubLFSDirectRoutesUseReadAndWritePolicy(t *testing.T) {
	t.Parallel()
	server := newTestServer(t)
	for _, test := range []struct {
		path string
		want policy.Operation
	}{
		{path: "/dutifuldev/gh-broker.git/info/lfs/locks", want: policy.OperationGitLFSWrite},
		{path: "/dutifuldev/gh-broker.git/info/lfs/locks/verify", want: policy.OperationGitFetch},
	} {
		response := doWithBody(t, server, http.MethodPost, test.path, bearerAuth(), []byte(`{}`))
		if response.Code != http.StatusOK {
			t.Fatalf("%s status = %d, body = %q", test.path, response.Code, response.Body.String())
		}
		if got := gitLFSDirectOperation(http.MethodPost, test.path); got != test.want {
			t.Fatalf("%s operation = %q, want %q", test.path, got, test.want)
		}
	}
}

func TestGitHubLFSResponseFailures(t *testing.T) {
	t.Parallel()
	for name, responseBody := range map[string]string{"malformed": "{", "oversized": strings.Repeat("x", maxGitHubLFSBatch+1)} {
		t.Run(name, func(t *testing.T) {
			server := newTestServerWithHandler(t, func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(responseBody))
			})
			response := doWithBody(t, server, http.MethodPost, "/dutifuldev/gh-broker.git/info/lfs/objects/batch", bearerAuth(), []byte(`{"operation":"download"}`))
			if response.Code != http.StatusBadGateway {
				t.Fatalf("status = %d, body = %q", response.Code, response.Body.String())
			}
		})
	}
	server := newTestServerWithHandler(t, func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "denied", http.StatusForbidden) })
	response := doWithBody(t, server, http.MethodPost, "/dutifuldev/gh-broker.git/info/lfs/objects/batch", bearerAuth(), []byte(`{"operation":"download"}`))
	if response.Code != http.StatusForbidden {
		t.Fatalf("upstream refusal status = %d", response.Code)
	}
	failing := newTestServer(t)
	failing.githubGitClient = &http.Client{Transport: errorRoundTripper{}}
	response = doWithBody(t, failing, http.MethodPost, "/dutifuldev/gh-broker.git/info/lfs/objects/batch", bearerAuth(), []byte(`{"operation":"download"}`))
	if response.Code != http.StatusBadGateway {
		t.Fatalf("transport failure status = %d", response.Code)
	}
}

func TestDoGitHubLFSRequestFailsClosed(t *testing.T) {
	t.Parallel()
	server := newTestServer(t)
	invalid := &http.Request{URL: &url.URL{Scheme: "ftp", Host: "example.test"}}
	if _, err := server.doGitHubLFSRequest(invalid); err == nil {
		t.Fatal("invalid LFS action URL was accepted")
	}
	redirecting := newTestServerWithHandler(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", "/elsewhere")
		w.WriteHeader(http.StatusFound)
	})
	request, err := http.NewRequest(http.MethodGet, redirecting.githubGitBaseURL.JoinPath("redirect").String(), http.NoBody)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := redirecting.doGitHubLFSRequest(request); err == nil {
		t.Fatal("GitHub LFS redirect was accepted")
	}
}

func TestRewriteGitHubLFSObjectRejectsInvalidObjects(t *testing.T) {
	t.Parallel()
	server := newTestServer(t)
	context := newGitContext(t, server, http.MethodPost, "/dutifuldev/gh-broker.git/info/lfs/objects/batch", nil)
	server.rewriteGitHubLFSObject(context, "bob", policy.OperationGitFetch, "invalid")
	invalid := map[string]any{"oid": "bad", "size": json.Number("4"), "actions": map[string]any{"download": map[string]any{}}}
	server.rewriteGitHubLFSObject(context, "bob", policy.OperationGitFetch, invalid)
	if _, found := invalid["actions"]; found {
		t.Fatal("invalid object retained actions")
	}
	valid := map[string]any{"oid": strings.Repeat("a", 64), "size": json.Number("4"), "actions": map[string]any{"bad": "invalid"}}
	server.rewriteGitHubLFSObject(context, "bob", policy.OperationGitFetch, valid)
	if len(valid["actions"].(map[string]any)) != 0 {
		t.Fatalf("invalid action retained: %+v", valid)
	}
}
