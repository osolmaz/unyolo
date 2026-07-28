package httpapi

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/osolmaz/unyolo/approval/notification"
	"github.com/osolmaz/unyolo/approval/notifier"
	unyolotelegram "github.com/osolmaz/unyolo/approval/notifier/telegram"
	"github.com/osolmaz/unyolo/approval/view"
	"github.com/osolmaz/unyolo/brokers/huggingface/internal/config"
	"github.com/osolmaz/unyolo/brokers/huggingface/internal/gitproxy"
	"github.com/osolmaz/unyolo/brokers/huggingface/internal/policy"
	"github.com/osolmaz/unyolo/telemetry/audit"
)

func testAuditRecorder() audit.Recorder { return audit.New(io.Discard) }

func newTestBroker(t *testing.T, dir, upstreamURL string, auditWriter io.Writer, scopeJSON string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(newTestHandler(t, dir, upstreamURL, auditWriter, scopeJSON))
}

func newTestHandler(t *testing.T, dir, upstreamURL string, auditWriter io.Writer, scopeJSON string) *Server {
	t.Helper()
	scp, err := policy.Parse([]byte(scopeJSON))
	if err != nil {
		t.Fatalf("policy.Parse() error = %v", err)
	}
	handler, err := New(Options{
		Config: config.Config{
			HFToken:      testToken,
			Clients:      []config.Client{{Name: "agent", Secret: testSecret}},
			StateDir:     filepath.Join(dir, "state"),
			MaxPackBytes: 25 * 1024 * 1024,
			HFTimeout:    10 * time.Second,
		},
		Scope:           scp,
		Audit:           audit.New(auditWriter),
		UpstreamBaseURL: upstreamURL,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return handler
}

func acceptedReceivePackReport(ref string) []byte {
	body := appendTestPktString(nil, "unpack ok\n")
	body = appendTestPktString(body, "ok "+ref+"\n")
	return appendTestFlush(body)
}

type writeErrorResponseWriter struct {
	header http.Header
	status int
}

func (w *writeErrorResponseWriter) Header() http.Header {
	if w.header == nil {
		w.header = http.Header{}
	}
	return w.header
}

func (w *writeErrorResponseWriter) WriteHeader(status int) {
	w.status = status
}

func (w *writeErrorResponseWriter) Write([]byte) (int, error) {
	return 0, errors.New("client connection closed")
}

type captureGrantNotifier struct {
	mu       sync.Mutex
	messages []approvalnotify.Approval
	updates  []notify.Status
}

type callbackDuringSendNotifier struct {
	mu      sync.Mutex
	server  *Server
	ref     notify.MessageRef
	result  notify.DecisionResult
	updates []notify.Status
}

func (n *callbackDuringSendNotifier) SendApproval(ctx context.Context, msg approvalnotify.Approval) (notify.MessageRef, error) {
	ref, err := unyolotelegram.ApprovalReference(msg, n.ref.ChatID, n.ref.MessageID)
	if err != nil {
		return notify.MessageRef{}, err
	}
	n.ref = ref
	result := n.server.handleTelegramDecision(ctx, notify.Decision{
		Action: notify.ActionApprove, GrantID: msg.GrantID, DecisionToken: msg.DecisionToken,
		ChatID: n.ref.ChatID, MessageID: n.ref.MessageID, MessageText: n.ref.Text,
		OperatorID: 42, OperatorTag: "operator",
	})
	n.mu.Lock()
	n.result = result
	n.mu.Unlock()
	return n.ref, nil
}

func testTelegramReference(t *testing.T, grantID string) notify.MessageRef {
	t.Helper()
	ref, err := unyolotelegram.ApprovalReference(approvalnotify.Approval{
		GrantID: grantID, DecisionToken: "test-token", Broker: "Hugging Face", Requester: "agent", Operation: "test.operation",
		Reason: "test notification", RequestedDurationSeconds: 60, MaxUses: 1, PendingExpiresAt: time.Now().Add(time.Minute),
		Presentation: approvalview.Presentation{Risk: approvalview.RiskLow, Title: "Test approval", Target: "test/repository"},
	}, 1, 2)
	if err != nil {
		t.Fatal(err)
	}
	return ref
}

func (n *callbackDuringSendNotifier) UpdateStatus(_ context.Context, _ notify.MessageRef, status notify.Status) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.updates = append(n.updates, status)
	return nil
}

func (n *callbackDuringSendNotifier) snapshot() (notify.DecisionResult, []notify.Status) {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.result, append([]notify.Status(nil), n.updates...)
}

func (n *captureGrantNotifier) SendApproval(_ context.Context, msg approvalnotify.Approval) (notify.MessageRef, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.messages = append(n.messages, msg)
	return notify.MessageRef{Kind: "capture", ChatID: 123, MessageID: len(n.messages), Text: "grant text"}, nil
}

func (n *captureGrantNotifier) UpdateStatus(_ context.Context, _ notify.MessageRef, status notify.Status) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.updates = append(n.updates, status)
	return nil
}

func (n *captureGrantNotifier) snapshot() ([]approvalnotify.Approval, []notify.Status) {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]approvalnotify.Approval(nil), n.messages...), append([]notify.Status(nil), n.updates...)
}

type blockingGrantNotifier struct {
	mu       sync.Mutex
	messages []approvalnotify.Approval
	started  chan struct{}
	release  chan struct{}
	once     sync.Once
	err      error
	firstErr error
}

func newBlockingGrantNotifier() *blockingGrantNotifier {
	return &blockingGrantNotifier{
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
}

func (n *blockingGrantNotifier) SendApproval(ctx context.Context, msg approvalnotify.Approval) (notify.MessageRef, error) {
	n.mu.Lock()
	n.messages = append(n.messages, msg)
	messageID := len(n.messages)
	n.mu.Unlock()
	if messageID == 1 {
		n.once.Do(func() {
			close(n.started)
		})
		select {
		case <-n.release:
		case <-ctx.Done():
			return notify.MessageRef{}, ctx.Err()
		}
	}
	if messageID == 1 && n.firstErr != nil {
		return notify.MessageRef{}, n.firstErr
	}
	if n.err != nil {
		return notify.MessageRef{}, n.err
	}
	return notify.MessageRef{Kind: "capture", ChatID: 123, MessageID: messageID, Text: "grant text"}, nil
}

func (*blockingGrantNotifier) UpdateStatus(context.Context, notify.MessageRef, notify.Status) error {
	return nil
}

func (n *blockingGrantNotifier) waitForSend(t *testing.T) {
	t.Helper()
	select {
	case <-n.started:
	case <-time.After(5 * time.Second):
		t.Fatalf("notifier send did not start")
	}
}

func (n *blockingGrantNotifier) releaseSend() {
	close(n.release)
}

func (n *blockingGrantNotifier) calls() int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return len(n.messages)
}

func (n *blockingGrantNotifier) decisionTokens() []string {
	n.mu.Lock()
	defer n.mu.Unlock()
	tokens := make([]string, len(n.messages))
	for index, message := range n.messages {
		tokens[index] = message.DecisionToken
	}
	return tokens
}

type zeroMessageGrantNotifier struct {
	calls int
}

func (n *zeroMessageGrantNotifier) SendApproval(context.Context, approvalnotify.Approval) (notify.MessageRef, error) {
	n.calls++
	return notify.MessageRef{Kind: "capture", ChatID: 123, Text: "grant text"}, nil
}

func (*zeroMessageGrantNotifier) UpdateStatus(context.Context, notify.MessageRef, notify.Status) error {
	return nil
}

type failingGrantNotifier struct{}

func (failingGrantNotifier) SendApproval(context.Context, approvalnotify.Approval) (notify.MessageRef, error) {
	return notify.MessageRef{}, errors.New("notify failed")
}

func (failingGrantNotifier) UpdateStatus(context.Context, notify.MessageRef, notify.Status) error {
	return nil
}

type gitUpstream struct {
	t      *testing.T
	repo   string
	token  string
	server *httptest.Server

	mu            sync.Mutex
	total         int
	receivePack   int
	rejectReceive bool
	failReceive   bool
}

func newGitUpstream(t *testing.T, repo, token string) *gitUpstream {
	t.Helper()
	upstream := &gitUpstream{t: t, repo: repo, token: token}
	upstream.server = httptest.NewServer(http.HandlerFunc(upstream.serveHTTP))
	return upstream
}

func (u *gitUpstream) serveHTTP(w http.ResponseWriter, r *http.Request) {
	u.mu.Lock()
	u.total++
	u.mu.Unlock()
	w.Header().Add("Set-Cookie", "hf_session=secret")
	if strings.HasPrefix(r.URL.Path, "/signed-lfs/upload/") {
		if r.Header.Get("Authorization") != "" {
			http.Error(w, "signed upload received authorization", http.StatusInternalServerError)
			return
		}
		if r.ContentLength <= 0 {
			http.Error(w, "signed upload missing content length", http.StatusLengthRequired)
			return
		}
		w.WriteHeader(http.StatusOK)
		return
	}
	if strings.HasPrefix(r.URL.Path, "/signed-lfs/verify/") {
		if r.Header.Get("Authorization") != "Bearer upstream-secret" {
			http.Error(w, "signed verify missing upstream header", http.StatusForbidden)
			return
		}
		w.WriteHeader(http.StatusOK)
		return
	}
	wantAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("x-access-token:"+u.token))
	if r.Header.Get("Authorization") != wantAuth {
		http.Error(w, "bad upstream auth", http.StatusForbidden)
		return
	}
	if r.Header.Get("Proxy-Authorization") != "" {
		http.Error(w, "leaked proxy authorization", http.StatusInternalServerError)
		return
	}
	tail, ok := strings.CutPrefix(r.URL.Path, "/datasets/acme/repo.git")
	if !ok {
		http.NotFound(w, r)
		return
	}
	if strings.HasPrefix(tail, "/info/lfs/") {
		if tail == "/info/lfs/objects/batch" {
			u.serveLFSBatch(w, r)
			return
		}
		if tail == "/info/lfs/locks/verify" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = io.Copy(w, r.Body)
		return
	}
	switch {
	case r.Method == http.MethodGet && tail == "/info/refs":
		u.serveAdvert(w, r)
	case r.Method == http.MethodPost && tail == "/git-upload-pack":
		u.serveRPC(w, r, "git-upload-pack")
	case r.Method == http.MethodPost && tail == "/git-receive-pack":
		u.mu.Lock()
		u.receivePack++
		rejectReceive := u.rejectReceive
		failReceive := u.failReceive
		u.mu.Unlock()
		if failReceive {
			u.serveReceiveFailure(w, r)
			return
		}
		if rejectReceive {
			u.serveReceiveRejection(w, r)
			return
		}
		u.serveRPC(w, r, "git-receive-pack")
	default:
		http.NotFound(w, r)
	}
}

func (u *gitUpstream) serveReceiveFailure(w http.ResponseWriter, r *http.Request) {
	_, _ = io.Copy(io.Discard, r.Body)
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijack unsupported", http.StatusInternalServerError)
		return
	}
	conn, _, err := hijacker.Hijack()
	if err != nil {
		return
	}
	_ = conn.Close()
}

func (u *gitUpstream) serveReceiveRejection(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "read body", http.StatusBadRequest)
		return
	}
	req, err := gitproxy.ParseReceivePack(body)
	if err != nil {
		http.Error(w, "parse receive-pack", http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/x-git-receive-pack-result")
	_, _ = w.Write(buildUpstreamRejectionReport(req))
}

func buildUpstreamRejectionReport(req gitproxy.ReceivePackRequest) []byte {
	sideBand := req.Capabilities["side-band-64k"] || req.Capabilities["side-band"]
	status := appendTestPktString(nil, "unpack ok\n")
	for _, command := range req.Commands {
		status = appendTestPktString(status, "ng "+command.Ref+" upstream rejected\n")
	}
	status = appendTestFlush(status)
	var out []byte
	if sideBand {
		out = appendTestBandBytes(out, 1, status)
		return appendTestFlush(out)
	}
	return status
}

func appendTestBandBytes(dst []byte, band byte, payload []byte) []byte {
	data := append([]byte{band}, payload...)
	return appendTestPkt(dst, data)
}

func (u *gitUpstream) serveLFSBatch(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		Operation string `json:"operation"`
		Objects   []struct {
			OID  string `json:"oid"`
			Size int64  `json:"size"`
		} `json:"objects"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "bad lfs batch", http.StatusBadRequest)
		return
	}
	if len(payload.Objects) == 0 {
		http.Error(w, "missing lfs objects", http.StatusBadRequest)
		return
	}
	object := payload.Objects[0]
	actions := map[string]map[string]any{}
	switch payload.Operation {
	case "download":
		actions["download"] = upstreamLFSAction(u.server.URL + "/datasets/acme/repo.git/info/lfs/objects/" + object.OID)
	case "upload":
		actions["upload"] = map[string]any{"href": fmt.Sprintf("%s/signed-lfs/upload/%s/%d", u.server.URL, object.OID, object.Size)}
		actions["verify"] = upstreamLFSAction(u.server.URL + "/signed-lfs/verify/" + object.OID)
	default:
		http.Error(w, "unsupported lfs operation", http.StatusForbidden)
		return
	}
	w.Header().Set("Content-Type", "application/vnd.git-lfs+json")
	response := map[string]any{
		"transfer": "basic",
		"objects": []map[string]any{{
			"oid":     object.OID,
			"size":    object.Size,
			"actions": actions,
		}},
	}
	if strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
		w.Header().Set("Content-Encoding", "gzip")
		gz := gzip.NewWriter(w)
		defer func() {
			_ = gz.Close()
		}()
		_ = json.NewEncoder(gz).Encode(response)
		return
	}
	_ = json.NewEncoder(w).Encode(response)
}

func upstreamLFSAction(href string) map[string]any {
	return map[string]any{
		"href": href,
		"header": map[string]string{
			"Authorization": "Bearer upstream-secret",
		},
	}
}

func (u *gitUpstream) serveAdvert(w http.ResponseWriter, r *http.Request) {
	service := r.URL.Query().Get("service")
	if service != "git-upload-pack" && service != "git-receive-pack" {
		http.Error(w, "unsupported service", http.StatusForbidden)
		return
	}
	w.Header().Set("Content-Type", "application/x-"+service+"-advertisement")
	var body []byte
	body = appendTestPktString(body, "# service="+service+"\n")
	body = appendTestFlush(body)
	body = append(body, u.runService(service, nil, "--stateless-rpc", "--advertise-refs")...)
	_, _ = w.Write(body)
}

func (u *gitUpstream) serveRPC(w http.ResponseWriter, r *http.Request, service string) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "read body", http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/x-"+service+"-result")
	out := u.runService(service, body, "--stateless-rpc")
	_, _ = w.Write(out)
}

func (u *gitUpstream) runService(service string, stdin []byte, args ...string) []byte {
	gitSubcommand := strings.TrimPrefix(service, "git-")
	fullArgs := append([]string{gitSubcommand}, args...)
	fullArgs = append(fullArgs, u.repo)
	cmd := exec.Command("git", fullArgs...)
	cmd.Env = append(os.Environ(), "GIT_HTTP_EXPORT_ALL=1")
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		u.t.Fatalf("git service %s: %v\n%s", service, err, out)
	}
	return out
}

func (u *gitUpstream) receivePackHits() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.receivePack
}

func (u *gitUpstream) setRejectReceive(reject bool) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.rejectReceive = reject
}

func (u *gitUpstream) setFailReceive(fail bool) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.failReceive = fail
}

func (u *gitUpstream) totalHits() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.total
}

func seedBareRepo(t *testing.T, dir string) string {
	t.Helper()
	upstreamRepo := filepath.Join(dir, "upstream.git")
	work := filepath.Join(dir, "seed")
	runGit(t, dir, "init", "--bare", upstreamRepo)
	runGit(t, dir, "init", work)
	runGit(t, work, "config", "user.email", "agent@example.com")
	runGit(t, work, "config", "user.name", "Agent")
	writeFile(t, filepath.Join(work, "file.txt"), "one\n")
	runGit(t, work, "add", "file.txt")
	runGit(t, work, "commit", "-m", "initial")
	runGit(t, work, "branch", "-M", "main")
	runGit(t, work, "remote", "add", "origin", upstreamRepo)
	runGit(t, work, "push", "origin", "main")
	runGit(t, upstreamRepo, "symbolic-ref", "HEAD", "refs/heads/main")
	return upstreamRepo
}

func brokerRemoteURL(serverURL string) string {
	u, err := url.Parse(serverURL)
	if err != nil {
		panic(err)
	}
	u.Path = "/datasets/acme/repo"
	return u.String()
}

func commitInClone(t *testing.T, clone, filename, contents, message string) {
	t.Helper()
	runClientGit(t, clone, "config", "user.email", "agent@example.com")
	runClientGit(t, clone, "config", "user.name", "Agent")
	writeFile(t, filepath.Join(clone, filename), contents)
	runClientGit(t, clone, "add", filename)
	runClientGit(t, clone, "commit", "-m", message)
}

func doRequest(t *testing.T, method, requestURL, authorization string, body io.Reader) (*http.Response, string) {
	t.Helper()
	return doRequestWithHeaders(t, method, requestURL, authorization, nil, body)
}

func doGrantRequestForTest(serverURL, body string) grantRequestResult {
	req, err := http.NewRequest(http.MethodPost, serverURL+"/api/grants", strings.NewReader(body))
	if err != nil {
		return grantRequestResult{err: err}
	}
	req.Header.Set("Authorization", "Bearer "+testSecret)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return grantRequestResult{err: err}
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return grantRequestResult{err: err}
	}
	return grantRequestResult{status: resp.StatusCode, body: string(data)}
}

func doRequestWithHeaders(t *testing.T, method, requestURL, authorization string, headers map[string]string, body io.Reader) (*http.Response, string) {
	t.Helper()
	req, err := http.NewRequest(method, requestURL, body)
	if err != nil {
		t.Fatal(err)
	}
	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp, string(data)
}

func assertLFSActionHref(t *testing.T, body, action, wantPrefix string) string {
	t.Helper()
	var payload struct {
		Objects []struct {
			Actions map[string]struct {
				Href   string            `json:"href"`
				Header map[string]string `json:"header"`
			} `json:"actions"`
		} `json:"objects"`
	}
	if err := json.Unmarshal([]byte(body), &payload); err != nil {
		t.Fatalf("LFS batch response is not JSON: %v\n%s", err, body)
	}
	if len(payload.Objects) != 1 {
		t.Fatalf("LFS objects = %d, want 1 in %s", len(payload.Objects), body)
	}
	got := payload.Objects[0].Actions[action]
	if !strings.HasPrefix(got.Href, wantPrefix) {
		t.Fatalf("LFS action %s href = %q, want prefix %q in %s", action, got.Href, wantPrefix, body)
	}
	u, err := url.Parse(got.Href)
	if err != nil {
		t.Fatalf("LFS action %s href is not a URL: %v", action, err)
	}
	if u.Query().Get(lfsActionQuery) == "" {
		t.Fatalf("LFS action %s href missing broker action token: %q", action, got.Href)
	}
	if len(got.Header) != 0 || strings.Contains(body, "upstream-secret") || strings.Contains(body, "Authorization") || strings.Contains(body, "/signed-lfs/") {
		t.Fatalf("LFS action %s leaked upstream headers in %s", action, body)
	}
	return got.Href
}

func writeFile(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
}

func runClientGit(t *testing.T, dir string, args ...string) string {
	t.Helper()
	out, err := runClientGitErr(dir, args...)
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return out
}

func runClientGitErr(dir string, args ...string) (string, error) {
	return runClientGitErrAs(testSecret, dir, args...)
}

func runClientGitErrAs(secret, dir string, args ...string) (string, error) {
	authHeader := "Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte("agent:"+secret))
	fullArgs := append([]string{"-c", "protocol.version=0", "-c", "http.extraheader=" + authHeader}, args...)
	cmd := exec.Command("git", fullArgs...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1")
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func runGit(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return string(out)
}
