package httpapi

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/osolmaz/brokerkit/approvalnotify"
	"github.com/osolmaz/brokerkit/audit"
	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/config"
	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/gitproxy"
	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/hfgrant"
	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/hfplan"
	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/policy"
	"github.com/osolmaz/brokerkit/grants"
	"github.com/osolmaz/brokerkit/notify"
	"github.com/osolmaz/brokerkit/state"
)

const (
	testSecret      = "abcdefghijklmnopqrstuvwxyz123456"
	testOtherSecret = "123456abcdefghijklmnopqrstuvwxyz"
	testToken       = "hf_upstream_token_value_1234567890"
)

func TestReceivePackReportIsBounded(t *testing.T) {
	body, err := readReceivePackReport(strings.NewReader("report"))
	if err != nil || string(body) != "report" {
		t.Fatalf("readReceivePackReport() = %q, %v", body, err)
	}
	if _, err := readReceivePackReport(io.LimitReader(zeroReader{}, maxReceivePackReportBytes+1)); err == nil {
		t.Fatal("readReceivePackReport() accepted an oversized response")
	}
}

func TestServerRuntimeInputsControlLFSState(t *testing.T) {
	now := time.Date(2026, 7, 13, 7, 0, 0, 0, time.FixedZone("test", 8*60*60))
	server := &Server{now: func() time.Time { return now }, newLFSActionID: func() (string, error) {
		return "", errors.New("entropy unavailable")
	}, lfsActions: map[string]lfsAction{}}
	if got := server.utcNow(); !got.Equal(now) || got.Location() != time.UTC {
		t.Fatalf("utcNow() = %v", got)
	}
	if _, ok := server.registerLFSAction("alice", route{repoType: policy.TypeModel, owner: "alice", name: "model"}, strings.Repeat("a", 64), "1", "download", map[string]any{"href": "https://huggingface.co/file"}); ok {
		t.Fatal("registerLFSAction() succeeded after entropy failure")
	}
}

type zeroReader struct{}

func (zeroReader) Read(buffer []byte) (int, error) {
	for index := range buffer {
		buffer[index] = 0
	}
	return len(buffer), nil
}

type testDatasetPolicy struct {
	name        string
	allowOps    []policy.Operation
	requestOps  []policy.Operation
	grantBounds map[string]int
}

type grantRequestResult struct {
	status int
	body   string
	err    error
}

type requestedGrant struct {
	grants.Grant
	DecisionToken string
}

func requestHFGrant(t *testing.T, store *grants.Store, plans *hfplan.Store, input hfgrant.Input) (requestedGrant, bool, error) {
	t.Helper()
	if input.ClientRequestID == "" {
		input.ClientRequestID = strings.NewReplacer("/", "-", " ", "-").Replace(t.Name())
	}
	var result grants.RequestResult
	var created bool
	var err error
	if store.SupportsPlanTransactions() {
		result, created, err = hfgrant.Request(store, plans, input)
	} else {
		var request grants.Request
		request, err = hfgrant.CanonicalRequest(input)
		if err == nil {
			err = plans.Bind(&request)
		}
		if err == nil {
			result, created, err = store.Request(request)
		}
	}
	return requestedGrant{Grant: result.Grant, DecisionToken: result.DecisionToken}, created, err
}

func testPlanStore(t *testing.T) *hfplan.Store {
	t.Helper()
	database, err := state.Open(t.Context(), t.TempDir(), state.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	plans, err := hfplan.NewStore(database)
	if err != nil {
		t.Fatal(err)
	}
	return plans
}

func appendOnlyDatasetPolicyJSON(names ...string) string {
	repos := make([]testDatasetPolicy, 0, len(names))
	for _, name := range names {
		repos = append(repos, testDatasetPolicy{name: name, allowOps: []policy.Operation{
			policy.OpRepoContentsRead,
			policy.OpGitFetch,
			policy.OpGitPushAppend,
		}})
	}
	return datasetPolicyJSON(repos...)
}

func emptyPolicyJSON() string {
	return `{"rules":[]}`
}

func readOnlyDataset(name string) testDatasetPolicy {
	return testDatasetPolicy{name: name, allowOps: []policy.Operation{
		policy.OpRepoContentsRead,
		policy.OpGitFetch,
	}}
}

func appendOnlyDataset(name string) testDatasetPolicy {
	return testDatasetPolicy{name: name, allowOps: []policy.Operation{
		policy.OpRepoContentsRead,
		policy.OpGitFetch,
		policy.OpGitPushAppend,
	}}
}

func grantableDataset(name string, requestOps ...policy.Operation) testDatasetPolicy {
	return testDatasetPolicy{
		name:       name,
		allowOps:   []policy.Operation{policy.OpRepoContentsRead, policy.OpGitFetch, policy.OpGitPushAppend},
		requestOps: requestOps,
	}
}

func grantableDatasetWithBounds(name string, bounds map[string]int, requestOps ...policy.Operation) testDatasetPolicy {
	repo := grantableDataset(name, requestOps...)
	repo.grantBounds = bounds
	return repo
}

func datasetPolicyJSON(repos ...testDatasetPolicy) string {
	rules := make([]map[string]any, 0, len(repos)*2)
	for _, repo := range repos {
		target := []map[string]string{{
			"kind":  string(policy.KindRepo),
			"type":  string(policy.TypeDataset),
			"owner": "acme",
			"name":  repo.name,
		}}
		if len(repo.allowOps) > 0 {
			rules = append(rules, map[string]any{
				"id":         "allow-" + repo.name,
				"effect":     string(policy.EffectAllow),
				"clients":    []string{"agent"},
				"operations": operationStrings(repo.allowOps),
				"targets":    target,
			})
		}
		if len(repo.requestOps) > 0 {
			grantPolicy := map[string]int{}
			for key, value := range repo.grantBounds {
				grantPolicy[key] = value
			}
			rules = append(rules, map[string]any{
				"id":           "request-" + repo.name,
				"effect":       string(policy.EffectRequest),
				"clients":      []string{"agent"},
				"operations":   operationStrings(repo.requestOps),
				"targets":      target,
				"grant_policy": grantPolicy,
			})
		}
	}
	data, err := json.Marshal(map[string]any{"rules": rules})
	if err != nil {
		panic(err)
	}
	return string(data)
}

func operationStrings(ops []policy.Operation) []string {
	out := make([]string, 0, len(ops))
	for _, op := range ops {
		out = append(out, string(op))
	}
	return out
}

func apiGrantRequestJSON(operation policy.Operation, ref, reason, clientRequestID string, minutes, maxUses int) string {
	return apiGrantRequestForRepoJSON(operation, "repo", ref, reason, clientRequestID, minutes, maxUses)
}

func apiGrantRequestForRepoJSON(operation policy.Operation, repo, ref, reason, clientRequestID string, minutes, maxUses int) string {
	if clientRequestID == "" {
		digest := sha256.Sum256([]byte(fmt.Sprintf("%s\x00%s\x00%s\x00%s\x00%d\x00%d", operation, repo, ref, reason, minutes, maxUses)))
		clientRequestID = "test-" + hex.EncodeToString(digest[:8])
	}
	target := map[string]any{
		"kind":  string(policy.KindRepo),
		"type":  string(policy.TypeDataset),
		"owner": "acme",
		"name":  repo,
	}
	if ref != "" {
		target["refs"] = []string{ref}
	}
	body := map[string]any{
		"operation": string(operation),
		"target":    target,
		"reason":    reason,
	}
	body["client_request_id"] = clientRequestID
	if minutes != 0 {
		body["minutes"] = minutes
	}
	if maxUses != 0 {
		body["max_uses"] = maxUses
	}
	data, err := json.Marshal(body)
	if err != nil {
		panic(err)
	}
	return string(data)
}

func telegramGrantDecision(action notify.Action, msg approvalnotify.Approval) notify.Decision {
	return notify.Decision{
		Action:        action,
		GrantID:       msg.GrantID,
		DecisionToken: msg.DecisionToken,
		ChatID:        123,
		MessageID:     1,
		MessageText:   "grant text",
		OperatorID:    42,
		OperatorTag:   "operator",
	}
}

func decodeAPIGrantResponse(t *testing.T, body string) apiGrantBody {
	t.Helper()
	var envelope struct {
		Status string `json:"status"`
		Data   struct {
			Grant apiGrantBody `json:"grant"`
		} `json:"data"`
	}
	if err := json.Unmarshal([]byte(body), &envelope); err != nil {
		t.Fatalf("grant response JSON error = %v body=%q", err, body)
	}
	return envelope.Data.Grant
}

func decodeAPIGrantList(t *testing.T, body string) []apiGrantBody {
	t.Helper()
	var envelope struct {
		Status string `json:"status"`
		Data   struct {
			Grants []apiGrantBody `json:"grants"`
		} `json:"data"`
	}
	if err := json.Unmarshal([]byte(body), &envelope); err != nil {
		t.Fatalf("grant list response JSON error = %v body=%q", err, body)
	}
	return envelope.Data.Grants
}

func decodeAPIRepoList(t *testing.T, body string) []apiRepoBody {
	t.Helper()
	var envelope struct {
		Status string `json:"status"`
		Data   struct {
			Repos []apiRepoBody `json:"repos"`
		} `json:"data"`
	}
	if err := json.Unmarshal([]byte(body), &envelope); err != nil {
		t.Fatalf("repo list response JSON error = %v body=%q", err, body)
	}
	return envelope.Data.Repos
}

func decodeJSendStatus(t *testing.T, body string) string {
	t.Helper()
	var envelope struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal([]byte(body), &envelope); err != nil {
		t.Fatalf("JSend response JSON error = %v body=%q", err, body)
	}
	return envelope.Status
}

func decodeJSendFailReason(t *testing.T, body string) string {
	t.Helper()
	var envelope struct {
		Status string `json:"status"`
		Data   struct {
			Reason string `json:"reason"`
		} `json:"data"`
	}
	if err := json.Unmarshal([]byte(body), &envelope); err != nil {
		t.Fatalf("JSend fail response JSON error = %v body=%q", err, body)
	}
	return envelope.Data.Reason
}

func TestAuthScopeAndHealth(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	dir := t.TempDir()
	upstreamRepo := seedBareRepo(t, dir)
	upstream := newGitUpstream(t, upstreamRepo, testToken)
	defer upstream.server.Close()
	var auditLog bytes.Buffer
	broker := newTestBroker(t, dir, upstream.server.URL, &auditLog, appendOnlyDatasetPolicyJSON("repo"))
	defer broker.Close()

	resp, body := doRequest(t, http.MethodGet, broker.URL+"/healthz", "", nil)
	if resp.StatusCode != http.StatusOK || strings.TrimSpace(body) != `{"ok": true}` {
		t.Fatalf("health = %d %q", resp.StatusCode, body)
	}
	resp, _ = doRequest(t, http.MethodHead, broker.URL+"/healthz", "", nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("HEAD health status = %d, want 401", resp.StatusCode)
	}
	infoRefs := broker.URL + "/datasets/acme/repo.git/info/refs?service=git-upload-pack"
	resp, _ = doRequest(t, http.MethodGet, infoRefs, "", nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("missing auth status = %d, want 401", resp.StatusCode)
	}
	resp, _ = doRequest(t, http.MethodGet, infoRefs, "Bearer wrong", nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("wrong auth status = %d, want 403", resp.StatusCode)
	}
	resp, _ = doRequest(t, http.MethodGet, broker.URL+"/datasets/acme/other.git/info/refs?service=git-upload-pack", "Bearer "+testSecret, nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("out-of-scope status = %d, want 403", resp.StatusCode)
	}
	if got := upstream.totalHits(); got != 0 {
		t.Fatalf("refused requests reached upstream: hits = %d", got)
	}
	if got := auditLog.String(); strings.Contains(got, testSecret) || strings.Contains(got, testToken) {
		t.Fatalf("audit leaked secret material:\n%s", got)
	}
}

func TestPolicyDecisionAuditIncludesMatchedRules(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstream.Close()
	policyJSON := `{"rules":[
		{"id":"allow-fetch","effect":"allow","clients":["agent"],"operations":["git.fetch"],"targets":[{"kind":"repo","type":"dataset","owner":"acme","name":"repo"}]},
		{"id":"deny-fetch","effect":"deny","clients":["agent"],"operations":["git.fetch"],"targets":[{"kind":"repo","type":"dataset","owner":"acme","name":"blocked"}]}
	]}`
	scp, err := policy.Parse([]byte(policyJSON))
	if err != nil {
		t.Fatal(err)
	}
	var auditLog bytes.Buffer
	handler, err := New(Options{
		Config: config.Config{
			HFToken:      testToken,
			Clients:      []config.Client{{Name: "agent", Secret: testSecret}},
			StateDir:     filepath.Join(t.TempDir(), "state"),
			MaxPackBytes: 25 * 1024 * 1024,
			HFTimeout:    10 * time.Second,
		},
		Scope:           scp,
		Audit:           audit.New(&auditLog),
		UpstreamBaseURL: upstream.URL,
	})
	if err != nil {
		t.Fatal(err)
	}
	broker := httptest.NewServer(handler)
	defer broker.Close()

	resp, _ := doRequest(t, http.MethodGet, broker.URL+"/datasets/acme/repo.git/info/refs?service=git-upload-pack", "Bearer "+testSecret, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("allowed fetch status = %d, want 200", resp.StatusCode)
	}
	resp, _ = doRequest(t, http.MethodGet, broker.URL+"/datasets/acme/blocked.git/info/refs?service=git-upload-pack", "Bearer "+testSecret, nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("denied fetch status = %d, want 403", resp.StatusCode)
	}
	assertAuditContains(t, auditLog.String(),
		`"matched_allow_rule_ids":["allow-fetch"]`,
		`"matched_deny_rule_ids":["deny-fetch"]`,
		`"matched_grant_rule_ids":[]`,
		`"matched_request_rule_ids":[]`,
		`"grant_id":""`,
	)
}

func TestLFSPassThroughAndPolicy(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	dir := t.TempDir()
	upstreamRepo := seedBareRepo(t, dir)
	upstream := newGitUpstream(t, upstreamRepo, testToken)
	defer upstream.server.Close()
	var auditLog bytes.Buffer
	handler := newTestHandler(t, dir, upstream.server.URL, &auditLog, datasetPolicyJSON(
		appendOnlyDataset("repo"),
		appendOnlyDataset("other"),
		readOnlyDataset("readonly"),
	))
	broker := httptest.NewServer(handler)
	defer broker.Close()

	oid := strings.Repeat("a", 64)
	batchURL := broker.URL + "/datasets/acme/repo/info/lfs/objects/batch"
	beforeOversizedBatch := upstream.totalHits()
	resp, _ := doRequest(t, http.MethodPost, batchURL, "Bearer "+testSecret, strings.NewReader(strings.Repeat("x", maxLFSBatchBytes+1)))
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized LFS batch status = %d, want 413", resp.StatusCode)
	}
	if got := upstream.totalHits(); got != beforeOversizedBatch {
		t.Fatalf("oversized LFS batch reached upstream: hits = %d, want %d", got, beforeOversizedBatch)
	}
	resp, body := doRequestWithHeaders(t, http.MethodPost, batchURL, "Bearer "+testSecret, map[string]string{
		"Accept-Encoding": "gzip",
	}, strings.NewReader(fmt.Sprintf(`{"operation":"download","objects":[{"oid":%q,"size":123}]}`, oid)))
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, "download") {
		t.Fatalf("download batch = %d %q", resp.StatusCode, body)
	}
	if got := resp.Header.Values("Set-Cookie"); len(got) != 0 {
		t.Fatalf("broker forwarded upstream cookies: %q", got)
	}
	downloadHref := assertLFSActionHref(t, body, "download", broker.URL+"/datasets/acme/repo.git/info/lfs/objects/"+oid)
	beforeCredentialFreeAction := upstream.totalHits()
	resp, body = doRequest(t, http.MethodGet, downloadHref, "", nil)
	if resp.StatusCode != http.StatusOK || upstream.totalHits() != beforeCredentialFreeAction+1 {
		t.Fatalf("credential-free LFS action = %d %q, upstream hits = %d, want 200 and %d", resp.StatusCode, body, upstream.totalHits(), beforeCredentialFreeAction+1)
	}
	mismatchedRequest := httptest.NewRequest(http.MethodGet, downloadHref, nil)
	mismatchedRoute, _ := parseRepoRoute(mismatchedRequest.URL.Path)
	beforeMismatchedClient := upstream.totalHits()
	_, mismatchedErr := handler.forward(httptest.NewRecorder(), mismatchedRequest, "other-agent", mismatchedRoute, nil, false)
	if !errors.Is(mismatchedErr, errInvalidLFSAction) || upstream.totalHits() != beforeMismatchedClient {
		t.Fatalf("cross-client LFS action error = %v, upstream hits = %d, want invalid action and %d", mismatchedErr, upstream.totalHits(), beforeMismatchedClient)
	}
	tamperedDownloadHref := strings.Replace(downloadHref, "/datasets/acme/repo.git/", "/datasets/acme/other.git/", 1)
	beforeTamperedDownload := upstream.totalHits()
	resp, _ = doRequest(t, http.MethodGet, tamperedDownloadHref, "", nil)
	if resp.StatusCode != http.StatusForbidden || upstream.totalHits() != beforeTamperedDownload {
		t.Fatalf("tampered credential-free LFS action status = %d, upstream hits = %d, want 403 and %d", resp.StatusCode, upstream.totalHits(), beforeTamperedDownload)
	}
	resp, body = doRequest(t, http.MethodPost, batchURL, "Bearer "+testSecret, strings.NewReader(fmt.Sprintf(`{"operation":"upload","objects":[{"oid":%q,"size":123}]}`, oid)))
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, "upload") {
		t.Fatalf("upload batch = %d %q", resp.StatusCode, body)
	}
	uploadHref := assertLFSActionHref(t, body, "upload", broker.URL+"/datasets/acme/repo.git/info/lfs/objects/"+oid+"/123")
	verifyHref := assertLFSActionHref(t, body, "verify", broker.URL+"/datasets/acme/repo.git/info/lfs/objects/"+oid+"/verify")
	tamperedHref := strings.Replace(uploadHref, "/datasets/acme/repo.git/", "/datasets/acme/other.git/", 1)
	beforeTamperedAction := upstream.totalHits()
	resp, _ = doRequest(t, http.MethodPut, tamperedHref, "Bearer "+testSecret, strings.NewReader("contents"))
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("tampered LFS action status = %d, want 403", resp.StatusCode)
	}
	if got := upstream.totalHits(); got != beforeTamperedAction {
		t.Fatalf("tampered LFS action reached upstream: hits = %d, want %d", got, beforeTamperedAction)
	}
	resp, _ = doRequest(t, http.MethodPut, uploadHref, "Bearer "+testSecret, strings.NewReader("contents"))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("signed LFS upload status = %d, want 200", resp.StatusCode)
	}
	if got := resp.Header.Values("Set-Cookie"); len(got) != 0 {
		t.Fatalf("broker forwarded signed-storage cookies: %q", got)
	}
	resp, _ = doRequest(t, http.MethodPost, verifyHref, "Bearer "+testSecret, strings.NewReader("{}"))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("signed LFS verify status = %d, want 200", resp.StatusCode)
	}
	beforeInvalidAction := upstream.totalHits()
	beforeInvalidAudit := auditLog.Len()
	resp, _ = doRequest(t, http.MethodPut, broker.URL+"/datasets/acme/repo.git/info/lfs/objects/"+oid+"/123?"+lfsActionQuery+"=missing", "Bearer "+testSecret, strings.NewReader("contents"))
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("invalid LFS action status = %d, want 403", resp.StatusCode)
	}
	if got := upstream.totalHits(); got != beforeInvalidAction {
		t.Fatalf("invalid LFS action reached upstream: hits = %d, want %d", got, beforeInvalidAction)
	}
	if got := auditLog.String()[beforeInvalidAudit:]; !strings.Contains(got, `"decision":"refused"`) || !strings.Contains(got, errInvalidLFSAction.Error()) || !strings.Contains(got, `"upstream_status":0`) {
		t.Fatalf("invalid LFS action audit missing refusal:\n%s", got)
	}
	resp, _ = doRequest(t, http.MethodPost, batchURL, "Bearer "+testSecret, strings.NewReader(`{"operation":"delete"}`))
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("unsupported LFS op status = %d, want 403", resp.StatusCode)
	}
	resp, _ = doRequest(t, http.MethodPost, broker.URL+"/datasets/acme/readonly/info/lfs/objects/batch", "Bearer "+testSecret, strings.NewReader(`{"operation":"upload"}`))
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("read-only LFS upload status = %d, want 403", resp.StatusCode)
	}
	resp, _ = doRequestWithHeaders(t, http.MethodGet, broker.URL+"/datasets/acme/repo/info/lfs/objects/"+oid, "Bearer "+testSecret, map[string]string{
		"Proxy-Authorization": "Basic leaked-proxy-secret",
	}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("LFS object GET status = %d, want 200", resp.StatusCode)
	}
	resp, _ = doRequest(t, http.MethodPut, broker.URL+"/datasets/acme/repo/info/lfs/objects/"+oid+"/123", "Bearer "+testSecret, strings.NewReader("contents"))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("LFS object PUT status = %d, want 200", resp.StatusCode)
	}
	resp, _ = doRequest(t, http.MethodPost, broker.URL+"/datasets/acme/repo/info/lfs/locks/verify", "Bearer "+testSecret, strings.NewReader("{}"))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("LFS locks verify status = %d, want 200", resp.StatusCode)
	}
	beforeUnsupported := upstream.totalHits()
	resp, _ = doRequest(t, http.MethodDelete, broker.URL+"/datasets/acme/repo/info/lfs/locks/lock-id/unlock", "Bearer "+testSecret, nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("unsupported LFS path status = %d, want 403", resp.StatusCode)
	}
	if got := upstream.totalHits(); got != beforeUnsupported {
		t.Fatalf("unsupported LFS path reached upstream: hits = %d, want %d", got, beforeUnsupported)
	}
}

func TestHTTPErrorPaths(t *testing.T) {
	dir := t.TempDir()
	scp, err := policy.Parse([]byte(appendOnlyDatasetPolicyJSON("repo")))
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{
		HFToken:      testToken,
		Clients:      []config.Client{{Name: "agent", Secret: testSecret}},
		StateDir:     filepath.Join(dir, "state"),
		MaxPackBytes: 4,
		HFTimeout:    50 * time.Millisecond,
	}
	if _, err := New(Options{Config: cfg, Scope: scp, UpstreamBaseURL: "://bad"}); err == nil {
		t.Fatalf("New() accepted invalid upstream URL")
	}
	handler, err := New(Options{Config: cfg, Scope: scp, Audit: testAuditRecorder(), UpstreamBaseURL: "http://127.0.0.1:1"})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(handler)
	defer server.Close()

	pushURL := server.URL + "/datasets/acme/repo.git/git-receive-pack"
	resp, _ := doRequest(t, http.MethodPost, pushURL, "Bearer "+testSecret, strings.NewReader("12345"))
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized push status = %d, want 413", resp.StatusCode)
	}
	cfg.MaxPackBytes = 1024
	if err := handler.Close(); err != nil {
		t.Fatal(err)
	}
	handler, err = New(Options{Config: cfg, Scope: scp, Audit: testAuditRecorder(), UpstreamBaseURL: "http://127.0.0.1:1"})
	if err != nil {
		t.Fatal(err)
	}
	server.Config.Handler = handler
	resp, _ = doRequest(t, http.MethodPost, pushURL, "Bearer "+testSecret, strings.NewReader("bad"))
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("bad push status = %d, want 400", resp.StatusCode)
	}
	resp, _ = doRequest(t, http.MethodPost, pushURL, "Bearer "+testSecret, bytes.NewReader(appendTestFlush(nil)))
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("empty push status = %d, want 400", resp.StatusCode)
	}
	resp, _ = doRequest(t, http.MethodGet, server.URL+"/datasets/acme/repo.git/info/refs?service=git-upload-pack", "Bearer "+testSecret, nil)
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("upstream failure status = %d, want 502", resp.StatusCode)
	}
	if rt, ok := parseRepoRoute("/spaces/acme/repo.git/info/refs"); !ok || rt.repoType != policy.TypeSpace {
		t.Fatalf("space route = %+v ok=%v", rt, ok)
	}
	if rt, ok := parseRepoRoute("/acme/repo.git/info/refs"); !ok || rt.repoType != policy.TypeModel {
		t.Fatalf("model route = %+v ok=%v", rt, ok)
	}
}

func TestConcurrentPushesCannotBothLand(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	dir := t.TempDir()
	upstreamRepo := seedBareRepo(t, dir)
	upstream := newGitUpstream(t, upstreamRepo, testToken)
	defer upstream.server.Close()
	broker := newTestBroker(t, dir, upstream.server.URL, io.Discard, appendOnlyDatasetPolicyJSON("repo"))
	defer broker.Close()

	remote := brokerRemoteURL(broker.URL)
	cloneA := filepath.Join(dir, "clone-a")
	cloneB := filepath.Join(dir, "clone-b")
	runClientGit(t, dir, "clone", remote, cloneA)
	runClientGit(t, dir, "clone", remote, cloneB)
	commitInClone(t, cloneA, "a.txt", "a\n", "a")
	commitInClone(t, cloneB, "b.txt", "b\n", "b")

	start := make(chan struct{})
	results := make(chan error, 2)
	for _, clone := range []string{cloneA, cloneB} {
		go func(clone string) {
			<-start
			_, err := runClientGitErr(clone, "push", "origin", "main")
			results <- err
		}(clone)
	}
	close(start)
	successes := 0
	for i := 0; i < 2; i++ {
		if err := <-results; err == nil {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("successful concurrent pushes = %d, want 1", successes)
	}
}

func TestUpstreamReceivePackRejectionDoesNotAdvanceMirror(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	dir := t.TempDir()
	upstreamRepo := seedBareRepo(t, dir)
	upstream := newGitUpstream(t, upstreamRepo, testToken)
	defer upstream.server.Close()
	var auditLog bytes.Buffer
	broker := newTestBroker(t, dir, upstream.server.URL, &auditLog, appendOnlyDatasetPolicyJSON("repo"))
	defer broker.Close()

	clone := filepath.Join(dir, "clone")
	runClientGit(t, dir, "clone", brokerRemoteURL(broker.URL), clone)
	commitInClone(t, clone, "rejected.txt", "rejected\n", "rejected")
	newSHA := strings.TrimSpace(runClientGit(t, clone, "rev-parse", "HEAD"))

	upstream.setRejectReceive(true)
	output, err := runClientGitErr(clone, "push", "origin", "main")
	if err == nil {
		t.Fatalf("upstream-rejected push succeeded:\n%s", output)
	}
	if !strings.Contains(output, "upstream rejected") {
		t.Fatalf("upstream rejection output missing reason:\n%s", output)
	}
	rejectedHits := upstream.receivePackHits()

	upstream.setRejectReceive(false)
	runClientGit(t, clone, "push", "origin", "main")
	if got := upstream.receivePackHits(); got != rejectedHits+1 {
		t.Fatalf("retry receive-pack hits = %d, want %d", got, rejectedHits+1)
	}
	if upstreamRef := strings.TrimSpace(runGit(t, upstreamRepo, "rev-parse", "refs/heads/main")); upstreamRef != newSHA {
		t.Fatalf("upstream main = %s, want %s", upstreamRef, newSHA)
	}
	if got := auditLog.String(); !strings.Contains(got, `"decision":"refused"`) || !strings.Contains(got, "upstream rejected") {
		t.Fatalf("audit missing upstream rejection:\n%s", got)
	}
}

func TestReceivePackAcceptedClassifiesReservationRelease(t *testing.T) {
	req := gitproxy.ReceivePackRequest{Commands: []gitproxy.Command{{Ref: "refs/heads/main"}}}
	if accepted, reason, definitive := receivePackAccepted(req, http.StatusInternalServerError, nil); accepted || definitive || !strings.Contains(reason, "HTTP 500") {
		t.Fatalf("HTTP failure accepted=%v reason=%q definitive=%v, want ambiguous rejection", accepted, reason, definitive)
	}
	if accepted, reason, definitive := receivePackAccepted(req, http.StatusForbidden, nil); accepted || !definitive || !strings.Contains(reason, "HTTP 403") {
		t.Fatalf("HTTP refusal accepted=%v reason=%q definitive=%v, want definitive pre-receive rejection", accepted, reason, definitive)
	}
	if accepted, reason, definitive := receivePackAccepted(req, http.StatusOK, []byte("not pktline")); accepted || definitive || reason != "could not parse upstream receive-pack report" {
		t.Fatalf("parse failure accepted=%v reason=%q definitive=%v, want ambiguous parse rejection", accepted, reason, definitive)
	}
	rejected := appendTestPktString(nil, "unpack ok\n")
	rejected = appendTestPktString(rejected, "ng refs/heads/main upstream rejected\n")
	rejected = appendTestFlush(rejected)
	if accepted, reason, definitive := receivePackAccepted(req, http.StatusOK, rejected); accepted || definitive || !strings.Contains(reason, "upstream rejected") {
		t.Fatalf("ng rejection accepted=%v reason=%q definitive=%v, want ambiguous receive-pack rejection", accepted, reason, definitive)
	}
	missing := appendTestPktString(nil, "unpack ok\n")
	missing = appendTestFlush(missing)
	if accepted, reason, definitive := receivePackAccepted(req, http.StatusOK, missing); accepted || definitive || !strings.Contains(reason, "missing ref status") {
		t.Fatalf("missing status accepted=%v reason=%q definitive=%v, want ambiguous missing status", accepted, reason, definitive)
	}
}

func TestForwardReceivePackKeepsAcceptedOutcomeOnClientWriteError(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-git-receive-pack-result")
		_, _ = w.Write(acceptedReceivePackReport("refs/heads/main"))
	}))
	defer upstream.Close()

	scp, err := policy.Parse([]byte(emptyPolicyJSON()))
	if err != nil {
		t.Fatal(err)
	}
	handler, err := New(Options{
		Audit: testAuditRecorder(),
		Config: config.Config{
			HFToken:      testToken,
			Clients:      []config.Client{{Name: "agent", Secret: testSecret}},
			StateDir:     filepath.Join(t.TempDir(), "state"),
			MaxPackBytes: 25 * 1024 * 1024,
			HFTimeout:    10 * time.Second,
		},
		Scope:           scp,
		UpstreamBaseURL: upstream.URL,
	})
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/datasets/acme/repo.git/git-receive-pack", nil)
	writer := &writeErrorResponseWriter{}
	status, accepted, reason, _, err := handler.forwardReceivePack(writer, req, route{
		repoType: policy.TypeDataset,
		owner:    "acme",
		name:     "repo",
		tail:     "git-receive-pack",
	}, gitproxy.ReceivePackRequest{
		Commands:     []gitproxy.Command{{Ref: "refs/heads/main"}},
		Capabilities: map[string]bool{},
	}, nil)
	if err != nil || status != http.StatusOK || !accepted || reason != "" {
		t.Fatalf("forwardReceivePack() status=%d accepted=%v reason=%q err=%v", status, accepted, reason, err)
	}
	if writer.status != http.StatusOK {
		t.Fatalf("client response status = %d, want 200", writer.status)
	}
}

func TestJoinURLPath(t *testing.T) {
	tests := []struct {
		base string
		path string
		want string
	}{
		{base: "", path: "/datasets/a/b.git/info/refs", want: "/datasets/a/b.git/info/refs"},
		{base: "/prefix", path: "/datasets/a/b.git/info/refs", want: "/prefix/datasets/a/b.git/info/refs"},
	}
	for _, tc := range tests {
		t.Run(fmt.Sprintf("%s:%s", tc.base, tc.path), func(t *testing.T) {
			if got := joinURLPath(tc.base, tc.path); got != tc.want {
				t.Fatalf("joinURLPath() = %q, want %q", got, tc.want)
			}
		})
	}
}
