package httpapi

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
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

	"github.com/osolmaz/brokerkit/grants"
	"github.com/osolmaz/brokerkit/notify"
	"github.com/osolmaz/hf-broker/internal/audit"
	"github.com/osolmaz/hf-broker/internal/config"
	"github.com/osolmaz/hf-broker/internal/gitproxy"
	"github.com/osolmaz/hf-broker/internal/gitproxy/pktline"
	"github.com/osolmaz/hf-broker/internal/hfgrant"
	"github.com/osolmaz/hf-broker/internal/policy"
)

const (
	testSecret      = "abcdefghijklmnopqrstuvwxyz123456"
	testOtherSecret = "123456abcdefghijklmnopqrstuvwxyz"
	testToken       = "hf_upstream_token_value_1234567890"
)

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

func requestHFGrant(store *grants.Store, input hfgrant.Input) (requestedGrant, bool, error) {
	result, created, err := hfgrant.Request(store, input)
	return requestedGrant{Grant: result.Grant, DecisionToken: result.DecisionToken}, created, err
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

func telegramGrantDecision(action notify.Action, msg notify.ApprovalMessage) notify.Decision {
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

func TestGitProxyEndToEndAppendOnly(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	dir := t.TempDir()
	upstreamRepo := seedBareRepo(t, dir)
	runGit(t, upstreamRepo, "config", "receive.advertisePushOptions", "true")
	upstream := newGitUpstream(t, upstreamRepo, testToken)
	defer upstream.server.Close()
	var auditLog bytes.Buffer
	broker := newTestBroker(t, dir, upstream.server.URL, &auditLog, appendOnlyDatasetPolicyJSON("repo"))
	defer broker.Close()

	clone := filepath.Join(dir, "clone")
	remote := brokerRemoteURL(broker.URL)
	runClientGit(t, dir, "clone", remote, clone)
	runClientGit(t, clone, "config", "user.email", "agent@example.com")
	runClientGit(t, clone, "config", "user.name", "Agent")
	initial := strings.TrimSpace(runClientGit(t, clone, "rev-parse", "HEAD"))

	writeFile(t, filepath.Join(clone, "file.txt"), "two\n")
	runClientGit(t, clone, "commit", "-am", "second")
	second := strings.TrimSpace(runClientGit(t, clone, "rev-parse", "HEAD"))
	beforeReceive := upstream.receivePackHits()
	runClientGit(t, clone, "push", "-o", "ci.skip", "origin", "main")
	if got := upstream.receivePackHits(); got != beforeReceive+1 {
		t.Fatalf("receive-pack hits after fast-forward = %d, want %d", got, beforeReceive+1)
	}
	if upstreamRef := strings.TrimSpace(runGit(t, upstreamRepo, "rev-parse", "refs/heads/main")); upstreamRef != second {
		t.Fatalf("upstream main = %s, want %s", upstreamRef, second)
	}

	otherRemote := strings.Replace(remote, "/repo", "/other", 1)
	beforeOther := upstream.totalHits()
	output, err := runClientGitErr(clone, "push", otherRemote, "main")
	if err == nil {
		t.Fatalf("out-of-policy push succeeded, output:\n%s", output)
	}
	if got := upstream.totalHits(); got != beforeOther {
		t.Fatalf("out-of-policy receive-pack touched upstream: hits=%d want %d", got, beforeOther)
	}

	runClientGit(t, clone, "reset", "--hard", initial)
	output, err = runClientGitErr(clone, "push", "--force", "origin", "main")
	if err == nil {
		t.Fatalf("force push succeeded, output:\n%s", output)
	}
	if !strings.Contains(output, "hf-broker") {
		t.Fatalf("force push output missing broker reason:\n%s", output)
	}
	if strings.Contains(output, "protocol error") {
		t.Fatalf("force push output has protocol error:\n%s", output)
	}
	if got := upstream.receivePackHits(); got != beforeReceive+1 {
		t.Fatalf("force push reached upstream: hits = %d, want %d", got, beforeReceive+1)
	}
	if got := auditLog.String(); !strings.Contains(got, `"operation":"git.push.force"`) {
		t.Fatalf("force push audit missing git.push.force:\n%s", got)
	}

	output, err = runClientGitErr(clone, "push", "origin", ":main")
	if err == nil {
		t.Fatalf("delete push succeeded, output:\n%s", output)
	}
	if got := upstream.receivePackHits(); got != beforeReceive+1 {
		t.Fatalf("delete reached upstream: hits = %d, want %d", got, beforeReceive+1)
	}
	if got := auditLog.String(); !strings.Contains(got, `"operation":"git.ref.delete"`) {
		t.Fatalf("delete push audit missing git.ref.delete:\n%s", got)
	}

	runClientGit(t, clone, "fetch", "origin")
	runClientGit(t, clone, "reset", "--hard", "origin/main")
	runClientGit(t, clone, "checkout", "-b", "feature")
	writeFile(t, filepath.Join(clone, "feature.txt"), "feature\n")
	runClientGit(t, clone, "add", "feature.txt")
	runClientGit(t, clone, "commit", "-m", "feature")
	feature := strings.TrimSpace(runClientGit(t, clone, "rev-parse", "HEAD"))
	output, err = runClientGitErr(clone, "push", "origin", "feature")
	if err != nil {
		t.Fatalf("feature push failed: %v\n%s\nreceive hits=%d\naudit=%s", err, output, upstream.receivePackHits(), auditLog.String())
	}
	if upstreamRef := strings.TrimSpace(runGit(t, upstreamRepo, "rev-parse", "refs/heads/feature")); upstreamRef != feature {
		t.Fatalf("upstream feature = %s, want %s", upstreamRef, feature)
	}

	runClientGit(t, clone, "tag", "-a", "v1", "-m", "v1")
	runClientGit(t, clone, "push", "origin", "v1")
	runClientGit(t, clone, "tag", "-f", "v1", "HEAD~1")
	output, err = runClientGitErr(clone, "push", "--force", "origin", "v1")
	if err == nil {
		t.Fatalf("tag move succeeded, output:\n%s", output)
	}
	if got := auditLog.String(); !strings.Contains(got, `"operation":"git.tag.update"`) {
		t.Fatalf("tag update audit missing git.tag.update:\n%s", got)
	}
	if got := auditLog.String(); strings.Contains(got, testSecret) || strings.Contains(got, testToken) {
		t.Fatalf("audit leaked secret material:\n%s", got)
	}
}

func TestTelegramGrantAllowsForcePush(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	dir := t.TempDir()
	upstreamRepo := seedBareRepo(t, dir)
	upstream := newGitUpstream(t, upstreamRepo, testToken)
	defer upstream.server.Close()
	var auditLog bytes.Buffer
	notifier := &captureGrantNotifier{}
	scp, err := policy.Parse([]byte(datasetPolicyJSON(grantableDatasetWithBounds("repo", map[string]int{"max_uses": 3}, policy.OpGitPushForce))))
	if err != nil {
		t.Fatal(err)
	}
	handler, err := New(Options{
		Config: config.Config{
			HFToken: testToken,
			Clients: []config.Client{
				{Name: "agent", Secret: testSecret},
				{Name: "other", Secret: testOtherSecret},
			},
			StateDir:     filepath.Join(dir, "state"),
			MaxPackBytes: 25 * 1024 * 1024,
			HFTimeout:    10 * time.Second,
		},
		Scope:           scp,
		Audit:           audit.New(&auditLog),
		UpstreamBaseURL: upstream.server.URL,
		GrantNotifier:   notifier,
	})
	if err != nil {
		t.Fatal(err)
	}
	broker := httptest.NewServer(handler)
	defer broker.Close()

	clone := filepath.Join(dir, "clone")
	runClientGit(t, dir, "clone", brokerRemoteURL(broker.URL), clone)
	runClientGit(t, clone, "config", "user.email", "agent@example.com")
	runClientGit(t, clone, "config", "user.name", "Agent")
	initial := strings.TrimSpace(runClientGit(t, clone, "rev-parse", "HEAD"))
	writeFile(t, filepath.Join(clone, "file.txt"), "two\n")
	runClientGit(t, clone, "commit", "-am", "second")
	second := strings.TrimSpace(runClientGit(t, clone, "rev-parse", "HEAD"))
	runClientGit(t, clone, "push", "origin", "main")
	if upstreamRef := strings.TrimSpace(runGit(t, upstreamRepo, "rev-parse", "refs/heads/main")); upstreamRef != second {
		t.Fatalf("upstream main = %s, want %s", upstreamRef, second)
	}

	runClientGit(t, clone, "reset", "--hard", initial)
	beforeGrant := upstream.receivePackHits()
	output, err := runClientGitErr(clone, "push", "--force", "origin", "main")
	if err == nil || !strings.Contains(output, "hf-broker") {
		t.Fatalf("force push without grant err=%v output:\n%s", err, output)
	}
	if got := upstream.receivePackHits(); got != beforeGrant {
		t.Fatalf("force push without grant reached upstream: hits=%d want %d", got, beforeGrant)
	}

	resp, body := doRequest(t, http.MethodPost, broker.URL+"/api/grants", "Bearer "+testSecret, strings.NewReader(apiGrantRequestJSON(policy.OpGitPushForce, "refs/heads/main", "recover main", "recover-main", 5, 0)))
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("grant request = %d %q, want 202", resp.StatusCode, body)
	}
	if len(notifier.messages) != 1 {
		t.Fatalf("notifier messages = %+v, want one", notifier.messages)
	}
	msg := notifier.messages[0]
	if strings.Contains(body, msg.DecisionToken) {
		t.Fatalf("grant response leaked decision token: %s", body)
	}
	resp, _ = doRequest(t, http.MethodPost, broker.URL+"/api/grants", "Bearer "+testSecret, strings.NewReader(apiGrantRequestJSON(policy.OpGitPushForce, "refs/heads/main", "recover main", "recover-main", 5, 0)))
	if resp.StatusCode != http.StatusAccepted || len(notifier.messages) != 1 {
		t.Fatalf("idempotent grant status=%d messages=%d, want 202 and one message", resp.StatusCode, len(notifier.messages))
	}
	answer := handler.handleTelegramDecision(context.Background(), telegramGrantDecision(notify.ActionApprove, msg))
	if answer.Answer != "Grant approved" {
		t.Fatalf("telegram answer = %+v", answer)
	}

	output, err = runClientGitErrAs(testOtherSecret, clone, "push", "--force", "origin", "main")
	if err == nil || !strings.Contains(output, "hf-broker") {
		t.Fatalf("cross-client force push used grant err=%v output:\n%s", err, output)
	}
	if got := upstream.receivePackHits(); got != beforeGrant {
		t.Fatalf("cross-client force push reached upstream: hits=%d want %d", got, beforeGrant)
	}

	assertHistoryRewriteGrantDoesNotAllowDeletion(t, clone, upstream, beforeGrant)

	runClientGit(t, clone, "push", "--force", "origin", "main")
	if upstreamRef := strings.TrimSpace(runGit(t, upstreamRepo, "rev-parse", "refs/heads/main")); upstreamRef != initial {
		t.Fatalf("upstream main after grant = %s, want %s", upstreamRef, initial)
	}
	if len(notifier.updates) != 1 || !strings.Contains(notifier.updates[0], "Access is now closed") {
		t.Fatalf("grant use notification updates = %+v", notifier.updates)
	}
	output, err = runClientGitErr(clone, "push", "origin", ":main")
	if err == nil {
		t.Fatalf("delete push after consumed grant err=%v output:\n%s", err, output)
	}
	if got := auditLog.String(); !strings.Contains(got, `"decision":"grant-used"`) ||
		!strings.Contains(got, `"grant_id":"`+msg.GrantID+`"`) ||
		!strings.Contains(got, `"matched_grant_rule_ids":["`+msg.GrantID+`"]`) ||
		strings.Contains(got, testSecret) ||
		strings.Contains(got, testToken) ||
		strings.Contains(got, msg.DecisionToken) {
		t.Fatalf("audit missing grant-used or leaked secret material:\n%s", got)
	}
	if replay := handler.handleTelegramDecision(context.Background(), telegramGrantDecision(notify.ActionDeny, msg)); replay.Answer != "Grant is no longer pending" {
		t.Fatalf("replay answer = %+v", replay)
	}
}

func assertHistoryRewriteGrantDoesNotAllowDeletion(t *testing.T, clone string, upstream *gitUpstream, wantHits int) {
	t.Helper()
	output, err := runClientGitErr(clone, "push", "origin", ":main")
	if err == nil {
		t.Fatalf("branch deletion used history-rewrite grant err=%v output:\n%s", err, output)
	}
	if got := upstream.receivePackHits(); got != wantHits {
		t.Fatalf("branch deletion with history-rewrite grant reached upstream: hits=%d want %d", got, wantHits)
	}
}

func TestDenyRuleOverridesActiveGrant(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	dir := t.TempDir()
	upstreamRepo := seedBareRepo(t, dir)
	upstream := newGitUpstream(t, upstreamRepo, testToken)
	defer upstream.server.Close()
	policyJSON := `{"rules":[
		{"id":"allow-append","effect":"allow","clients":["agent"],"operations":["repo.contents.read","git.fetch","git.push.append"],"targets":[{"kind":"repo","type":"dataset","owner":"acme","name":"repo"}]},
		{"id":"deny-force","effect":"deny","clients":["agent"],"operations":["git.push.force"],"targets":[{"kind":"repo","type":"dataset","owner":"acme","name":"repo"}]}
	]}`
	scp, err := policy.Parse([]byte(policyJSON))
	if err != nil {
		t.Fatal(err)
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
		UpstreamBaseURL: upstream.server.URL,
	})
	if err != nil {
		t.Fatal(err)
	}
	broker := httptest.NewServer(handler)
	defer broker.Close()

	grant, _, err := requestHFGrant(handler.grants, hfgrant.Input{
		Client:    "agent",
		Operation: string(policy.OpGitPushForce),
		Target:    "dataset/acme/repo",
		Ref:       "refs/heads/main",
		Reason:    "preapproved force push",
		MaxUses:   1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := handler.grants.Approve(grant.ID, grant.DecisionToken, "test"); err != nil {
		t.Fatal(err)
	}

	clone := filepath.Join(dir, "clone")
	runClientGit(t, dir, "clone", brokerRemoteURL(broker.URL), clone)
	runClientGit(t, clone, "config", "user.email", "agent@example.com")
	runClientGit(t, clone, "config", "user.name", "Agent")
	initial := strings.TrimSpace(runClientGit(t, clone, "rev-parse", "HEAD"))
	writeFile(t, filepath.Join(clone, "file.txt"), "two\n")
	runClientGit(t, clone, "commit", "-am", "second")
	runClientGit(t, clone, "push", "origin", "main")
	runClientGit(t, clone, "reset", "--hard", initial)
	beforeForce := upstream.receivePackHits()

	output, err := runClientGitErr(clone, "push", "--force", "origin", "main")
	if err == nil || !strings.Contains(output, "hf-broker") {
		t.Fatalf("force push with denied active grant err=%v output:\n%s", err, output)
	}
	if got := upstream.receivePackHits(); got != beforeForce {
		t.Fatalf("denied force push reached upstream: hits=%d want %d", got, beforeForce)
	}
}

func TestDenyRuleStopsActiveGrantPushPreflight(t *testing.T) {
	scp, err := policy.Parse([]byte(`{"rules":[{
		"id":"deny-force",
		"effect":"deny",
		"clients":["agent"],
		"operations":["git.push.force"],
		"targets":[{"kind":"repo","type":"dataset","owner":"acme","name":"repo","refs":["refs/heads/main"]}]
	}]}`))
	if err != nil {
		t.Fatal(err)
	}
	store := grants.New(filepath.Join(t.TempDir(), "grants.json"), grants.Options{})
	grant, _, err := requestHFGrant(store, hfgrant.Input{
		Client:    "agent",
		Operation: string(policy.OpGitPushForce),
		Target:    "dataset/acme/repo",
		Ref:       "refs/heads/main",
		Attrs:     refChangeAttrs("non_fast_forward"),
		Reason:    "old force-push approval",
		MaxUses:   1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Approve(grant.ID, grant.DecisionToken, "test"); err != nil {
		t.Fatal(err)
	}
	server := &Server{policy: scp, grants: store}
	rt := route{repoType: policy.TypeDataset, owner: "acme", name: "repo"}

	ok, reason, err := server.pushCandidateMayInspect("agent", rt, "dataset/acme/repo", "refs/heads/main", pushPolicyCandidate{
		operation: policy.OpGitPushForce,
		refChange: "non_fast_forward",
	}, 12)
	if err != nil {
		t.Fatal(err)
	}
	if ok || reason != "policy denied" {
		t.Fatalf("pushCandidateMayInspect() = %v, %q; want denied despite active grant", ok, reason)
	}
}

func TestActiveGrantRequiresApprovedAttrs(t *testing.T) {
	store := grants.New(filepath.Join(t.TempDir(), "grants.json"), grants.Options{})
	grant, _, err := requestHFGrant(store, hfgrant.Input{
		Client:    "agent",
		Operation: string(policy.OpGitPushAppend),
		Target:    "dataset/acme/repo",
		Ref:       "refs/heads/main",
		Attrs:     map[string]any{"ref_change": "fast_forward"},
		Reason:    "append one fast-forward",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Approve(grant.ID, grant.DecisionToken, "test"); err != nil {
		t.Fatal(err)
	}
	server := &Server{grants: store}
	used := map[string]grantUse{}

	matched, err := server.useActiveGrant("agent", policy.OpGitPushAppend, "dataset/acme/repo", "refs/heads/main", refChangeAttrs("non_fast_forward"), used)
	if err != nil {
		t.Fatal(err)
	}
	if matched {
		t.Fatalf("useActiveGrant() matched non-approved attrs")
	}
	if len(used) != 0 {
		t.Fatalf("used grants after rejected attr match = %+v, want none", used)
	}

	matched, err = server.useActiveGrant("agent", policy.OpGitPushAppend, "dataset/acme/repo", "refs/heads/main", refChangeAttrs("fast_forward"), used)
	if err != nil {
		t.Fatal(err)
	}
	if !matched {
		t.Fatalf("useActiveGrant() did not match approved attrs")
	}
	if used[grant.ID].grant.ID != grant.ID {
		t.Fatalf("used grants = %+v, want approved grant", used)
	}
}

func TestExecutionModeGrantDoesNotAuthorizeRuntimeRequest(t *testing.T) {
	store := grants.New(filepath.Join(t.TempDir(), "grants.json"), grants.Options{})
	grant, _, err := requestHFGrant(store, hfgrant.Input{
		Client:    "agent",
		Operation: string(policy.OpGitPushForce),
		Mode:      hfgrant.ModeExecution,
		Target:    "dataset/acme/repo",
		Ref:       "refs/heads/main",
		Attrs:     refChangeAttrs("non_fast_forward"),
		Reason:    "approve exact execution plan only",
		MaxUses:   1,
	})
	if err != nil {
		t.Fatal(err)
	}
	active, err := store.Approve(grant.ID, grant.DecisionToken, "test")
	if err != nil {
		t.Fatal(err)
	}
	server := &Server{grants: store}
	attrs := refChangeAttrs("non_fast_forward")

	matched, err := server.useActiveGrant("agent", policy.OpGitPushForce, "dataset/acme/repo", "refs/heads/main", attrs, map[string]grantUse{})
	if err != nil {
		t.Fatal(err)
	}
	if matched {
		t.Fatalf("useActiveGrant() matched execution-mode grant")
	}
	rules, err := server.activeGrantRules("agent")
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 0 {
		t.Fatalf("activeGrantRules() = %+v, want no execution-mode grants", rules)
	}
	if activeGrantMatchesIgnoringRef(active, "agent", policy.OpGitPushForce, "dataset/acme/repo", attrs) {
		t.Fatalf("activeGrantMatchesIgnoringRef() matched execution-mode grant")
	}
}

func TestRetainedReservationDoesNotAuthorizeRuntimeRequest(t *testing.T) {
	request, err := hfgrant.CanonicalRequest(hfgrant.Input{
		Client:    "agent",
		Operation: string(policy.OpGitPushForce),
		Target:    "dataset/acme/repo",
		Ref:       "refs/heads/main",
		Attrs:     refChangeAttrs("non_fast_forward"),
		Reason:    "test retained reservation",
	})
	if err != nil {
		t.Fatal(err)
	}
	retained := grants.Grant{
		ID:                  "grant-retained",
		Client:              request.Client,
		Operation:           request.Operation,
		Target:              request.Target,
		Metadata:            request.Metadata,
		Attrs:               request.Attrs,
		Status:              grants.StatusActive,
		MaxUses:             3,
		ReservedCount:       1,
		ReservationRetained: true,
	}
	if _, ok := activeGrantRule(retained); ok {
		t.Fatal("activeGrantRule() generated a rule for a retained reservation")
	}
	if activeGrantMatchesIgnoringRef(retained, "agent", policy.OpGitPushForce, "dataset/acme/repo", refChangeAttrs("non_fast_forward")) {
		t.Fatal("activeGrantMatchesIgnoringRef() matched a retained reservation")
	}
}

func TestMalformedGrantStoreReturnsInternalServerError(t *testing.T) {
	dir := t.TempDir()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	broker := newTestBroker(t, dir, upstream.URL, io.Discard, appendOnlyDatasetPolicyJSON("repo"))
	defer broker.Close()

	grantDir := filepath.Join(dir, "state", "grants")
	if err := os.MkdirAll(grantDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(grantDir, "grants.json"), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, service := range []string{"git-upload-pack", "git-receive-pack"} {
		resp, body := doRequest(t, http.MethodGet, broker.URL+"/datasets/acme/repo.git/info/refs?service="+service, "Bearer "+testSecret, nil)
		if resp.StatusCode != http.StatusInternalServerError || !strings.Contains(body, "could not inspect grants") {
			t.Fatalf("malformed grant store %s response = %d %q, want 500", service, resp.StatusCode, body)
		}
	}
}

func TestReceivePackDiscoveryAllowsRefScopedPushPolicy(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("receive-pack discovery"))
	}))
	defer upstream.Close()
	scp, err := policy.Parse([]byte(`{"rules":[{
		"id":"append-main",
		"effect":"allow",
		"clients":["agent"],
		"operations":["git.push.append"],
		"targets":[{"kind":"repo","type":"dataset","owner":"acme","name":"repo","refs":["refs/heads/main"]}]
	}]}`))
	if err != nil {
		t.Fatal(err)
	}
	handler, err := New(Options{
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
	broker := httptest.NewServer(handler)
	defer broker.Close()

	resp, body := doRequest(t, http.MethodGet, broker.URL+"/datasets/acme/repo.git/info/refs?service=git-receive-pack", "Bearer "+testSecret, nil)
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, "receive-pack discovery") {
		t.Fatalf("receive-pack discovery = %d %q, want forwarded response", resp.StatusCode, body)
	}
}

func TestReceivePackDiscoveryIgnoresRefScopedDeny(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("receive-pack discovery"))
	}))
	defer upstream.Close()
	scp, err := policy.Parse([]byte(`{"rules":[
		{
			"id":"deny-main",
			"effect":"deny",
			"clients":["agent"],
			"operations":["git.push.append"],
			"targets":[{"kind":"repo","type":"dataset","owner":"acme","name":"repo","refs":["refs/heads/main"]}]
		},
		{
			"id":"allow-dev",
			"effect":"allow",
			"clients":["agent"],
			"operations":["git.push.append"],
			"targets":[{"kind":"repo","type":"dataset","owner":"acme","name":"repo","refs":["refs/heads/dev"]}]
		}
	]}`))
	if err != nil {
		t.Fatal(err)
	}
	handler, err := New(Options{
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
	broker := httptest.NewServer(handler)
	defer broker.Close()

	resp, body := doRequest(t, http.MethodGet, broker.URL+"/datasets/acme/repo.git/info/refs?service=git-receive-pack", "Bearer "+testSecret, nil)
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, "receive-pack discovery") {
		t.Fatalf("receive-pack discovery = %d %q, want ref-scoped deny ignored until POST", resp.StatusCode, body)
	}
}

func TestReceivePackDiscoveryChecksAllOperationDecisions(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("receive-pack discovery"))
	}))
	defer upstream.Close()
	scp, err := policy.Parse([]byte(`{"rules":[
		{
			"id":"deny-force",
			"effect":"deny",
			"clients":["agent"],
			"operations":["git.push.force"],
			"targets":[{"kind":"repo","type":"dataset","owner":"acme","name":"repo"}]
		},
		{
			"id":"allow-delete",
			"effect":"allow",
			"clients":["agent"],
			"operations":["git.ref.delete"],
			"targets":[{"kind":"repo","type":"dataset","owner":"acme","name":"repo"}]
		}
	]}`))
	if err != nil {
		t.Fatal(err)
	}
	handler, err := New(Options{
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
	broker := httptest.NewServer(handler)
	defer broker.Close()

	resp, body := doRequest(t, http.MethodGet, broker.URL+"/datasets/acme/repo.git/info/refs?service=git-receive-pack", "Bearer "+testSecret, nil)
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, "receive-pack discovery") {
		t.Fatalf("receive-pack discovery = %d %q, want later allowed operation to permit discovery", resp.StatusCode, body)
	}
}

func TestReceivePackDiscoveryChecksLaterActiveGrant(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("receive-pack discovery"))
	}))
	defer upstream.Close()
	scp, err := policy.Parse([]byte(`{"rules":[
		{
			"id":"deny-force",
			"effect":"deny",
			"clients":["agent"],
			"operations":["git.push.force"],
			"targets":[{"kind":"repo","type":"dataset","owner":"acme","name":"repo"}]
		},
		{
			"id":"request-delete",
			"effect":"request",
			"clients":["agent"],
			"operations":["git.ref.delete"],
			"targets":[{"kind":"repo","type":"dataset","owner":"acme","name":"repo"}],
			"grant_policy":{"default_minutes":5,"max_minutes":5,"default_max_uses":1,"max_uses":1}
		}
	]}`))
	if err != nil {
		t.Fatal(err)
	}
	handler, err := New(Options{
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
	grant, _, err := requestHFGrant(handler.grants, hfgrant.Input{
		Client:    "agent",
		Operation: string(policy.OpGitRefDelete),
		Target:    "dataset/acme/repo",
		Ref:       "refs/heads/feature",
		Attrs:     map[string]any{"max_bytes": int64(1024), "ref_change": "delete"},
		Reason:    "delete stale branch",
		MaxUses:   1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := handler.grants.Approve(grant.ID, grant.DecisionToken, "test"); err != nil {
		t.Fatal(err)
	}
	broker := httptest.NewServer(handler)
	defer broker.Close()

	resp, body := doRequest(t, http.MethodGet, broker.URL+"/datasets/acme/repo.git/info/refs?service=git-receive-pack", "Bearer "+testSecret, nil)
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, "receive-pack discovery") {
		t.Fatalf("receive-pack discovery = %d %q, want later active grant to permit discovery", resp.StatusCode, body)
	}
}

func TestReceivePackDiscoveryRequiresAllowOrActiveGrant(t *testing.T) {
	var mu sync.Mutex
	upstreamHits := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		upstreamHits++
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("receive-pack discovery"))
	}))
	defer upstream.Close()
	hits := func() int {
		mu.Lock()
		defer mu.Unlock()
		return upstreamHits
	}
	scp, err := policy.Parse([]byte(`{"rules":[{
		"id":"request-force",
		"effect":"request",
		"clients":["agent"],
		"operations":["git.push.force"],
		"targets":[{"kind":"repo","type":"dataset","owner":"acme","name":"repo"}],
		"grant_policy":{"default_minutes":5,"max_minutes":5,"default_max_uses":1,"max_uses":1}
	}]}`))
	if err != nil {
		t.Fatal(err)
	}
	handler, err := New(Options{
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
	broker := httptest.NewServer(handler)
	defer broker.Close()
	url := broker.URL + "/datasets/acme/repo.git/info/refs?service=git-receive-pack"

	resp, _ := doRequest(t, http.MethodGet, url, "Bearer "+testSecret, nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("request-only receive-pack discovery = %d, want 403", resp.StatusCode)
	}
	if got := hits(); got != 0 {
		t.Fatalf("request-only discovery reached upstream: hits=%d want 0", got)
	}

	grant, _, err := requestHFGrant(handler.grants, hfgrant.Input{
		Client:    "agent",
		Operation: string(policy.OpGitPushForce),
		Target:    "dataset/acme/repo",
		Ref:       "refs/heads/main",
		Reason:    "force push once",
		MaxUses:   1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := handler.grants.Approve(grant.ID, grant.DecisionToken, "test"); err != nil {
		t.Fatal(err)
	}

	resp, body := doRequest(t, http.MethodGet, url, "Bearer "+testSecret, nil)
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, "receive-pack discovery") {
		t.Fatalf("active-grant receive-pack discovery = %d %q, want forwarded response", resp.StatusCode, body)
	}
	active, err := handler.grants.Get(grant.ID)
	if err != nil {
		t.Fatal(err)
	}
	if active.Status != grants.StatusActive || active.UsedCount != 0 {
		t.Fatalf("grant after receive-pack discovery = %+v, want active and unused", active)
	}
}

func TestReceivePackDiscoveryDeniedPolicyBeatsActiveGrant(t *testing.T) {
	var mu sync.Mutex
	upstreamHits := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		upstreamHits++
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("receive-pack discovery"))
	}))
	defer upstream.Close()
	hits := func() int {
		mu.Lock()
		defer mu.Unlock()
		return upstreamHits
	}
	scp, err := policy.Parse([]byte(`{"rules":[{
		"id":"deny-force",
		"effect":"deny",
		"clients":["agent"],
		"operations":["git.push.force"],
		"targets":[{"kind":"repo","type":"dataset","owner":"acme","name":"repo"}]
	}]}`))
	if err != nil {
		t.Fatal(err)
	}
	handler, err := New(Options{
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
	grant, _, err := requestHFGrant(handler.grants, hfgrant.Input{
		Client:    "agent",
		Operation: string(policy.OpGitPushForce),
		Target:    "dataset/acme/repo",
		Ref:       "refs/heads/main",
		Reason:    "force push once",
		MaxUses:   1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := handler.grants.Approve(grant.ID, grant.DecisionToken, "test"); err != nil {
		t.Fatal(err)
	}
	broker := httptest.NewServer(handler)
	defer broker.Close()

	resp, _ := doRequest(t, http.MethodGet, broker.URL+"/datasets/acme/repo.git/info/refs?service=git-receive-pack", "Bearer "+testSecret, nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("denied receive-pack discovery with active grant = %d, want 403", resp.StatusCode)
	}
	if got := hits(); got != 0 {
		t.Fatalf("denied discovery reached upstream: hits=%d want 0", got)
	}
}

func TestReceivePackDeniedBeforeReadingLargePack(t *testing.T) {
	tests := []struct {
		name       string
		policyJSON string
		wantText   string
	}{
		{name: "no policy", policyJSON: emptyPolicyJSON(), wantText: "no matching policy rule"},
		{name: "request only", policyJSON: `{"rules":[{
			"id":"request-force",
			"effect":"request",
			"clients":["agent"],
			"operations":["git.push.force"],
			"targets":[{"kind":"repo","type":"dataset","owner":"acme","name":"repo"}],
			"grant_policy":{"default_minutes":5,"max_minutes":5}
		}]}`, wantText: "approval required"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			scp, err := policy.Parse([]byte(tc.policyJSON))
			if err != nil {
				t.Fatal(err)
			}
			handler, err := New(Options{
				Config: config.Config{
					HFToken:      testToken,
					Clients:      []config.Client{{Name: "agent", Secret: testSecret}},
					StateDir:     filepath.Join(t.TempDir(), "state"),
					MaxPackBytes: 16,
					HFTimeout:    10 * time.Second,
				},
				Scope:           scp,
				UpstreamBaseURL: "http://127.0.0.1:1",
			})
			if err != nil {
				t.Fatal(err)
			}
			broker := httptest.NewServer(handler)
			defer broker.Close()

			resp, body := doRequest(t, http.MethodPost, broker.URL+"/datasets/acme/repo.git/git-receive-pack", "Bearer "+testSecret, strings.NewReader(strings.Repeat("x", 1024)))
			if resp.StatusCode != http.StatusForbidden || !strings.Contains(body, tc.wantText) {
				t.Fatalf("receive-pack refusal = %d %q, want 403 containing %q", resp.StatusCode, body, tc.wantText)
			}
		})
	}
}

func TestGrantBackedReceivePackRejectionRetainsReservationAndUpdatesMessage(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	dir := t.TempDir()
	upstreamRepo := seedBareRepo(t, dir)
	upstream := newGitUpstream(t, upstreamRepo, testToken)
	defer upstream.server.Close()
	notifier := &captureGrantNotifier{}
	scp, err := policy.Parse([]byte(datasetPolicyJSON(grantableDataset("repo", policy.OpGitPushForce))))
	if err != nil {
		t.Fatal(err)
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
		UpstreamBaseURL: upstream.server.URL,
		GrantNotifier:   notifier,
	})
	if err != nil {
		t.Fatal(err)
	}
	broker := httptest.NewServer(handler)
	defer broker.Close()

	clone := filepath.Join(dir, "clone")
	runClientGit(t, dir, "clone", brokerRemoteURL(broker.URL), clone)
	runClientGit(t, clone, "config", "user.email", "agent@example.com")
	runClientGit(t, clone, "config", "user.name", "Agent")
	initial := strings.TrimSpace(runClientGit(t, clone, "rev-parse", "HEAD"))
	writeFile(t, filepath.Join(clone, "file.txt"), "two\n")
	runClientGit(t, clone, "commit", "-am", "second")
	runClientGit(t, clone, "push", "origin", "main")
	runClientGit(t, clone, "reset", "--hard", initial)

	resp, body := doRequest(t, http.MethodPost, broker.URL+"/api/grants", "Bearer "+testSecret, strings.NewReader(apiGrantRequestJSON(policy.OpGitPushForce, "refs/heads/main", "recover main", "", 0, 0)))
	if resp.StatusCode != http.StatusAccepted || len(notifier.messages) != 1 {
		t.Fatalf("grant request status=%d body=%q messages=%d, want 202 and one message", resp.StatusCode, body, len(notifier.messages))
	}
	msg := notifier.messages[0]
	answer := handler.handleTelegramDecision(context.Background(), telegramGrantDecision(notify.ActionApprove, msg))
	if answer.Answer != "Grant approved" {
		t.Fatalf("telegram answer = %+v", answer)
	}

	upstream.setRejectReceive(true)
	output, err := runClientGitErr(clone, "push", "--force", "origin", "main")
	if err == nil || !strings.Contains(output, "upstream rejected") {
		t.Fatalf("upstream-rejected force push err=%v output:\n%s", err, output)
	}
	if len(notifier.updates) != 1 || !strings.Contains(notifier.updates[0], "ambiguous") {
		t.Fatalf("grant retained-reservation updates = %+v, want ambiguous update", notifier.updates)
	}
	updated, err := handler.grants.Get(msg.GrantID)
	if err != nil {
		t.Fatalf("Get(%q) error = %v", msg.GrantID, err)
	}
	if updated.Status != grants.StatusActive || updated.ReservedCount != 1 || updated.UsedCount != 0 || !updated.ReservationRetained {
		t.Fatalf("grant after upstream rejection = %+v, want active with retained reservation", updated)
	}
	if _, ok, err := hfgrant.MatchActiveFunc(handler.grants, "agent", string(policy.OpGitPushForce), "dataset/acme/repo", "refs/heads/main", nil); err != nil || ok {
		t.Fatalf("MatchActive() after retained reservation ok=%v err=%v, want false nil", ok, err)
	}
	rejectedHits := upstream.receivePackHits()
	output, err = runClientGitErr(clone, "push", "--force", "origin", "main")
	if err == nil || !strings.Contains(output, "hf-broker") {
		t.Fatalf("retry after retained reservation err=%v output:\n%s", err, output)
	}
	if got := upstream.receivePackHits(); got != rejectedHits {
		t.Fatalf("retry after retained reservation reached upstream: hits=%d want %d", got, rejectedHits)
	}
}

func TestGrantBackedForwardErrorRetainsReservationAndUpdatesMessage(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	dir := t.TempDir()
	upstreamRepo := seedBareRepo(t, dir)
	upstream := newGitUpstream(t, upstreamRepo, testToken)
	defer upstream.server.Close()
	notifier := &captureGrantNotifier{}
	scp, err := policy.Parse([]byte(datasetPolicyJSON(grantableDataset("repo", policy.OpGitPushForce))))
	if err != nil {
		t.Fatal(err)
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
		UpstreamBaseURL: upstream.server.URL,
		GrantNotifier:   notifier,
	})
	if err != nil {
		t.Fatal(err)
	}
	broker := httptest.NewServer(handler)
	defer broker.Close()

	clone := filepath.Join(dir, "clone")
	runClientGit(t, dir, "clone", brokerRemoteURL(broker.URL), clone)
	runClientGit(t, clone, "config", "user.email", "agent@example.com")
	runClientGit(t, clone, "config", "user.name", "Agent")
	initial := strings.TrimSpace(runClientGit(t, clone, "rev-parse", "HEAD"))
	writeFile(t, filepath.Join(clone, "file.txt"), "two\n")
	runClientGit(t, clone, "commit", "-am", "second")
	runClientGit(t, clone, "push", "origin", "main")
	runClientGit(t, clone, "reset", "--hard", initial)

	resp, body := doRequest(t, http.MethodPost, broker.URL+"/api/grants", "Bearer "+testSecret, strings.NewReader(apiGrantRequestJSON(policy.OpGitPushForce, "refs/heads/main", "recover main", "", 0, 0)))
	if resp.StatusCode != http.StatusAccepted || len(notifier.messages) != 1 {
		t.Fatalf("grant request status=%d body=%q messages=%d, want 202 and one message", resp.StatusCode, body, len(notifier.messages))
	}
	msg := notifier.messages[0]
	answer := handler.handleTelegramDecision(context.Background(), telegramGrantDecision(notify.ActionApprove, msg))
	if answer.Answer != "Grant approved" {
		t.Fatalf("telegram answer = %+v", answer)
	}

	upstream.setFailReceive(true)
	output, err := runClientGitErr(clone, "push", "--force", "origin", "main")
	if err == nil || !strings.Contains(output, "HTTP 403") {
		t.Fatalf("forward-error force push err=%v output:\n%s", err, output)
	}
	if len(notifier.updates) != 1 || !strings.Contains(notifier.updates[0], "ambiguous") {
		t.Fatalf("grant forward-error updates = %+v, want ambiguous update", notifier.updates)
	}
	updated, err := handler.grants.Get(msg.GrantID)
	if err != nil {
		t.Fatalf("Get(%q) error = %v", msg.GrantID, err)
	}
	if updated.Status != grants.StatusActive || updated.ReservedCount != 1 || updated.UsedCount != 0 || !updated.ReservationRetained {
		t.Fatalf("grant after forward error = %+v, want active with retained reservation", updated)
	}
}

func TestForwardGrantClientWriteErrorRetainsReservation(t *testing.T) {
	dir := t.TempDir()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		_, _ = w.Write([]byte("upstream body"))
	}))
	defer upstream.Close()
	notifier := &captureGrantNotifier{}
	scp, err := policy.Parse([]byte(`{"rules":[{
		"id":"request-fetch",
		"effect":"request",
		"clients":["agent"],
		"operations":["git.fetch"],
		"targets":[{"kind":"repo","type":"dataset","owner":"acme","name":"repo"}],
		"grant_policy":{"default_minutes":5,"max_minutes":5,"default_max_uses":1,"max_uses":1}
	}]}`))
	if err != nil {
		t.Fatal(err)
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
		UpstreamBaseURL: upstream.URL,
		GrantNotifier:   notifier,
	})
	if err != nil {
		t.Fatal(err)
	}
	grant, _, err := requestHFGrant(handler.grants, hfgrant.Input{
		Client:    "agent",
		Operation: string(policy.OpGitFetch),
		Target:    "dataset/acme/repo",
		Reason:    "fetch once",
		MaxUses:   1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := handler.grants.SetNotification(grant.ID, notify.MessageRef{Kind: "capture", ChatID: 123, MessageID: 1, Text: "grant text"}); err != nil {
		t.Fatal(err)
	}
	if _, err := handler.grants.Approve(grant.ID, grant.DecisionToken, "test"); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/datasets/acme/repo.git/git-upload-pack", strings.NewReader("want refs"))
	req.Header.Set("Authorization", "Bearer "+testSecret)
	writer := &writeErrorResponseWriter{}
	handler.ServeHTTP(writer, req)

	updated, err := handler.grants.Get(grant.ID)
	if err != nil {
		t.Fatal(err)
	}
	if updated.Status != grants.StatusActive || updated.ReservedCount != 1 || updated.UsedCount != 0 || !updated.ReservationRetained {
		t.Fatalf("grant after client write error = %+v, want active with retained reservation", updated)
	}
	if len(notifier.updates) != 1 || !strings.Contains(notifier.updates[0], "ambiguous") {
		t.Fatalf("grant client-write updates = %+v, want ambiguous update", notifier.updates)
	}
}

func TestGrantRequestAcceptsConfiguredGitCapabilities(t *testing.T) {
	dir := t.TempDir()
	notifier := &captureGrantNotifier{}
	scp, err := policy.Parse([]byte(datasetPolicyJSON(grantableDataset("repo", policy.OpGitPushForce, policy.OpGitRefDelete, policy.OpGitTagUpdate))))
	if err != nil {
		t.Fatal(err)
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
		UpstreamBaseURL: "http://127.0.0.1:1",
		GrantNotifier:   notifier,
	})
	if err != nil {
		t.Fatal(err)
	}
	broker := httptest.NewServer(handler)
	defer broker.Close()

	tests := []struct {
		operation string
		ref       string
	}{
		{operation: "git.push.force", ref: "refs/heads/main"},
		{operation: "git.ref.delete", ref: "refs/heads/feature"},
		{operation: "git.tag.update", ref: "refs/tags/v1"},
	}
	for i, tc := range tests {
		body := apiGrantRequestJSON(policy.Operation(tc.operation), tc.ref, "recover", tc.operation, 0, 0)
		resp, text := doRequest(t, http.MethodPost, broker.URL+"/api/grants", "Bearer "+testSecret, strings.NewReader(body))
		if resp.StatusCode != http.StatusAccepted {
			t.Fatalf("%s grant request = %d %q, want 202", tc.operation, resp.StatusCode, text)
		}
		if len(notifier.messages) != i+1 || notifier.messages[i].Operation != tc.operation {
			t.Fatalf("notifier messages = %+v, want operation %s at index %d", notifier.messages, tc.operation, i)
		}
	}

	invalid := []struct {
		operation string
		ref       string
	}{
		{operation: "git.push.force", ref: "refs/tags/v1"},
		{operation: "git.push.force", ref: "refs/replace/abc"},
		{operation: "git.ref.delete", ref: "refs/tags/v1"},
		{operation: "git.ref.delete", ref: "refs/replace/abc"},
		{operation: "git.tag.update", ref: "refs/heads/main"},
	}
	for _, tc := range invalid {
		body := apiGrantRequestJSON(policy.Operation(tc.operation), tc.ref, "recover", "", 0, 0)
		resp, _ := doRequest(t, http.MethodPost, broker.URL+"/api/grants", "Bearer "+testSecret, strings.NewReader(body))
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("%s grant request for %s = %d, want 400", tc.operation, tc.ref, resp.StatusCode)
		}
	}
}

func TestGrantRequestAcceptsAppendPushWhenRequestable(t *testing.T) {
	dir := t.TempDir()
	notifier := &captureGrantNotifier{}
	scp, err := policy.Parse([]byte(datasetPolicyJSON(testDatasetPolicy{
		name:       "repo",
		requestOps: []policy.Operation{policy.OpGitPushAppend},
	})))
	if err != nil {
		t.Fatal(err)
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
		UpstreamBaseURL: "http://127.0.0.1:1",
		GrantNotifier:   notifier,
	})
	if err != nil {
		t.Fatal(err)
	}
	broker := httptest.NewServer(handler)
	defer broker.Close()

	body := apiGrantRequestJSON(policy.OpGitPushAppend, "refs/heads/main", "append once", "append-once", 0, 0)
	resp, text := doRequest(t, http.MethodPost, broker.URL+"/api/grants", "Bearer "+testSecret, strings.NewReader(body))
	if resp.StatusCode != http.StatusAccepted || len(notifier.messages) != 1 {
		t.Fatalf("append grant request = %d %s messages=%d, want 202 and one message", resp.StatusCode, text, len(notifier.messages))
	}

	body = apiGrantRequestJSON(policy.OpGitPushAppend, "refs/replace/abc", "append replace", "", 0, 0)
	resp, _ = doRequest(t, http.MethodPost, broker.URL+"/api/grants", "Bearer "+testSecret, strings.NewReader(body))
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("append grant for replace ref = %d, want 400", resp.StatusCode)
	}
}

func TestGrantRequestErrors(t *testing.T) {
	dir := t.TempDir()
	var auditLog bytes.Buffer
	scp, err := policy.Parse([]byte(datasetPolicyJSON(grantableDatasetWithBounds("repo", map[string]int{"max_uses": 2}, policy.OpGitPushForce))))
	if err != nil {
		t.Fatal(err)
	}
	baseCfg := config.Config{
		HFToken:      testToken,
		Clients:      []config.Client{{Name: "agent", Secret: testSecret}},
		StateDir:     filepath.Join(dir, "state"),
		MaxPackBytes: 25 * 1024 * 1024,
		HFTimeout:    10 * time.Second,
	}
	handler, err := New(Options{Config: baseCfg, Scope: scp, Audit: audit.New(&auditLog), UpstreamBaseURL: "http://127.0.0.1:1"})
	if err != nil {
		t.Fatal(err)
	}
	broker := httptest.NewServer(handler)
	defer broker.Close()
	validBody := apiGrantRequestJSON(policy.OpGitPushForce, "refs/heads/main", "recover", "without-notifier", 5, 0)
	resp, _ := doRequest(t, http.MethodPost, broker.URL+"/api/grants", "Bearer "+testSecret, strings.NewReader(validBody))
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("grant without approval channel = %d, want 503", resp.StatusCode)
	}
	baseCfg.Operators = []config.Client{{Name: "operator", Secret: "operator-secret-abcdefghijklmnopqrstuvwxyz"}}
	handler, err = New(Options{Config: baseCfg, Scope: scp, Audit: audit.New(&auditLog), UpstreamBaseURL: "http://127.0.0.1:1"})
	if err != nil {
		t.Fatal(err)
	}
	broker.Config.Handler = handler
	resp, _ = doRequest(t, http.MethodPost, broker.URL+"/api/grants", "Bearer "+testSecret, strings.NewReader(validBody))
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("grant with operator inbox = %d, want 202", resp.StatusCode)
	}

	notifier := &captureGrantNotifier{}
	handler, err = New(Options{Config: baseCfg, Scope: scp, Audit: audit.New(&auditLog), UpstreamBaseURL: "http://127.0.0.1:1", GrantNotifier: notifier})
	if err != nil {
		t.Fatal(err)
	}
	broker.Config.Handler = handler
	beforeBadTargetAudit := auditLog.Len()
	resp, _ = doRequest(t, http.MethodPost, broker.URL+"/api/grants", "Bearer "+testSecret, strings.NewReader(fmt.Sprintf(`{"operation":"git.push.force","target":%q,"reason":"recover","client_request_id":"bad-target"}`, testSecret)))
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("bad target status = %d, want 400", resp.StatusCode)
	}
	if got := auditLog.String()[beforeBadTargetAudit:]; strings.Contains(got, testSecret) || !strings.Contains(got, `"target":""`) {
		t.Fatalf("bad grant target audit leaked request body or missed empty target:\n%s", got)
	}
	attrMarker := "secret_attr_marker"
	resp, body := doRequest(t, http.MethodPost, broker.URL+"/api/grants", "Bearer "+testSecret, strings.NewReader(fmt.Sprintf(
		`{"operation":"git.push.force","target":{"kind":"repo","type":"dataset","owner":"acme","name":"repo","refs":["refs/heads/main"]},"attrs":{%q:"value"},"reason":"recover","client_request_id":"unknown-attr-marker"}`,
		attrMarker,
	)))
	if resp.StatusCode != http.StatusBadRequest || decodeJSendFailReason(t, body) != "invalid_attrs" {
		t.Fatalf("unknown attrs = %d %s, want 400 invalid_attrs", resp.StatusCode, body)
	}
	if strings.Contains(body, attrMarker) || strings.Contains(body, "value") {
		t.Fatalf("invalid attrs response leaked request attrs: %s", body)
	}
	tests := []struct {
		name   string
		method string
		body   string
		want   int
	}{
		{name: "wrong method", method: http.MethodPut, want: http.StatusMethodNotAllowed},
		{name: "bad json", method: http.MethodPost, body: `{`, want: http.StatusBadRequest},
		{name: "trailing json", method: http.MethodPost, body: validBody + `{}`, want: http.StatusBadRequest},
		{name: "missing client request id", method: http.MethodPost, body: `{"operation":"git.push.force","target":{"kind":"repo","type":"dataset","owner":"acme","name":"repo","refs":["refs/heads/main"]},"reason":"recover"}`, want: http.StatusBadRequest},
		{name: "bad operation", method: http.MethodPost, body: apiGrantRequestJSON(policy.Operation("git.upload_pack"), "refs/heads/main", "recover", "", 0, 0), want: http.StatusBadRequest},
		{name: "transport operation", method: http.MethodPost, body: apiGrantRequestJSON(policy.Operation("git.receive-pack"), "refs/heads/main", "recover", "", 0, 0), want: http.StatusBadRequest},
		{name: "unknown attrs", method: http.MethodPost, body: `{"operation":"git.push.force","target":{"kind":"repo","type":"dataset","owner":"acme","name":"repo","refs":["refs/heads/main"]},"attrs":{"unknown":"value"},"reason":"recover","client_request_id":"unknown-attrs"}`, want: http.StatusBadRequest},
		{name: "target paths", method: http.MethodPost, body: `{"operation":"repo.contents.read","target":{"kind":"repo","type":"dataset","owner":"acme","name":"repo","paths":["README.md"]},"reason":"read one file","client_request_id":"target-paths"}`, want: http.StatusBadRequest},
		{name: "wildcard target", method: http.MethodPost, body: `{"operation":"git.push.force","target":{"kind":"repo","type":"dataset","owner":"acme","name":"*","refs":["refs/heads/main"]},"reason":"recover","client_request_id":"wildcard-target"}`, want: http.StatusBadRequest},
		{name: "bucket target", method: http.MethodPost, body: `{"operation":"bucket.object.read","target":{"kind":"bucket","owner":"acme","name":"artifacts","keys":["runs/one"]},"reason":"read one object","client_request_id":"bucket-target"}`, want: http.StatusBadRequest},
		{name: "unconfigured capability", method: http.MethodPost, body: apiGrantRequestJSON(policy.OpGitRefDelete, "refs/heads/main", "recover", "", 0, 0), want: http.StatusForbidden},
		{name: "bad ref", method: http.MethodPost, body: apiGrantRequestJSON(policy.OpGitPushForce, "main", "recover", "", 0, 0), want: http.StatusBadRequest},
		{name: "out of scope", method: http.MethodPost, body: apiGrantRequestForRepoJSON(policy.OpGitPushForce, "other", "refs/heads/main", "recover", "", 0, 0), want: http.StatusForbidden},
		{name: "negative minutes", method: http.MethodPost, body: apiGrantRequestJSON(policy.OpGitPushForce, "refs/heads/main", "recover", "", -1, 0), want: http.StatusBadRequest},
		{name: "too many minutes", method: http.MethodPost, body: apiGrantRequestJSON(policy.OpGitPushForce, "refs/heads/main", "recover", "", 61, 0), want: http.StatusBadRequest},
		{name: "negative max uses", method: http.MethodPost, body: apiGrantRequestJSON(policy.OpGitPushForce, "refs/heads/main", "recover", "", 0, -1), want: http.StatusBadRequest},
		{name: "too many uses", method: http.MethodPost, body: apiGrantRequestJSON(policy.OpGitPushForce, "refs/heads/main", "recover", "", 0, 3), want: http.StatusBadRequest},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp, _ := doRequest(t, tc.method, broker.URL+"/api/grants", "Bearer "+testSecret, strings.NewReader(tc.body))
			if resp.StatusCode != tc.want {
				t.Fatalf("status = %d, want %d", resp.StatusCode, tc.want)
			}
		})
	}

	baseCfg.Operators = nil
	handler, err = New(Options{Config: baseCfg, Scope: scp, Audit: audit.New(&auditLog), UpstreamBaseURL: "http://127.0.0.1:1", GrantNotifier: failingGrantNotifier{}})
	if err != nil {
		t.Fatal(err)
	}
	broker.Config.Handler = handler
	resp, _ = doRequest(t, http.MethodPost, broker.URL+"/api/grants", "Bearer "+testSecret, strings.NewReader(validBody))
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("notifier failure status = %d, want 502", resp.StatusCode)
	}
}

func TestOperatorInboxSurvivesTelegramNotificationFailure(t *testing.T) {
	dir := t.TempDir()
	scp, err := policy.Parse([]byte(datasetPolicyJSON(grantableDataset("repo", policy.OpGitPushForce))))
	if err != nil {
		t.Fatal(err)
	}
	handler, err := New(Options{
		Config: config.Config{
			HFToken: testToken, Clients: []config.Client{{Name: "agent", Secret: testSecret}},
			Operators: []config.Client{{Name: "operator", Secret: "operator-secret-abcdefghijklmnopqrstuvwxyz"}},
			StateDir:  filepath.Join(dir, "state"), MaxPackBytes: 25 * 1024 * 1024, HFTimeout: 10 * time.Second,
		},
		Scope: scp, UpstreamBaseURL: "http://127.0.0.1:1", GrantNotifier: failingGrantNotifier{},
	})
	if err != nil {
		t.Fatal(err)
	}
	broker := httptest.NewServer(handler)
	defer broker.Close()
	body := apiGrantRequestJSON(policy.OpGitPushForce, "refs/heads/main", "recover", "telegram-failed-inbox-pending", 5, 0)
	resp, responseBody := doRequest(t, http.MethodPost, broker.URL+"/api/grants", "Bearer "+testSecret, strings.NewReader(body))
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("grant request = %d %s, want 202", resp.StatusCode, responseBody)
	}
	stored := decodeAPIGrantResponse(t, responseBody)
	grant, err := handler.grants.Get(stored.ID)
	if err != nil || grant.Status != grants.StatusPending || !grant.NotificationDeliveryUnresolved {
		t.Fatalf("stored grant = %+v, err=%v", grant, err)
	}
}

func TestDeniedGrantDecisionResult(t *testing.T) {
	tests := []struct {
		name       string
		decision   policy.Decision
		wantStatus int
		wantReason string
	}{
		{name: "invalid operation", decision: policy.Decision{Reason: "invalid_operation"}, wantStatus: http.StatusBadRequest, wantReason: "invalid_operation"},
		{name: "invalid target", decision: policy.Decision{Reason: "invalid_target"}, wantStatus: http.StatusBadRequest, wantReason: "invalid_target"},
		{name: "policy denied", decision: policy.Decision{Reason: "policy_denied"}, wantStatus: http.StatusForbidden, wantReason: "policy_denied"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, status, reason, message := deniedGrantDecisionResult(tc.decision)
			if status != tc.wantStatus || reason != tc.wantReason || message == "" {
				t.Fatalf("deniedGrantDecisionResult() = status %d reason %q message %q", status, reason, message)
			}
		})
	}
}

func TestValidateGrantTargetForOperation(t *testing.T) {
	repo := policy.Target{Kind: policy.KindRepo, Type: policy.TypeDataset, Owner: "acme", Name: "repo"}
	tests := []struct {
		name      string
		operation policy.Operation
		target    policy.Target
		wantErr   bool
	}{
		{name: "force with ref", operation: policy.OpGitPushForce, target: policy.Target{Kind: policy.KindRepo, Type: policy.TypeDataset, Owner: "acme", Name: "repo", Refs: []string{"refs/heads/main"}}},
		{name: "fetch without ref", operation: policy.OpGitFetch, target: repo},
		{name: "force missing ref", operation: policy.OpGitPushForce, target: repo, wantErr: true},
		{name: "fetch with ref", operation: policy.OpGitFetch, target: policy.Target{Kind: policy.KindRepo, Type: policy.TypeDataset, Owner: "acme", Name: "repo", Refs: []string{"refs/heads/main"}}, wantErr: true},
		{name: "path constraint", operation: policy.OpRepoContentsRead, target: policy.Target{Kind: policy.KindRepo, Type: policy.TypeDataset, Owner: "acme", Name: "repo", Paths: []string{"README.md"}}, wantErr: true},
		{name: "bucket target", operation: policy.OpBucketObjectRead, target: policy.Target{Kind: policy.KindBucket, Owner: "acme", Name: "artifacts", Keys: []string{"runs/one"}}, wantErr: true},
		{name: "bad repo identity", operation: policy.OpGitFetch, target: policy.Target{Kind: policy.KindRepo, Type: policy.TypeAny, Owner: "acme", Name: "repo"}, wantErr: true},
		{name: "wildcard owner", operation: policy.OpGitFetch, target: policy.Target{Kind: policy.KindRepo, Type: policy.TypeDataset, Owner: "*", Name: "repo"}, wantErr: true},
		{name: "wildcard name", operation: policy.OpGitFetch, target: policy.Target{Kind: policy.KindRepo, Type: policy.TypeDataset, Owner: "acme", Name: "*"}, wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateGrantTargetForOperation(tc.operation, tc.target)
			if (err != nil) != tc.wantErr {
				t.Fatalf("validateGrantTargetForOperation() error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

func TestAPIGrantsUseJSendAndClientScopedReads(t *testing.T) {
	dir := t.TempDir()
	notifier := &captureGrantNotifier{}
	var auditLog bytes.Buffer
	scp, err := policy.Parse([]byte(datasetPolicyJSON(grantableDataset("repo", policy.OpGitPushForce))))
	if err != nil {
		t.Fatal(err)
	}
	handler, err := New(Options{
		Config: config.Config{
			HFToken: testToken,
			Clients: []config.Client{
				{Name: "agent", Secret: testSecret},
				{Name: "other", Secret: testOtherSecret},
			},
			StateDir:     filepath.Join(dir, "state"),
			MaxPackBytes: 25 * 1024 * 1024,
			HFTimeout:    10 * time.Second,
		},
		Scope:           scp,
		Audit:           audit.New(&auditLog),
		UpstreamBaseURL: "http://127.0.0.1:1",
		GrantNotifier:   notifier,
	})
	if err != nil {
		t.Fatal(err)
	}
	broker := httptest.NewServer(handler)
	defer broker.Close()

	resp, body := doRequest(t, http.MethodGet, broker.URL+"/api/grants", "", nil)
	if resp.StatusCode != http.StatusUnauthorized || decodeJSendFailReason(t, body) != "missing_auth" {
		t.Fatalf("missing auth = %d %s, want 401 missing_auth", resp.StatusCode, body)
	}

	body = apiGrantRequestJSON(policy.OpGitPushForce, "refs/heads/main", "recover", "api-idempotent", 5, 0)
	resp, body = doRequest(t, http.MethodPost, broker.URL+"/api/grants", "Bearer "+testSecret, strings.NewReader(body))
	if resp.StatusCode != http.StatusAccepted || decodeJSendStatus(t, body) != "success" {
		t.Fatalf("grant create = %d %s, want 202 success", resp.StatusCode, body)
	}
	if len(notifier.messages) != 1 || strings.Contains(body, notifier.messages[0].DecisionToken) {
		t.Fatalf("grant create messages=%+v body=%s, want one message and no decision token leak", notifier.messages, body)
	}
	created := decodeAPIGrantResponse(t, body)
	if created.Operation != string(policy.OpGitPushForce) || len(created.Target.Refs) != 1 || created.Target.Refs[0] != "refs/heads/main" {
		t.Fatalf("created grant = %+v, want force grant for main", created)
	}
	if created.PendingUntil == nil || created.ExpiresAt != nil {
		t.Fatalf("created grant times = pending_until %v expires_at %v, want pending only", created.PendingUntil, created.ExpiresAt)
	}

	resp, body = doRequest(t, http.MethodGet, broker.URL+"/api/grants/"+created.ID, "Bearer "+testSecret, nil)
	if resp.StatusCode != http.StatusOK || decodeAPIGrantResponse(t, body).ID != created.ID {
		t.Fatalf("grant get = %d %s, want created grant", resp.StatusCode, body)
	}
	resp, body = doRequest(t, http.MethodGet, broker.URL+"/api/grants", "Bearer "+testSecret, nil)
	if resp.StatusCode != http.StatusOK || len(decodeAPIGrantList(t, body)) != 1 {
		t.Fatalf("grant list = %d %s, want one grant", resp.StatusCode, body)
	}
	resp, body = doRequest(t, http.MethodGet, broker.URL+"/api/grants?status=bogus", "Bearer "+testSecret, nil)
	if resp.StatusCode != http.StatusBadRequest || decodeJSendFailReason(t, body) != "validation_failed" {
		t.Fatalf("bad grant list status filter = %d %s, want 400 validation_failed", resp.StatusCode, body)
	}
	resp, body = doRequest(t, http.MethodGet, broker.URL+"/api/grants/"+created.ID, "Bearer "+testOtherSecret, nil)
	if resp.StatusCode != http.StatusNotFound || decodeJSendFailReason(t, body) != "grant_not_found" {
		t.Fatalf("cross-client grant get = %d %s, want 404 grant_not_found", resp.StatusCode, body)
	}

	conflictBody := apiGrantRequestJSON(policy.OpGitPushForce, "refs/heads/main", "different reason", "api-idempotent", 5, 0)
	resp, body = doRequest(t, http.MethodPost, broker.URL+"/api/grants", "Bearer "+testSecret, strings.NewReader(conflictBody))
	if resp.StatusCode != http.StatusConflict || decodeJSendFailReason(t, body) != "idempotency_conflict" {
		t.Fatalf("idempotency conflict = %d %s, want 409 idempotency_conflict", resp.StatusCode, body)
	}
	assertAuditContains(t, auditLog.String(),
		`"operation":"grant_read"`,
		`"target":"`+created.ID+`"`,
		`"operation":"grant_list"`,
		`"target":"grants"`,
		`"client":"other"`,
		`"reason":"grant_not_found"`,
		`"reason":"validation_failed"`,
	)
}

func assertAuditContains(t *testing.T, auditText string, values ...string) {
	t.Helper()
	for _, value := range values {
		if !strings.Contains(auditText, value) {
			t.Fatalf("audit missing %s:\n%s", value, auditText)
		}
	}
}

func TestAPIGrantResponsesPersistGrantMode(t *testing.T) {
	dir := t.TempDir()
	notifier := &captureGrantNotifier{}
	scp, err := policy.Parse([]byte(`{"rules":[{
		"id":"request-force-execution",
		"effect":"request",
		"clients":["agent"],
		"operations":["git.push.force"],
		"targets":[{"kind":"repo","type":"dataset","owner":"acme","name":"repo"}],
		"grant_policy":{"mode":"execution","default_minutes":5,"max_minutes":5}
	}]}`))
	if err != nil {
		t.Fatal(err)
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
		UpstreamBaseURL: "http://127.0.0.1:1",
		GrantNotifier:   notifier,
	})
	if err != nil {
		t.Fatal(err)
	}
	broker := httptest.NewServer(handler)
	defer broker.Close()

	resp, body := doRequest(t, http.MethodPost, broker.URL+"/api/grants", "Bearer "+testSecret, strings.NewReader(apiGrantRequestJSON(policy.OpGitPushForce, "refs/heads/main", "recover", "", 0, 0)))
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("grant create = %d %s, want 202", resp.StatusCode, body)
	}
	created := decodeAPIGrantResponse(t, body)
	if created.Mode != policy.GrantModeExecution {
		t.Fatalf("created grant mode = %q, want execution", created.Mode)
	}

	resp, body = doRequest(t, http.MethodGet, broker.URL+"/api/grants/"+created.ID, "Bearer "+testSecret, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("grant get = %d %s, want 200", resp.StatusCode, body)
	}
	if got := decodeAPIGrantResponse(t, body).Mode; got != policy.GrantModeExecution {
		t.Fatalf("get grant mode = %q, want execution", got)
	}

	resp, body = doRequest(t, http.MethodGet, broker.URL+"/api/grants", "Bearer "+testSecret, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("grant list = %d %s, want 200", resp.StatusCode, body)
	}
	listed := decodeAPIGrantList(t, body)
	if len(listed) != 1 || listed[0].Mode != policy.GrantModeExecution {
		t.Fatalf("listed grants = %+v, want one execution grant", listed)
	}
}

func TestGrantExpiresAtStringPtrOmitsNeverActiveExpiredGrant(t *testing.T) {
	expiresAt := time.Date(2026, 7, 8, 12, 0, 0, 0, time.UTC)
	if got := grantExpiresAtStringPtr(grants.Grant{Status: grants.StatusExpired, ExpiredFrom: grants.StatusPending, ExpiresAt: expiresAt}); got != nil {
		t.Fatalf("pending-expired grant expires_at = %q, want nil", *got)
	}
	if got := grantExpiresAtStringPtr(grants.Grant{Status: grants.StatusExpired, ExpiredFrom: grants.StatusActive, ExpiresAt: expiresAt}); got == nil {
		t.Fatalf("active-expired grant expires_at = nil, want timestamp")
	}
}

func TestAPIGrantNotifierFailureIsJSend(t *testing.T) {
	dir := t.TempDir()
	scp, err := policy.Parse([]byte(datasetPolicyJSON(grantableDataset("repo", policy.OpGitPushForce))))
	if err != nil {
		t.Fatal(err)
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
		UpstreamBaseURL: "http://127.0.0.1:1",
		GrantNotifier:   failingGrantNotifier{},
	})
	if err != nil {
		t.Fatal(err)
	}
	broker := httptest.NewServer(handler)
	defer broker.Close()

	resp, body := doRequest(t, http.MethodPost, broker.URL+"/api/grants", "Bearer "+testSecret, strings.NewReader(apiGrantRequestJSON(policy.OpGitPushForce, "refs/heads/main", "recover", "", 0, 0)))
	if resp.StatusCode != http.StatusBadGateway || decodeJSendStatus(t, body) != "error" || !strings.HasPrefix(resp.Header.Get("Content-Type"), "application/json") {
		t.Fatalf("notifier failure = %d %q %s, want 502 JSend error", resp.StatusCode, resp.Header.Get("Content-Type"), body)
	}
	stored, err := handler.grants.ListForClient("agent")
	if err != nil || len(stored) != 1 || !stored[0].NotificationDeliveryUnresolved || stored[0].NotificationClaimedAt.IsZero() {
		t.Fatalf("stored notifier failure = %+v err=%v, want one unresolved claim", stored, err)
	}
}

func TestGrantNotificationWaitState(t *testing.T) {
	tests := []struct {
		name  string
		grant grants.Grant
		want  error
	}{
		{name: "canceled", grant: grants.Grant{Status: grants.StatusCanceled}, want: errGrantNotificationCanceled},
		{name: "unresolved", grant: grants.Grant{Status: grants.StatusPending, NotificationDeliveryUnresolved: true}, want: errGrantNotificationUnresolved},
		{name: "queued", grant: grants.Grant{Status: grants.StatusPending}, want: errGrantNotificationStillQueued},
		{name: "notified", grant: grants.Grant{Status: grants.StatusPending, Notification: &grants.MessageRef{MessageID: 1}}},
		{name: "terminal", grant: grants.Grant{Status: grants.StatusDenied}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := grantNotificationWaitState(test.grant); !errors.Is(got, test.want) || (got == nil) != (test.want == nil) {
				t.Fatalf("grantNotificationWaitState() = %v, want %v", got, test.want)
			}
		})
	}
}

func TestUnresolvedNotifierFailureSurvivesRestartAndRetriesAfterLease(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 7, 10, 7, 0, 0, 0, time.UTC)
	var nowMu sync.Mutex
	nowFunc := func() time.Time {
		nowMu.Lock()
		defer nowMu.Unlock()
		return now
	}
	advanceNow := func(duration time.Duration) {
		nowMu.Lock()
		defer nowMu.Unlock()
		now = now.Add(duration)
	}
	notifier := newBlockingGrantNotifier()
	notifier.firstErr = errors.New("notify failed")
	notifier.releaseSend()
	scp, err := policy.Parse([]byte(datasetPolicyJSON(grantableDataset("repo", policy.OpGitPushForce))))
	if err != nil {
		t.Fatal(err)
	}
	stateDir := filepath.Join(dir, "state")
	grantPath := filepath.Join(stateDir, "grants", "grants.json")
	newHandler := func() *Server {
		handler, err := New(Options{
			Config: config.Config{
				HFToken:      testToken,
				Clients:      []config.Client{{Name: "agent", Secret: testSecret}},
				StateDir:     stateDir,
				MaxPackBytes: 25 * 1024 * 1024,
				HFTimeout:    10 * time.Second,
			},
			Scope:           scp,
			UpstreamBaseURL: "http://127.0.0.1:1",
			GrantNotifier:   notifier,
		})
		if err != nil {
			t.Fatal(err)
		}
		handler.grants = grants.New(grantPath, grants.Options{Now: nowFunc})
		return handler
	}
	body := apiGrantRequestJSON(policy.OpGitPushForce, "refs/heads/main", "recover", "restart-unresolved", 0, 0)

	firstBroker := httptest.NewServer(newHandler())
	resp, responseBody := doRequest(t, http.MethodPost, firstBroker.URL+"/api/grants", "Bearer "+testSecret, strings.NewReader(body))
	firstBroker.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("first request status=%d body=%q, want 502", resp.StatusCode, responseBody)
	}
	if notifier.calls() != 1 {
		t.Fatalf("first notifier calls = %d, want one", notifier.calls())
	}

	restartedHandler := newHandler()
	restartedBroker := httptest.NewServer(restartedHandler)
	defer restartedBroker.Close()
	started := time.Now()
	resp, responseBody = doRequest(t, http.MethodPost, restartedBroker.URL+"/api/grants", "Bearer "+testSecret, strings.NewReader(body))
	if resp.StatusCode != http.StatusBadGateway || time.Since(started) >= time.Second {
		t.Fatalf("restart request status=%d elapsed=%s body=%q, want prompt 502", resp.StatusCode, time.Since(started), responseBody)
	}
	if notifier.calls() != 1 {
		t.Fatalf("restart notifier calls = %d, want no duplicate", notifier.calls())
	}

	advanceNow(grantNotificationClaimLease + time.Second)
	resp, responseBody = doRequest(t, http.MethodPost, restartedBroker.URL+"/api/grants", "Bearer "+testSecret, strings.NewReader(body))
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("post-lease retry status=%d body=%q, want 202", resp.StatusCode, responseBody)
	}
	if notifier.calls() != 2 {
		t.Fatalf("post-lease notifier calls = %d, want two", notifier.calls())
	}
	tokens := notifier.decisionTokens()
	if len(tokens) != 2 || tokens[0] == "" || tokens[0] == tokens[1] {
		t.Fatalf("notification tokens = %+v, want two distinct non-empty tokens", tokens)
	}
	stored, err := restartedHandler.grants.ListForClient("agent")
	if err != nil || len(stored) != 1 || stored[0].Notification == nil || stored[0].NotificationDeliveryUnresolved {
		t.Fatalf("stored post-lease grant = %+v err=%v", stored, err)
	}
}

func TestApprovedGrantAllowsForwardedFetch(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	dir := t.TempDir()
	upstreamRepo := seedBareRepo(t, dir)
	upstream := newGitUpstream(t, upstreamRepo, testToken)
	defer upstream.server.Close()
	notifier := &captureGrantNotifier{}
	var auditLog bytes.Buffer
	scp, err := policy.Parse([]byte(`{"rules":[{
		"id":"request-fetch",
		"effect":"request",
		"clients":["agent"],
		"operations":["git.fetch"],
		"targets":[{"kind":"repo","type":"dataset","owner":"acme","name":"repo"}],
		"grant_policy":{"default_minutes":5,"max_minutes":5,"default_max_uses":1,"max_uses":1}
	}]}`))
	if err != nil {
		t.Fatal(err)
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
		Audit:           audit.New(&auditLog),
		UpstreamBaseURL: upstream.server.URL,
		GrantNotifier:   notifier,
	})
	if err != nil {
		t.Fatal(err)
	}
	broker := httptest.NewServer(handler)
	defer broker.Close()
	infoRefs := broker.URL + "/datasets/acme/repo.git/info/refs?service=git-upload-pack"

	beforeGrant := upstream.totalHits()
	resp, _ := doRequest(t, http.MethodGet, infoRefs, "Bearer "+testSecret, nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("fetch before grant = %d, want 403", resp.StatusCode)
	}
	if got := upstream.totalHits(); got != beforeGrant {
		t.Fatalf("fetch before grant reached upstream: hits=%d want %d", got, beforeGrant)
	}

	body := apiGrantRequestJSON(policy.OpGitFetch, "", "read once", "fetch-once", 0, 0)
	resp, text := doRequest(t, http.MethodPost, broker.URL+"/api/grants", "Bearer "+testSecret, strings.NewReader(body))
	if resp.StatusCode != http.StatusAccepted || len(notifier.messages) != 1 {
		t.Fatalf("fetch grant request = %d %s messages=%d, want 202 and one message", resp.StatusCode, text, len(notifier.messages))
	}
	msg := notifier.messages[0]
	answer := handler.handleTelegramDecision(context.Background(), telegramGrantDecision(notify.ActionApprove, msg))
	if answer.Answer != "Grant approved" {
		t.Fatalf("grant approval answer = %+v", answer)
	}

	resp, _ = doRequest(t, http.MethodGet, infoRefs, "Bearer "+testSecret, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("fetch with grant = %d, want 200", resp.StatusCode)
	}
	active, err := handler.grants.Get(msg.GrantID)
	if err != nil {
		t.Fatal(err)
	}
	if active.Status != grants.StatusActive || active.UsedCount != 0 {
		t.Fatalf("grant after upload-pack discovery = %+v, want active and unused", active)
	}

	clone := filepath.Join(dir, "clone")
	runClientGit(t, dir, "clone", brokerRemoteURL(broker.URL), clone)
	used, err := handler.grants.Get(msg.GrantID)
	if err != nil {
		t.Fatal(err)
	}
	if used.Status != grants.StatusConsumed || used.UsedCount != 1 {
		t.Fatalf("grant after fetch RPC = %+v, want consumed once", used)
	}
	assertAuditContains(t, auditLog.String(),
		`"decision":"grant-used"`,
		`"grant_id":"`+msg.GrantID+`"`,
		`"matched_grant_rule_ids":["`+msg.GrantID+`"]`,
	)
}

func TestApprovedGrantAllowsOneLFSDownloadAction(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	dir := t.TempDir()
	upstreamRepo := seedBareRepo(t, dir)
	upstream := newGitUpstream(t, upstreamRepo, testToken)
	defer upstream.server.Close()
	notifier := &captureGrantNotifier{}
	scp, err := policy.Parse([]byte(`{"rules":[{
		"id":"request-content-read",
		"effect":"request",
		"clients":["agent"],
		"operations":["repo.contents.read"],
		"targets":[{"kind":"repo","type":"dataset","owner":"acme","name":"repo"}],
		"grant_policy":{"default_minutes":5,"max_minutes":5,"default_max_uses":1,"max_uses":1}
	}]}`))
	if err != nil {
		t.Fatal(err)
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
		UpstreamBaseURL: upstream.server.URL,
		GrantNotifier:   notifier,
	})
	if err != nil {
		t.Fatal(err)
	}
	broker := httptest.NewServer(handler)
	defer broker.Close()

	oid := strings.Repeat("b", 64)
	batchURL := broker.URL + "/datasets/acme/repo/info/lfs/objects/batch"
	beforeGrant := upstream.totalHits()
	resp, _ := doRequest(t, http.MethodPost, batchURL, "Bearer "+testSecret, strings.NewReader(fmt.Sprintf(`{"operation":"download","objects":[{"oid":%q,"size":123}]}`, oid)))
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("LFS batch before grant = %d, want 403", resp.StatusCode)
	}
	if got := upstream.totalHits(); got != beforeGrant {
		t.Fatalf("LFS batch before grant reached upstream: hits=%d want %d", got, beforeGrant)
	}

	grantBody := apiGrantRequestJSON(policy.OpRepoContentsRead, "", "download one LFS object", "lfs-download", 0, 0)
	resp, text := doRequest(t, http.MethodPost, broker.URL+"/api/grants", "Bearer "+testSecret, strings.NewReader(grantBody))
	if resp.StatusCode != http.StatusAccepted || len(notifier.messages) != 1 {
		t.Fatalf("LFS grant request = %d %s messages=%d, want 202 and one message", resp.StatusCode, text, len(notifier.messages))
	}
	msg := notifier.messages[0]
	answer := handler.handleTelegramDecision(context.Background(), telegramGrantDecision(notify.ActionApprove, msg))
	if answer.Answer != "Grant approved" {
		t.Fatalf("grant approval answer = %+v", answer)
	}

	resp, body := doRequest(t, http.MethodPost, batchURL, "Bearer "+testSecret, strings.NewReader(fmt.Sprintf(`{"operation":"download","objects":[{"oid":%q,"size":123}]}`, oid)))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("LFS batch with grant = %d %s, want 200", resp.StatusCode, body)
	}
	actionHref := assertLFSActionHref(t, body, "download", broker.URL+"/datasets/acme/repo.git/info/lfs/objects/"+oid)
	active, err := handler.grants.Get(msg.GrantID)
	if err != nil {
		t.Fatal(err)
	}
	if active.Status != grants.StatusActive || active.UsedCount != 0 {
		t.Fatalf("grant after LFS batch = %+v, want active and unused", active)
	}

	beforeInvalidAction := upstream.totalHits()
	resp, body = doRequest(t, http.MethodGet, broker.URL+"/datasets/acme/repo.git/info/lfs/objects/"+oid+"?"+lfsActionQuery+"=missing", "Bearer "+testSecret, nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("invalid LFS action with grant = %d %s, want 403", resp.StatusCode, body)
	}
	if !strings.Contains(body, errInvalidLFSAction.Error()) || strings.Contains(body, "upstream request failed") {
		t.Fatalf("invalid LFS action body = %q, want invalid-action response only", body)
	}
	if got := upstream.totalHits(); got != beforeInvalidAction {
		t.Fatalf("invalid LFS action with grant reached upstream: hits=%d want %d", got, beforeInvalidAction)
	}
	active, err = handler.grants.Get(msg.GrantID)
	if err != nil {
		t.Fatal(err)
	}
	if active.Status != grants.StatusActive || active.UsedCount != 0 || active.ReservedCount != 0 {
		t.Fatalf("grant after invalid LFS action = %+v, want active and unused", active)
	}

	resp, body = doRequest(t, http.MethodGet, actionHref, "Bearer "+testSecret, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("LFS action with grant = %d %s, want 200", resp.StatusCode, body)
	}
	used, err := handler.grants.Get(msg.GrantID)
	if err != nil {
		t.Fatal(err)
	}
	if used.Status != grants.StatusConsumed || used.UsedCount != 1 {
		t.Fatalf("grant after LFS action = %+v, want consumed once", used)
	}
}

func TestRefScopedAppendAllowsLFSUploadSupportTraffic(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	dir := t.TempDir()
	upstreamRepo := seedBareRepo(t, dir)
	upstream := newGitUpstream(t, upstreamRepo, testToken)
	defer upstream.server.Close()
	broker := newTestBroker(t, dir, upstream.server.URL, io.Discard, `{"rules":[{
		"id":"allow-main-append",
		"effect":"allow",
		"clients":["agent"],
		"operations":["git.push.append"],
		"targets":[{"kind":"repo","type":"dataset","owner":"acme","name":"repo","refs":["refs/heads/main"]}]
	}]}`)
	defer broker.Close()

	oid := strings.Repeat("c", 64)
	batchURL := broker.URL + "/datasets/acme/repo/info/lfs/objects/batch"
	resp, body := doRequest(t, http.MethodPost, batchURL, "Bearer "+testSecret, strings.NewReader(fmt.Sprintf(`{"operation":"upload","objects":[{"oid":%q,"size":123}]}`, oid)))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("LFS upload batch = %d %s, want 200", resp.StatusCode, body)
	}
	uploadHref := assertLFSActionHref(t, body, "upload", broker.URL+"/datasets/acme/repo.git/info/lfs/objects/"+oid+"/123")
	resp, body = doRequest(t, http.MethodPut, uploadHref, "Bearer "+testSecret, strings.NewReader("contents"))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("LFS upload action = %d %s, want 200", resp.StatusCode, body)
	}
}

func TestLFSUploadSupportIgnoresRefScopedDenyAndRefChangeAttrs(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	dir := t.TempDir()
	upstreamRepo := seedBareRepo(t, dir)
	upstream := newGitUpstream(t, upstreamRepo, testToken)
	defer upstream.server.Close()
	broker := newTestBroker(t, dir, upstream.server.URL, io.Discard, `{"rules":[
		{
			"id":"deny-main",
			"effect":"deny",
			"clients":["agent"],
			"operations":["git.push.append"],
			"targets":[{"kind":"repo","type":"dataset","owner":"acme","name":"repo","refs":["refs/heads/main"]}]
		},
		{
			"id":"allow-dev-fast-forward",
			"effect":"allow",
			"clients":["agent"],
			"operations":["git.push.append"],
			"attrs":{"ref_change":"fast_forward"},
			"targets":[{"kind":"repo","type":"dataset","owner":"acme","name":"repo","refs":["refs/heads/dev"]}]
		}
	]}`)
	defer broker.Close()

	oid := strings.Repeat("f", 64)
	batchURL := broker.URL + "/datasets/acme/repo/info/lfs/objects/batch"
	resp, body := doRequest(t, http.MethodPost, batchURL, "Bearer "+testSecret, strings.NewReader(fmt.Sprintf(`{"operation":"upload","objects":[{"oid":%q,"size":123}]}`, oid)))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("LFS upload batch = %d %s, want 200", resp.StatusCode, body)
	}
	uploadHref := assertLFSActionHref(t, body, "upload", broker.URL+"/datasets/acme/repo.git/info/lfs/objects/"+oid+"/123")
	resp, body = doRequest(t, http.MethodPut, uploadHref, "Bearer "+testSecret, strings.NewReader("contents"))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("LFS upload action = %d %s, want 200", resp.StatusCode, body)
	}
}

func TestForwardPolicyMaxBytesUsesContentLength(t *testing.T) {
	dir := t.TempDir()
	upstreamRepo := seedBareRepo(t, dir)
	upstream := newGitUpstream(t, upstreamRepo, testToken)
	defer upstream.server.Close()
	broker := newTestBroker(t, dir, upstream.server.URL, io.Discard, `{"rules":[{
		"id":"allow-small-lfs-upload",
		"effect":"allow",
		"clients":["agent"],
		"operations":["git.push.append"],
		"attrs":{"max_bytes":4},
		"targets":[{"kind":"repo","type":"dataset","owner":"acme","name":"repo"}]
	}]}`)
	defer broker.Close()

	oid := strings.Repeat("e", 64)
	uploadURL := broker.URL + "/datasets/acme/repo.git/info/lfs/objects/" + oid + "/4"
	beforeAllowed := upstream.totalHits()
	resp, body := doRequest(t, http.MethodPut, uploadURL, "Bearer "+testSecret, strings.NewReader("data"))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("small LFS upload = %d %s, want 200", resp.StatusCode, body)
	}
	if got := upstream.totalHits(); got != beforeAllowed+1 {
		t.Fatalf("small LFS upload upstream hits=%d want %d", got, beforeAllowed+1)
	}

	beforeDenied := upstream.totalHits()
	resp, body = doRequest(t, http.MethodPut, uploadURL, "Bearer "+testSecret, strings.NewReader("toolong"))
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("large LFS upload = %d %s, want 403", resp.StatusCode, body)
	}
	if got := upstream.totalHits(); got != beforeDenied {
		t.Fatalf("large LFS upload reached upstream: hits=%d want %d", got, beforeDenied)
	}
}

func TestPushAttrsIncludePackSize(t *testing.T) {
	attrs := pushAttrs(gitproxy.ClassifiedCommand{Kind: gitproxy.RefUpdateAppend}, 12)
	if attrs["ref_change"] != "fast_forward" || attrs["max_bytes"] != int64(12) {
		t.Fatalf("push attrs = %#v, want ref_change fast_forward and max_bytes 12", attrs)
	}
}

func TestApprovedAppendGrantDoesNotSpendUseOnLFSUploadSupportTraffic(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	dir := t.TempDir()
	upstreamRepo := seedBareRepo(t, dir)
	upstream := newGitUpstream(t, upstreamRepo, testToken)
	defer upstream.server.Close()
	notifier := &captureGrantNotifier{}
	scp, err := policy.Parse([]byte(`{"rules":[{
		"id":"request-main-append",
		"effect":"request",
		"clients":["agent"],
		"operations":["git.push.append"],
		"targets":[{"kind":"repo","type":"dataset","owner":"acme","name":"repo","refs":["refs/heads/main"]}],
		"grant_policy":{"default_minutes":5,"max_minutes":5,"default_max_uses":1,"max_uses":1}
	}]}`))
	if err != nil {
		t.Fatal(err)
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
		UpstreamBaseURL: upstream.server.URL,
		GrantNotifier:   notifier,
	})
	if err != nil {
		t.Fatal(err)
	}
	broker := httptest.NewServer(handler)
	defer broker.Close()

	grantBody := `{
		"operation":"git.push.append",
		"target":{"kind":"repo","type":"dataset","owner":"acme","name":"repo","refs":["refs/heads/main"]},
		"attrs":{"ref_change":"fast_forward"},
		"reason":"upload one LFS object before push",
		"client_request_id":"lfs-upload"
	}`
	resp, text := doRequest(t, http.MethodPost, broker.URL+"/api/grants", "Bearer "+testSecret, strings.NewReader(grantBody))
	if resp.StatusCode != http.StatusAccepted || len(notifier.messages) != 1 {
		t.Fatalf("LFS upload grant request = %d %s messages=%d, want 202 and one message", resp.StatusCode, text, len(notifier.messages))
	}
	msg := notifier.messages[0]
	answer := handler.handleTelegramDecision(context.Background(), telegramGrantDecision(notify.ActionApprove, msg))
	if answer.Answer != "Grant approved" {
		t.Fatalf("grant approval answer = %+v", answer)
	}

	oid := strings.Repeat("d", 64)
	batchURL := broker.URL + "/datasets/acme/repo/info/lfs/objects/batch"
	resp, body := doRequest(t, http.MethodPost, batchURL, "Bearer "+testSecret, strings.NewReader(fmt.Sprintf(`{"operation":"upload","objects":[{"oid":%q,"size":123}]}`, oid)))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("LFS upload batch with grant = %d %s, want 200", resp.StatusCode, body)
	}
	uploadHref := assertLFSActionHref(t, body, "upload", broker.URL+"/datasets/acme/repo.git/info/lfs/objects/"+oid+"/123")
	beforeInvalidAction := upstream.totalHits()
	resp, body = doRequest(t, http.MethodPut, broker.URL+"/datasets/acme/repo.git/info/lfs/objects/"+oid+"/123?"+lfsActionQuery+"=missing", "Bearer "+testSecret, strings.NewReader("contents"))
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("invalid LFS upload action with grant = %d %s, want 403", resp.StatusCode, body)
	}
	if !strings.Contains(body, errInvalidLFSAction.Error()) || strings.Contains(body, "upstream request failed") {
		t.Fatalf("invalid LFS upload action body = %q, want invalid-action response only", body)
	}
	if got := upstream.totalHits(); got != beforeInvalidAction {
		t.Fatalf("invalid LFS upload action with grant reached upstream: hits=%d want %d", got, beforeInvalidAction)
	}
	resp, body = doRequest(t, http.MethodPut, uploadHref, "Bearer "+testSecret, strings.NewReader("contents"))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("LFS upload action with grant = %d %s, want 200", resp.StatusCode, body)
	}
	active, err := handler.grants.Get(msg.GrantID)
	if err != nil {
		t.Fatal(err)
	}
	if active.Status != grants.StatusActive || active.UsedCount != 0 {
		t.Fatalf("grant after LFS upload support traffic = %+v, want active and unused", active)
	}
}

func TestAPIReposListsOnlyPolicyMetadata(t *testing.T) {
	var auditLog bytes.Buffer
	policyJSON := `{"rules":[
		{"id":"list-repo","effect":"allow","clients":["agent"],"operations":["repo.list","repo.metadata.read"],"targets":[{"kind":"repo","type":"dataset","owner":"acme","name":"repo"}]},
		{"id":"list-split","effect":"allow","clients":["agent"],"operations":["repo.list"],"targets":[{"kind":"repo","type":"dataset","owner":"acme","name":"split"}]},
		{"id":"metadata-split","effect":"allow","clients":["agent"],"operations":["repo.metadata.read"],"targets":[{"kind":"repo","type":"dataset","owner":"acme","name":"split"}]},
		{"id":"list-wildcard","effect":"allow","clients":["agent"],"operations":["repo.list","repo.metadata.read"],"targets":[{"kind":"repo","type":"dataset","owner":"acme","name":"*"}]},
		{"id":"other-client","effect":"allow","clients":["other"],"operations":["repo.list","repo.metadata.read"],"targets":[{"kind":"repo","type":"dataset","owner":"acme","name":"other"}]}
	]}`
	scp, err := policy.Parse([]byte(policyJSON))
	if err != nil {
		t.Fatal(err)
	}
	handler, err := New(Options{
		Config: config.Config{
			HFToken: testToken,
			Clients: []config.Client{
				{Name: "agent", Secret: testSecret},
				{Name: "other", Secret: testOtherSecret},
			},
			StateDir:     filepath.Join(t.TempDir(), "state"),
			MaxPackBytes: 25 * 1024 * 1024,
			HFTimeout:    10 * time.Second,
		},
		Scope:           scp,
		Audit:           audit.New(&auditLog),
		UpstreamBaseURL: "http://127.0.0.1:1",
	})
	if err != nil {
		t.Fatal(err)
	}
	broker := httptest.NewServer(handler)
	defer broker.Close()

	resp, body := doRequest(t, http.MethodGet, broker.URL+"/api/repos?type=dataset&owner=acme", "Bearer "+testSecret, nil)
	repos := decodeAPIRepoList(t, body)
	if resp.StatusCode != http.StatusOK || !repoNamesEqual(repos, []string{"repo", "split"}) {
		t.Fatalf("repo list = %d %s, want exact agent repos from combined and split rules", resp.StatusCode, body)
	}
	if strings.Contains(body, "refs/") || strings.Contains(body, "commit") || strings.Contains(body, "README") {
		t.Fatalf("repo list leaked content metadata: %s", body)
	}
	if got := auditLog.String(); !strings.Contains(got, `"operation":"repo.list"`) ||
		!strings.Contains(got, `"target":"repos"`) ||
		!strings.Contains(got, `"decision":"allowed"`) ||
		!strings.Contains(got, `"client":"agent"`) {
		t.Fatalf("repo list audit = %s, want allowed repo.list entry", got)
	}
	beforeInvalidAudit := auditLog.Len()
	resp, body = doRequest(t, http.MethodGet, broker.URL+"/api/repos?cursor=bad", "Bearer "+testSecret, nil)
	if resp.StatusCode != http.StatusBadRequest || decodeJSendFailReason(t, body) != "invalid_cursor" {
		t.Fatalf("invalid cursor = %d %s, want 400 invalid_cursor", resp.StatusCode, body)
	}
	if got := auditLog.String()[beforeInvalidAudit:]; !strings.Contains(got, `"operation":"repo.list"`) ||
		!strings.Contains(got, `"target":"repos"`) ||
		!strings.Contains(got, `"decision":"refused"`) ||
		!strings.Contains(got, `"reason":"invalid_cursor"`) {
		t.Fatalf("invalid cursor audit = %s, want refused repo.list entry", got)
	}
	beforeInvalidAudit = auditLog.Len()
	resp, body = doRequest(t, http.MethodGet, broker.URL+"/api/repos?limit=0", "Bearer "+testSecret, nil)
	if resp.StatusCode != http.StatusBadRequest || decodeJSendFailReason(t, body) != "invalid_limit" {
		t.Fatalf("invalid limit = %d %s, want 400 invalid_limit", resp.StatusCode, body)
	}
	if got := auditLog.String()[beforeInvalidAudit:]; !strings.Contains(got, `"reason":"invalid_limit"`) {
		t.Fatalf("invalid limit audit = %s, want invalid_limit", got)
	}
}

func TestAPIUnknownRoutesAreAudited(t *testing.T) {
	var auditLog bytes.Buffer
	scp, err := policy.Parse([]byte(emptyPolicyJSON()))
	if err != nil {
		t.Fatal(err)
	}
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
		UpstreamBaseURL: "http://127.0.0.1:1",
	})
	if err != nil {
		t.Fatal(err)
	}
	broker := httptest.NewServer(handler)
	defer broker.Close()

	resp, body := doRequest(t, http.MethodPut, broker.URL+"/api/grants", "Bearer "+testSecret, nil)
	if resp.StatusCode != http.StatusMethodNotAllowed || decodeJSendFailReason(t, body) != "method_not_allowed" {
		t.Fatalf("method mismatch = %d %s, want 405 method_not_allowed", resp.StatusCode, body)
	}
	resp, body = doRequest(t, http.MethodGet, broker.URL+"/api/unknown", "Bearer "+testSecret, nil)
	if resp.StatusCode != http.StatusNotFound || decodeJSendFailReason(t, body) != "not_found" {
		t.Fatalf("unknown API route = %d %s, want 404 not_found", resp.StatusCode, body)
	}
	got := auditLog.String()
	for _, want := range []string{
		`"operation":"api"`,
		`"target":"/api/grants"`,
		`"reason":"method_not_allowed"`,
		`"target":"/api/unknown"`,
		`"reason":"not_found"`,
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("API route audit = %s, missing %s", got, want)
		}
	}
}

func repoNamesEqual(repos []apiRepoBody, names []string) bool {
	if len(repos) != len(names) {
		return false
	}
	for i, repo := range repos {
		if repo.Name != names[i] {
			return false
		}
	}
	return true
}

func TestParseRepoListLimit(t *testing.T) {
	cases := []struct {
		value string
		want  int
		ok    bool
	}{
		{value: "", want: 100, ok: true},
		{value: "1", want: 1, ok: true},
		{value: "100", want: 100, ok: true},
		{value: "0", ok: false},
		{value: "101", ok: false},
		{value: "many", ok: false},
	}
	for _, tc := range cases {
		got, ok := parseRepoListLimit(tc.value)
		if got != tc.want || ok != tc.ok {
			t.Fatalf("parseRepoListLimit(%q) = %d, %v; want %d, %v", tc.value, got, ok, tc.want, tc.ok)
		}
	}
}

func TestGrantRequestRetryNotifiesPendingGrantWithoutMessage(t *testing.T) {
	dir := t.TempDir()
	notifier := &captureGrantNotifier{}
	scp, err := policy.Parse([]byte(datasetPolicyJSON(grantableDataset("repo", policy.OpGitPushForce))))
	if err != nil {
		t.Fatal(err)
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
		UpstreamBaseURL: "http://127.0.0.1:1",
		GrantNotifier:   notifier,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := requestHFGrant(handler.grants, hfgrant.Input{
		Client:            "agent",
		ClientRequestID:   "retry-missing-message",
		Operation:         string(policy.OpGitPushForce),
		Target:            "dataset/acme/repo",
		Ref:               "refs/heads/main",
		Reason:            "recover",
		Mode:              hfgrant.ModeWindow,
		RequestedDuration: 5 * time.Minute,
		PendingTimeout:    5 * time.Minute,
		MaxUses:           1,
	}); err != nil {
		t.Fatalf("preseed Request() error = %v", err)
	}
	broker := httptest.NewServer(handler)
	defer broker.Close()

	resp, body := doRequest(t, http.MethodPost, broker.URL+"/api/grants", "Bearer "+testSecret, strings.NewReader(apiGrantRequestJSON(policy.OpGitPushForce, "refs/heads/main", "recover", "retry-missing-message", 0, 0)))
	if resp.StatusCode != http.StatusAccepted || len(notifier.messages) != 1 {
		t.Fatalf("retry grant status=%d body=%q messages=%d, want 202 and one message", resp.StatusCode, body, len(notifier.messages))
	}
}

func TestConcurrentIdempotentGrantRequestsSendOneNotification(t *testing.T) {
	dir := t.TempDir()
	notifier := newBlockingGrantNotifier()
	scp, err := policy.Parse([]byte(datasetPolicyJSON(grantableDataset("repo", policy.OpGitPushForce))))
	if err != nil {
		t.Fatal(err)
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
		UpstreamBaseURL: "http://127.0.0.1:1",
		GrantNotifier:   notifier,
	})
	if err != nil {
		t.Fatal(err)
	}
	broker := httptest.NewServer(handler)
	defer broker.Close()
	body := apiGrantRequestJSON(policy.OpGitPushForce, "refs/heads/main", "recover", "concurrent-notify", 0, 0)

	firstDone := make(chan grantRequestResult, 1)
	go func() {
		firstDone <- doGrantRequestForTest(broker.URL, body)
	}()
	notifier.waitForSend(t)

	retryDone := make(chan grantRequestResult, 1)
	go func() {
		retryDone <- doGrantRequestForTest(broker.URL, body)
	}()
	select {
	case got := <-retryDone:
		t.Fatalf("retry grant returned before notification resolved: %+v", got)
	case <-time.After(100 * time.Millisecond):
	}
	if calls := notifier.calls(); calls != 1 {
		t.Fatalf("notifier calls before release = %d, want one", calls)
	}
	notifier.releaseSend()
	select {
	case got := <-firstDone:
		if got.err != nil {
			t.Fatalf("first grant request error = %v", got.err)
		}
		if got.status != http.StatusAccepted {
			t.Fatalf("first grant status=%d body=%q, want 202", got.status, got.body)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("first grant request did not finish")
	}
	select {
	case got := <-retryDone:
		if got.err != nil {
			t.Fatalf("retry grant request error = %v", got.err)
		}
		if got.status != http.StatusAccepted {
			t.Fatalf("retry grant status=%d body=%q, want 202", got.status, got.body)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("retry grant request did not finish")
	}
	if calls := notifier.calls(); calls != 1 {
		t.Fatalf("notifier calls after release = %d, want one", calls)
	}
}

func TestCallbackWinningNotificationRaceKeepsMessageActive(t *testing.T) {
	dir := t.TempDir()
	notifier := &callbackDuringSendNotifier{
		ref: notify.MessageRef{Kind: "telegram", ChatID: 123, MessageID: 7, Text: "grant text"},
	}
	scp, err := policy.Parse([]byte(datasetPolicyJSON(grantableDataset("repo", policy.OpGitPushForce))))
	if err != nil {
		t.Fatal(err)
	}
	handler, err := New(Options{
		Config: config.Config{
			HFToken: testToken, Clients: []config.Client{{Name: "agent", Secret: testSecret}},
			StateDir: filepath.Join(dir, "state"), MaxPackBytes: 25 * 1024 * 1024, HFTimeout: 10 * time.Second,
		},
		Scope: scp, UpstreamBaseURL: "http://127.0.0.1:1", GrantNotifier: notifier,
	})
	if err != nil {
		t.Fatal(err)
	}
	notifier.server = handler
	broker := httptest.NewServer(handler)
	defer broker.Close()
	body := apiGrantRequestJSON(policy.OpGitPushForce, "refs/heads/main", "recover", "callback-wins-send-race", 0, 0)
	resp, responseBody := doRequest(t, http.MethodPost, broker.URL+"/api/grants", "Bearer "+testSecret, strings.NewReader(body))
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("grant request = %d %s, want 202", resp.StatusCode, responseBody)
	}
	result, updates := notifier.snapshot()
	if result.Answer != "Grant approved" || result.Retry {
		t.Fatalf("callback result = %+v", result)
	}
	for _, status := range updates {
		if strings.Contains(status, "Superseded") {
			t.Fatalf("callback-owned message was superseded: %q", status)
		}
	}
	created := decodeAPIGrantResponse(t, responseBody)
	stored, err := handler.grants.Get(created.ID)
	if err != nil || stored.Status != grants.StatusActive || stored.Notification == nil || *stored.Notification != notifier.ref {
		t.Fatalf("stored grant = %+v err=%v", stored, err)
	}
}

func TestConcurrentGrantRetrySeesNotificationFailure(t *testing.T) {
	dir := t.TempDir()
	notifier := newBlockingGrantNotifier()
	notifier.err = errors.New("notify failed")
	scp, err := policy.Parse([]byte(datasetPolicyJSON(grantableDataset("repo", policy.OpGitPushForce))))
	if err != nil {
		t.Fatal(err)
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
		UpstreamBaseURL: "http://127.0.0.1:1",
		GrantNotifier:   notifier,
	})
	if err != nil {
		t.Fatal(err)
	}
	broker := httptest.NewServer(handler)
	defer broker.Close()
	body := apiGrantRequestJSON(policy.OpGitPushForce, "refs/heads/main", "recover", "concurrent-notify-failure", 0, 0)

	firstDone := make(chan grantRequestResult, 1)
	go func() {
		firstDone <- doGrantRequestForTest(broker.URL, body)
	}()
	notifier.waitForSend(t)
	retryDone := make(chan grantRequestResult, 1)
	go func() {
		retryDone <- doGrantRequestForTest(broker.URL, body)
	}()
	select {
	case got := <-retryDone:
		t.Fatalf("retry grant returned before notification failure resolved: %+v", got)
	case <-time.After(100 * time.Millisecond):
	}
	if calls := notifier.calls(); calls != 1 {
		t.Fatalf("notifier calls before failure release = %d, want one", calls)
	}

	notifier.releaseSend()
	for name, done := range map[string]chan grantRequestResult{"first": firstDone, "retry": retryDone} {
		select {
		case got := <-done:
			if got.err != nil {
				t.Fatalf("%s grant request error = %v", name, got.err)
			}
			if got.status != http.StatusBadGateway {
				t.Fatalf("%s grant status=%d body=%q, want 502", name, got.status, got.body)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("%s grant request did not finish", name)
		}
	}
	if calls := notifier.calls(); calls != 1 {
		t.Fatalf("notifier calls = %d, want one", calls)
	}
}

func TestStaleNotifierFailureDoesNotCancelNewerNotification(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 7, 6, 1, 2, 3, 0, time.UTC)
	var nowMu sync.Mutex
	nowFunc := func() time.Time {
		nowMu.Lock()
		defer nowMu.Unlock()
		return now
	}
	advanceNow := func(d time.Duration) {
		nowMu.Lock()
		defer nowMu.Unlock()
		now = now.Add(d)
	}
	notifier := newBlockingGrantNotifier()
	notifier.firstErr = errors.New("notify failed")
	scp, err := policy.Parse([]byte(datasetPolicyJSON(grantableDataset("repo", policy.OpGitPushForce))))
	if err != nil {
		t.Fatal(err)
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
		UpstreamBaseURL: "http://127.0.0.1:1",
		GrantNotifier:   notifier,
	})
	if err != nil {
		t.Fatal(err)
	}
	handler.grants = grants.New(filepath.Join(dir, "state", "grants", "grants.json"), grants.Options{Now: nowFunc})
	broker := httptest.NewServer(handler)
	defer broker.Close()
	body := apiGrantRequestJSON(policy.OpGitPushForce, "refs/heads/main", "recover", "stale-notify-failure", 0, 0)

	firstDone := make(chan grantRequestResult, 1)
	go func() {
		firstDone <- doGrantRequestForTest(broker.URL, body)
	}()
	notifier.waitForSend(t)
	advanceNow(grantNotificationClaimLease + time.Second)

	retryDone := make(chan grantRequestResult, 1)
	go func() {
		retryDone <- doGrantRequestForTest(broker.URL, body)
	}()
	var retry apiGrantBody
	select {
	case got := <-retryDone:
		if got.err != nil {
			t.Fatalf("retry grant request error = %v", got.err)
		}
		if got.status != http.StatusAccepted {
			t.Fatalf("retry grant status=%d body=%q, want 202", got.status, got.body)
		}
		retry = decodeAPIGrantResponse(t, got.body)
	case <-time.After(5 * time.Second):
		t.Fatalf("retry grant request did not finish")
	}
	if calls := notifier.calls(); calls != 2 {
		t.Fatalf("notifier calls before stale failure release = %d, want two", calls)
	}

	notifier.releaseSend()
	select {
	case got := <-firstDone:
		if got.err != nil {
			t.Fatalf("first grant request error = %v", got.err)
		}
		if got.status != http.StatusAccepted {
			t.Fatalf("first grant status=%d body=%q, want 202", got.status, got.body)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("first grant request did not finish")
	}
	updated, err := handler.grants.Get(retry.ID)
	if err != nil {
		t.Fatalf("Get(%q) error = %v", retry.ID, err)
	}
	if updated.Status != grants.StatusPending || updated.Notification == nil || updated.Notification.MessageID != 2 || !updated.NotificationClaimedAt.IsZero() {
		t.Fatalf("grant after stale notifier failure = %+v, want pending grant with newer notifier", updated)
	}
}

func TestGrantRequestRejectsNonEditableNotifier(t *testing.T) {
	dir := t.TempDir()
	notifier := &zeroMessageGrantNotifier{}
	scp, err := policy.Parse([]byte(datasetPolicyJSON(grantableDataset("repo", policy.OpGitPushForce))))
	if err != nil {
		t.Fatal(err)
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
		UpstreamBaseURL: "http://127.0.0.1:1",
		GrantNotifier:   notifier,
	})
	if err != nil {
		t.Fatal(err)
	}
	broker := httptest.NewServer(handler)
	defer broker.Close()
	body := apiGrantRequestJSON(policy.OpGitPushForce, "refs/heads/main", "recover", "non-editable-notifier", 0, 0)

	resp, bodyText := doRequest(t, http.MethodPost, broker.URL+"/api/grants", "Bearer "+testSecret, strings.NewReader(body))
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("grant request status=%d body=%q, want 502", resp.StatusCode, bodyText)
	}
	resp, bodyText = doRequest(t, http.MethodPost, broker.URL+"/api/grants", "Bearer "+testSecret, strings.NewReader(body))
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("retry grant status=%d body=%q, want 502", resp.StatusCode, bodyText)
	}
	if notifier.calls != 2 {
		t.Fatalf("notifier calls = %d, want one failed delivery per request", notifier.calls)
	}
}

func TestReserveGrantUseFailureRefusesBeforeUpstream(t *testing.T) {
	dir := t.TempDir()
	store := grants.New(filepath.Join(dir, "grants.json"), grants.Options{})
	grant, _, err := requestHFGrant(store, hfgrant.Input{
		Client:    "agent",
		Operation: string(policy.OpGitPushForce),
		Target:    "dataset/acme/repo",
		Ref:       "refs/heads/main",
		Reason:    "force push",
		MaxUses:   1,
	})
	if err != nil {
		t.Fatal(err)
	}
	approved, err := store.Approve(grant.ID, grant.DecisionToken, "telegram:1")
	if err != nil {
		t.Fatalf("Approve() error = %v", err)
	}
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = os.Chmod(dir, 0o700)
	}()
	server := &Server{grants: store}

	reserved, err := server.reserveGrantUses([]grantUse{{grant: approved}})
	if err == nil {
		t.Fatalf("reserveGrantUses() error = nil, want persistence failure")
	}
	if len(reserved) != 0 {
		t.Fatalf("reserved grants after failure = %+v, want none", reserved)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := hfgrant.MatchActiveFunc(store, approved.Client, approved.Operation, hfgrant.Target(approved), hfgrant.Ref(approved), nil); err != nil || !ok {
		t.Fatalf("MatchActive() after failed reservation ok=%v err=%v, want true nil", ok, err)
	}
}

func TestReleaseGrantUsesRestoresReservedGrant(t *testing.T) {
	store := grants.New(filepath.Join(t.TempDir(), "grants.json"), grants.Options{})
	grant, _, err := requestHFGrant(store, hfgrant.Input{
		Client:    "agent",
		Operation: string(policy.OpGitPushForce),
		Target:    "dataset/acme/repo",
		Ref:       "refs/heads/main",
		Reason:    "force push",
		MaxUses:   1,
	})
	if err != nil {
		t.Fatal(err)
	}
	approved, err := store.Approve(grant.ID, grant.DecisionToken, "telegram:1")
	if err != nil {
		t.Fatalf("Approve() error = %v", err)
	}
	server := &Server{grants: store}

	reserved, err := server.reserveGrantUses([]grantUse{{grant: approved}})
	if err != nil {
		t.Fatalf("reserveGrantUses() error = %v", err)
	}
	if _, ok, err := hfgrant.MatchActiveFunc(store, approved.Client, approved.Operation, hfgrant.Target(approved), hfgrant.Ref(approved), nil); err != nil || ok {
		t.Fatalf("MatchActive() while reserved ok=%v err=%v, want false nil", ok, err)
	}

	server.releaseGrantUses(reserved)
	if _, ok, err := hfgrant.MatchActiveFunc(store, approved.Client, approved.Operation, hfgrant.Target(approved), hfgrant.Ref(approved), nil); err != nil || !ok {
		t.Fatalf("MatchActive() after release ok=%v err=%v, want true nil", ok, err)
	}
}

func TestRetainGrantUseReservationsPersistsReviewMarker(t *testing.T) {
	store := grants.New(filepath.Join(t.TempDir(), "grants.json"), grants.Options{})
	grant, _, err := requestHFGrant(store, hfgrant.Input{
		Client:    "agent",
		Operation: string(policy.OpGitPushForce),
		Target:    "dataset/acme/repo",
		Ref:       "refs/heads/main",
		Reason:    "ambiguous push",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.SetNotification(grant.ID, grants.MessageRef{Kind: "telegram", ChatID: 1, MessageID: 2, Text: "grant text"}); err != nil {
		t.Fatalf("SetNotification() error = %v", err)
	}
	approved, err := store.Approve(grant.ID, grant.DecisionToken, "telegram:1")
	if err != nil {
		t.Fatalf("Approve() error = %v", err)
	}
	server := &Server{grants: store}
	reserved, err := server.reserveGrantUses([]grantUse{{grant: approved}})
	if err != nil {
		t.Fatalf("reserveGrantUses() error = %v", err)
	}

	retained, err := server.retainGrantUseReservations(reserved)
	if err != nil {
		t.Fatalf("retainGrantUseReservations() error = %v", err)
	}

	if len(retained) != 1 || !retained[0].ReservationRetained || retained[0].ReservedCount != 1 {
		t.Fatalf("retained grants = %+v, want one retained reservation", retained)
	}
	updates, err := store.StatusUpdatesDue()
	if err != nil {
		t.Fatalf("StatusUpdatesDue() error = %v", err)
	}
	if len(updates) != 1 || updates[0].Kind != grants.StatusUpdateRetainedReservation {
		t.Fatalf("StatusUpdatesDue() = %+v, want retained reservation update", updates)
	}
}

func TestUpdateRetainedGrantReservationMessageReloadsExpiredGrant(t *testing.T) {
	now := time.Date(2026, 7, 6, 1, 2, 3, 0, time.UTC)
	store := grants.New(filepath.Join(t.TempDir(), "grants.json"), grants.Options{Now: func() time.Time { return now }})
	grant, _, err := requestHFGrant(store, hfgrant.Input{
		Client:            "agent",
		Operation:         string(policy.OpGitPushForce),
		Target:            "dataset/acme/repo",
		Ref:               "refs/heads/main",
		Reason:            "slow ambiguous push",
		RequestedDuration: time.Minute,
		MaxUses:           3,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.SetNotification(grant.ID, grants.MessageRef{Kind: "telegram", ChatID: 1, MessageID: 2, Text: "grant text"}); err != nil {
		t.Fatalf("SetNotification() error = %v", err)
	}
	approved, err := store.Approve(grant.ID, grant.DecisionToken, "telegram:1")
	if err != nil {
		t.Fatalf("Approve() error = %v", err)
	}
	if err := store.MarkNotificationStatus(grant.ID, string(grants.StatusActive)); err != nil {
		t.Fatalf("MarkNotificationStatus(active) error = %v", err)
	}
	reserved, err := store.ReserveUse(approved.ID)
	if err != nil {
		t.Fatalf("ReserveUse() error = %v", err)
	}
	now = now.Add(2 * time.Minute)
	notifier := &captureGrantNotifier{}
	server := &Server{grants: store, notifier: notifier}

	server.updateRetainedGrantReservationMessage(reserved)

	if len(notifier.updates) != 1 || !strings.Contains(notifier.updates[0], "Access is closed") || strings.Contains(notifier.updates[0], "uses remain") {
		t.Fatalf("retained reservation updates = %+v, want closed expired status", notifier.updates)
	}
	updated, err := store.Get(grant.ID)
	if err != nil {
		t.Fatalf("Get(%q) error = %v", grant.ID, err)
	}
	if updated.Status != grants.StatusExpired || !updated.ReservationRetained || !strings.HasPrefix(updated.NotificationStatus, "reserved:expired:") {
		t.Fatalf("grant after retained reservation update = %+v, want expired retained grant with reserved notifier status", updated)
	}
}

func TestWaitForGrantNotificationCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := (&Server{}).waitForGrantNotification(ctx, "grant-id")
	if !errors.Is(err, errGrantNotificationStillQueued) {
		t.Fatalf("waitForGrantNotification() error = %v, want errGrantNotificationStillQueued", err)
	}
}

func TestGrantStatusUpdateText(t *testing.T) {
	tests := []struct {
		name   string
		update grants.StatusUpdate
		want   string
	}{
		{
			name:   "active",
			update: grants.StatusUpdate{Status: grants.StatusActive},
			want:   "✅ Approved. Access is active.",
		},
		{
			name:   "denied",
			update: grants.StatusUpdate{Status: grants.StatusDenied},
			want:   "❌ Denied. Access was not granted.",
		},
		{
			name:   "consumed",
			update: grants.StatusUpdate{Kind: grants.StatusUpdateUsed, Status: grants.StatusConsumed, Grant: grants.Grant{Status: grants.StatusConsumed, MaxUses: 1, UsedCount: 1}},
			want:   "✅ Used. Access is now closed.",
		},
		{
			name:   "reserved",
			update: grants.StatusUpdate{Kind: grants.StatusUpdateRetainedReservation, Status: grants.StatusActive, Grant: grants.Grant{Status: grants.StatusActive, MaxUses: 2, UsedCount: 1, ReservedCount: 1}},
			want:   "⚠️ Push result is ambiguous. 2 of 2 uses are held; access is closed until an operator reviews it.",
		},
		{
			name:   "reserved expired",
			update: grants.StatusUpdate{Kind: grants.StatusUpdateRetainedReservation, Status: grants.StatusExpired, Grant: grants.Grant{Status: grants.StatusExpired, MaxUses: 3, UsedCount: 1, ReservedCount: 1}},
			want:   "⚠️ Push result is ambiguous. Access is closed; operator review is still needed.",
		},
		{
			name:   "expired",
			update: grants.StatusUpdate{Status: grants.StatusExpired, Grant: grants.Grant{ExpiredFrom: grants.StatusActive}},
			want:   "⌛ Expired. Access window ended.",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := grantStatusUpdateText(tc.update); got != tc.want {
				t.Fatalf("grantStatusUpdateText() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestGrantUseStatusCountsReservedUses(t *testing.T) {
	got := grantUseStatus(grants.Grant{Status: grants.StatusActive, MaxUses: 2, UsedCount: 1, ReservedCount: 1})
	if !strings.Contains(got, "1 use is held") || !strings.Contains(got, "0 uses remain") {
		t.Fatalf("grantUseStatus() = %q, want held use counted against remaining budget", got)
	}
	got = grantUseStatus(grants.Grant{Status: grants.StatusExpired, MaxUses: 3, UsedCount: 1})
	if strings.Contains(got, "remain") || !strings.Contains(got, "Access is now closed") {
		t.Fatalf("expired grantUseStatus() = %q, want closed access without remaining budget", got)
	}
}

func TestRefChangeForClassUsesPolicyVocabulary(t *testing.T) {
	zero := strings.Repeat("0", 40)
	oldSHA := strings.Repeat("a", 40)
	newSHA := strings.Repeat("b", 40)
	tests := []struct {
		name  string
		class gitproxy.ClassifiedCommand
		want  string
	}{
		{name: "create", class: gitproxy.ClassifiedCommand{Kind: gitproxy.RefUpdateAppend, Command: gitproxy.Command{Old: zero, New: newSHA}}, want: "create"},
		{name: "fast forward", class: gitproxy.ClassifiedCommand{Kind: gitproxy.RefUpdateAppend, Command: gitproxy.Command{Old: oldSHA, New: newSHA}}, want: "fast_forward"},
		{name: "rewrite", class: gitproxy.ClassifiedCommand{Kind: gitproxy.RefUpdateHistoryRewrite, Command: gitproxy.Command{Old: oldSHA, New: newSHA}}, want: "non_fast_forward"},
		{name: "delete", class: gitproxy.ClassifiedCommand{Kind: gitproxy.RefUpdateRefDelete, Command: gitproxy.Command{Old: oldSHA, New: zero}}, want: "delete"},
		{name: "tag", class: gitproxy.ClassifiedCommand{Kind: gitproxy.RefUpdateTagUpdate, Command: gitproxy.Command{Old: oldSHA, New: newSHA}}, want: "tag_update"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := refChangeForClass(tc.class); got != tc.want {
				t.Fatalf("refChangeForClass() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestPushAuditOperationUsesClassifiedOperation(t *testing.T) {
	tests := []struct {
		name    string
		classes []gitproxy.ClassifiedCommand
		want    string
	}{
		{name: "empty defaults append", want: string(policy.OpGitPushAppend)},
		{name: "append", classes: []gitproxy.ClassifiedCommand{{Kind: gitproxy.RefUpdateAppend}}, want: string(policy.OpGitPushAppend)},
		{name: "force", classes: []gitproxy.ClassifiedCommand{{Kind: gitproxy.RefUpdateHistoryRewrite}}, want: string(policy.OpGitPushForce)},
		{name: "delete", classes: []gitproxy.ClassifiedCommand{{Kind: gitproxy.RefUpdateRefDelete}}, want: string(policy.OpGitRefDelete)},
		{name: "tag", classes: []gitproxy.ClassifiedCommand{{Kind: gitproxy.RefUpdateTagUpdate}}, want: string(policy.OpGitTagUpdate)},
		{name: "mixed", classes: []gitproxy.ClassifiedCommand{{Kind: gitproxy.RefUpdateAppend}, {Kind: gitproxy.RefUpdateHistoryRewrite}}, want: "git.push"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := pushAuditOperation(tc.classes); got != tc.want {
				t.Fatalf("pushAuditOperation() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestParseGrantTarget(t *testing.T) {
	tests := []struct {
		target string
		ok     bool
		typ    policy.RepoType
	}{
		{target: "model/acme/repo", ok: true, typ: policy.TypeModel},
		{target: "dataset/acme/repo", ok: true, typ: policy.TypeDataset},
		{target: "space/acme/repo", ok: true, typ: policy.TypeSpace},
		{target: "dataset/acme", ok: false},
		{target: "bucket/acme/repo", ok: false},
		{target: "dataset/acme/../repo", ok: false},
		{target: "dataset//repo", ok: false},
		{target: "dataset/acme/bad repo", ok: false},
		{target: "dataset/acme/*", ok: false},
		{target: "dataset/a?me/repo", ok: false},
		{target: "dataset/acme/repo\x00x", ok: false},
	}
	for _, tc := range tests {
		t.Run(tc.target, func(t *testing.T) {
			rt, ok := parseGrantTarget(tc.target)
			if ok != tc.ok {
				t.Fatalf("ok = %v, want %v", ok, tc.ok)
			}
			if ok && rt.repoType != tc.typ {
				t.Fatalf("repoType = %q, want %q", rt.repoType, tc.typ)
			}
		})
	}
}

func TestNewWithTelegramConfigStartsPoller(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	scp, err := policy.Parse([]byte(emptyPolicyJSON()))
	if err != nil {
		t.Fatal(err)
	}
	_, err = New(Options{
		Context: ctx,
		Config: config.Config{
			HFToken:          testToken,
			Clients:          []config.Client{{Name: "agent", Secret: testSecret}},
			StateDir:         t.TempDir(),
			MaxPackBytes:     25 * 1024 * 1024,
			HFTimeout:        10 * time.Second,
			TelegramBotToken: "telegram_token_value",
			TelegramChatID:   123,
		},
		Scope:           scp,
		UpstreamBaseURL: "http://127.0.0.1:1",
		TelegramBaseURL: "http://127.0.0.1:1",
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
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
	broker := newTestBroker(t, dir, upstream.server.URL, &auditLog, datasetPolicyJSON(
		appendOnlyDataset("repo"),
		appendOnlyDataset("other"),
		readOnlyDataset("readonly"),
	))
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
	assertLFSActionHref(t, body, "download", broker.URL+"/datasets/acme/repo.git/info/lfs/objects/"+oid)
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
	handler, err := New(Options{Config: cfg, Scope: scp, UpstreamBaseURL: "http://127.0.0.1:1"})
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
	handler, err = New(Options{Config: cfg, Scope: scp, UpstreamBaseURL: "http://127.0.0.1:1"})
	if err != nil {
		t.Fatal(err)
	}
	server.Config.Handler = handler
	resp, _ = doRequest(t, http.MethodPost, pushURL, "Bearer "+testSecret, strings.NewReader("bad"))
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("bad push status = %d, want 400", resp.StatusCode)
	}
	resp, _ = doRequest(t, http.MethodPost, pushURL, "Bearer "+testSecret, bytes.NewReader(pktline.AppendFlush(nil)))
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
	rejected := pktline.AppendString(nil, "unpack ok\n")
	rejected = pktline.AppendString(rejected, "ng refs/heads/main upstream rejected\n")
	rejected = pktline.AppendFlush(rejected)
	if accepted, reason, definitive := receivePackAccepted(req, http.StatusOK, rejected); accepted || definitive || !strings.Contains(reason, "upstream rejected") {
		t.Fatalf("ng rejection accepted=%v reason=%q definitive=%v, want ambiguous receive-pack rejection", accepted, reason, definitive)
	}
	missing := pktline.AppendString(nil, "unpack ok\n")
	missing = pktline.AppendFlush(missing)
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

func newTestBroker(t *testing.T, dir, upstreamURL string, auditWriter io.Writer, scopeJSON string) *httptest.Server {
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
	return httptest.NewServer(handler)
}

func acceptedReceivePackReport(ref string) []byte {
	body := pktline.AppendString(nil, "unpack ok\n")
	body = pktline.AppendString(body, "ok "+ref+"\n")
	return pktline.AppendFlush(body)
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
	messages []notify.ApprovalMessage
	updates  []string
}

type callbackDuringSendNotifier struct {
	mu      sync.Mutex
	server  *Server
	ref     notify.MessageRef
	result  notify.DecisionResult
	updates []string
}

func (n *callbackDuringSendNotifier) SendApproval(ctx context.Context, msg notify.ApprovalMessage) (notify.MessageRef, error) {
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

func (n *callbackDuringSendNotifier) UpdateStatus(_ context.Context, _ notify.MessageRef, status string) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.updates = append(n.updates, status)
	return nil
}

func (n *callbackDuringSendNotifier) snapshot() (notify.DecisionResult, []string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.result, append([]string(nil), n.updates...)
}

func (n *captureGrantNotifier) SendApproval(_ context.Context, msg notify.ApprovalMessage) (notify.MessageRef, error) {
	n.messages = append(n.messages, msg)
	return notify.MessageRef{Kind: "capture", ChatID: 123, MessageID: len(n.messages), Text: "grant text"}, nil
}

func (n *captureGrantNotifier) UpdateStatus(_ context.Context, _ notify.MessageRef, status string) error {
	n.updates = append(n.updates, status)
	return nil
}

type blockingGrantNotifier struct {
	mu       sync.Mutex
	messages []notify.ApprovalMessage
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

func (n *blockingGrantNotifier) SendApproval(ctx context.Context, msg notify.ApprovalMessage) (notify.MessageRef, error) {
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

func (*blockingGrantNotifier) UpdateStatus(context.Context, notify.MessageRef, string) error {
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

func (n *zeroMessageGrantNotifier) SendApproval(context.Context, notify.ApprovalMessage) (notify.MessageRef, error) {
	n.calls++
	return notify.MessageRef{Kind: "capture", ChatID: 123, Text: "grant text"}, nil
}

func (*zeroMessageGrantNotifier) UpdateStatus(context.Context, notify.MessageRef, string) error {
	return nil
}

type failingGrantNotifier struct{}

func (failingGrantNotifier) SendApproval(context.Context, notify.ApprovalMessage) (notify.MessageRef, error) {
	return notify.MessageRef{}, errors.New("notify failed")
}

func (failingGrantNotifier) UpdateStatus(context.Context, notify.MessageRef, string) error {
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
	status := pktline.AppendString(nil, "unpack ok\n")
	for _, command := range req.Commands {
		status = pktline.AppendString(status, "ng "+command.Ref+" upstream rejected\n")
	}
	status = pktline.AppendFlush(status)
	var out []byte
	if sideBand {
		out = appendTestBandBytes(out, 1, status)
		return pktline.AppendFlush(out)
	}
	return status
}

func appendTestBandBytes(dst []byte, band byte, payload []byte) []byte {
	data := append([]byte{band}, payload...)
	return pktline.Append(dst, data)
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
	body = pktline.AppendString(body, "# service="+service+"\n")
	body = pktline.AppendFlush(body)
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
