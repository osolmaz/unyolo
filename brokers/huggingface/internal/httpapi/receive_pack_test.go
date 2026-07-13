package httpapi

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/osolmaz/brokerkit/audit"
	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/config"
	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/hfgrant"
	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/hfplan"
	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/policy"
	"github.com/osolmaz/brokerkit/grants"
	"github.com/osolmaz/brokerkit/notify"
	rootpolicy "github.com/osolmaz/brokerkit/policy"
)

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
	automatic, err := handler.grants.ListForClient("agent")
	if err != nil || len(automatic) != 1 || automatic[0].Status != grants.StatusPending || !strings.Contains(output, automatic[0].ID) {
		t.Fatalf("automatic approval = %+v, err=%v, output=%q", automatic, err, output)
	}
	output, err = runClientGitErr(clone, "push", "--force", "origin", "main")
	if err == nil || !strings.Contains(output, automatic[0].ID) {
		t.Fatalf("automatic approval retry err=%v output=%q", err, output)
	}
	replayed, err := handler.grants.ListForClient("agent")
	if err != nil || len(replayed) != 1 || replayed[0].ID != automatic[0].ID {
		t.Fatalf("automatic approval replay = %+v, err=%v", replayed, err)
	}
	if err := handler.grants.Cancel(automatic[0].ID); err != nil {
		t.Fatal(err)
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

	grant, _, err := requestHFGrant(t, handler.grants, handler.plans, hfgrant.Input{
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
	grant, _, err := requestHFGrant(t, store, testPlanStore(t), hfgrant.Input{
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
	plans := testPlanStore(t)
	grant, _, err := requestHFGrant(t, store, plans, hfgrant.Input{
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
	server := &Server{grants: store, plans: plans, planValidator: hfplan.Validator{Store: plans}}
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
	plans := testPlanStore(t)
	grant, _, err := requestHFGrant(t, store, plans, hfgrant.Input{
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
	server := &Server{grants: store, plans: plans, planValidator: hfplan.Validator{Store: plans}}
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
		Client:          "agent",
		ClientRequestID: "retained-reservation",
		Operation:       string(policy.OpGitPushForce),
		Target:          "dataset/acme/repo",
		Ref:             "refs/heads/main",
		Attrs:           refChangeAttrs("non_fast_forward"),
		Reason:          "test retained reservation",
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
	handler := newTestHandler(t, dir, upstream.URL, io.Discard, appendOnlyDatasetPolicyJSON("repo"))
	t.Cleanup(func() { _ = handler.Close() })
	requested, _, err := handler.grants.Request(grants.Request{Client: "agent", ClientRequestID: "corrupt-1", Operation: "git.push.force",
		Target: rootpolicy.Target{Kind: "hf", Fields: map[string][]string{"name": {"dataset/acme/repo"}}}, Reason: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := handler.database.SQL().ExecContext(t.Context(), "PRAGMA ignore_check_constraints = ON"); err != nil {
		t.Fatal(err)
	}
	if _, err := handler.database.SQL().ExecContext(t.Context(), "UPDATE grants SET target_json = '{' WHERE id = ?", requested.Grant.ID); err != nil {
		t.Fatal(err)
	}
	broker := httptest.NewServer(handler)
	defer broker.Close()
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
	grant, _, err := requestHFGrant(t, handler.grants, handler.plans, hfgrant.Input{
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

	grant, _, err := requestHFGrant(t, handler.grants, handler.plans, hfgrant.Input{
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
	grant, _, err := requestHFGrant(t, handler.grants, handler.plans, hfgrant.Input{
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
	})
	if err != nil {
		t.Fatal(err)
	}
	grant, _, err := requestHFGrant(t, handler.grants, handler.plans, hfgrant.Input{
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
	handler.notifier = notifier

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
