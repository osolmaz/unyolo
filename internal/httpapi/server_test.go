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

	"github.com/osolmaz/hf-broker/internal/audit"
	"github.com/osolmaz/hf-broker/internal/config"
	"github.com/osolmaz/hf-broker/internal/gitproxy"
	"github.com/osolmaz/hf-broker/internal/gitproxy/pktline"
	"github.com/osolmaz/hf-broker/internal/grants"
	"github.com/osolmaz/hf-broker/internal/notify"
	"github.com/osolmaz/hf-broker/internal/scope"
)

const (
	testSecret      = "abcdefghijklmnopqrstuvwxyz123456"
	testOtherSecret = "123456abcdefghijklmnopqrstuvwxyz"
	testToken       = "hf_upstream_token_value_1234567890"
)

type grantRequestResult struct {
	status int
	body   string
	err    error
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
	broker := newTestBroker(t, dir, upstream.server.URL, &auditLog, `{
		"repos": [{"id": "acme/repo", "type": "dataset", "mode": "append-only"}]
	}`)
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

	runClientGit(t, clone, "reset", "--hard", initial)
	output, err := runClientGitErr(clone, "push", "--force", "origin", "main")
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

	output, err = runClientGitErr(clone, "push", "origin", ":main")
	if err == nil {
		t.Fatalf("delete push succeeded, output:\n%s", output)
	}
	if !strings.Contains(output, "hf-broker") {
		t.Fatalf("delete output missing broker reason:\n%s", output)
	}
	if got := upstream.receivePackHits(); got != beforeReceive+1 {
		t.Fatalf("delete reached upstream: hits = %d, want %d", got, beforeReceive+1)
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
	scp, err := scope.Parse([]byte(`{"repos":[{"id":"acme/repo","type":"dataset","mode":"append-only","grant_policy":{"git_history_rewrite":{"max_uses":3}}}]}`))
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

	resp, body := doRequest(t, http.MethodPost, broker.URL+"/grants", "Bearer "+testSecret, strings.NewReader(`{
		"operation":"git_history_rewrite",
		"target":"dataset/acme/repo",
		"ref":"refs/heads/main",
		"reason":"recover main",
		"minutes":5,
		"client_request_id":"recover-main"
	}`))
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
	resp, _ = doRequest(t, http.MethodPost, broker.URL+"/grants", "Bearer "+testSecret, strings.NewReader(`{
		"operation":"git_history_rewrite",
		"target":"dataset/acme/repo",
		"ref":"refs/heads/main",
		"reason":"recover main",
		"minutes":5,
		"client_request_id":"recover-main"
	}`))
	if resp.StatusCode != http.StatusAccepted || len(notifier.messages) != 1 {
		t.Fatalf("idempotent grant status=%d messages=%d, want 202 and one message", resp.StatusCode, len(notifier.messages))
	}
	answer := handler.handleTelegramDecision(context.Background(), notify.Decision{
		Action:      notify.DecisionApprove,
		ID:          msg.ID,
		Token:       msg.DecisionToken,
		OperatorID:  42,
		OperatorTag: "operator",
	})
	if answer.Answer != "Grant approved" || answer.ActiveExpiresAt.IsZero() {
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
	if err == nil || !strings.Contains(output, "hf-broker") {
		t.Fatalf("delete push after consumed grant err=%v output:\n%s", err, output)
	}
	if got := auditLog.String(); !strings.Contains(got, `"decision":"grant-used"`) || strings.Contains(got, testSecret) || strings.Contains(got, testToken) || strings.Contains(got, msg.DecisionToken) {
		t.Fatalf("audit missing grant-used or leaked secret material:\n%s", got)
	}
	if replay := handler.handleTelegramDecision(context.Background(), notify.Decision{Action: notify.DecisionDeny, ID: msg.ID, Token: msg.DecisionToken}); replay.Answer != "Grant is no longer pending" {
		t.Fatalf("replay answer = %+v", replay)
	}
}

func assertHistoryRewriteGrantDoesNotAllowDeletion(t *testing.T, clone string, upstream *gitUpstream, wantHits int) {
	t.Helper()
	output, err := runClientGitErr(clone, "push", "origin", ":main")
	if err == nil || !strings.Contains(output, "hf-broker") {
		t.Fatalf("branch deletion used history-rewrite grant err=%v output:\n%s", err, output)
	}
	if got := upstream.receivePackHits(); got != wantHits {
		t.Fatalf("branch deletion with history-rewrite grant reached upstream: hits=%d want %d", got, wantHits)
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
	scp, err := scope.Parse([]byte(`{"repos":[{"id":"acme/repo","type":"dataset","mode":"append-only","grant_policy":{"git_history_rewrite":{}}}]}`))
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

	resp, body := doRequest(t, http.MethodPost, broker.URL+"/grants", "Bearer "+testSecret, strings.NewReader(`{
		"operation":"git_history_rewrite",
		"target":"dataset/acme/repo",
		"ref":"refs/heads/main",
		"reason":"recover main"
	}`))
	if resp.StatusCode != http.StatusAccepted || len(notifier.messages) != 1 {
		t.Fatalf("grant request status=%d body=%q messages=%d, want 202 and one message", resp.StatusCode, body, len(notifier.messages))
	}
	msg := notifier.messages[0]
	answer := handler.handleTelegramDecision(context.Background(), notify.Decision{
		Action:     notify.DecisionApprove,
		ID:         msg.ID,
		Token:      msg.DecisionToken,
		OperatorID: 42,
	})
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
	updated, err := handler.grants.Get(msg.ID)
	if err != nil {
		t.Fatalf("Get(%q) error = %v", msg.ID, err)
	}
	if updated.Status != grants.StatusActive || updated.ReservedCount != 1 || updated.UsedCount != 0 || !updated.ReservationRetained {
		t.Fatalf("grant after upstream rejection = %+v, want active with retained reservation", updated)
	}
	if _, ok, err := handler.grants.MatchActive("agent", string(scope.OpGitHistoryRewrite), "dataset/acme/repo", "refs/heads/main"); err != nil || ok {
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
	scp, err := scope.Parse([]byte(`{"repos":[{"id":"acme/repo","type":"dataset","mode":"append-only","grant_policy":{"git_history_rewrite":{}}}]}`))
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

	resp, body := doRequest(t, http.MethodPost, broker.URL+"/grants", "Bearer "+testSecret, strings.NewReader(`{
		"operation":"git_history_rewrite",
		"target":"dataset/acme/repo",
		"ref":"refs/heads/main",
		"reason":"recover main"
	}`))
	if resp.StatusCode != http.StatusAccepted || len(notifier.messages) != 1 {
		t.Fatalf("grant request status=%d body=%q messages=%d, want 202 and one message", resp.StatusCode, body, len(notifier.messages))
	}
	msg := notifier.messages[0]
	answer := handler.handleTelegramDecision(context.Background(), notify.Decision{
		Action:     notify.DecisionApprove,
		ID:         msg.ID,
		Token:      msg.DecisionToken,
		OperatorID: 42,
	})
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
	updated, err := handler.grants.Get(msg.ID)
	if err != nil {
		t.Fatalf("Get(%q) error = %v", msg.ID, err)
	}
	if updated.Status != grants.StatusActive || updated.ReservedCount != 1 || updated.UsedCount != 0 || !updated.ReservationRetained {
		t.Fatalf("grant after forward error = %+v, want active with retained reservation", updated)
	}
}

func TestGrantRequestAcceptsConfiguredGitCapabilities(t *testing.T) {
	dir := t.TempDir()
	notifier := &captureGrantNotifier{}
	scp, err := scope.Parse([]byte(`{"repos":[{"id":"acme/repo","type":"dataset","mode":"append-only","grant_policy":{"git_history_rewrite":{},"git_ref_delete":{},"git_tag_update":{}}}]}`))
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
		{operation: "git_history_rewrite", ref: "refs/heads/main"},
		{operation: "git_ref_delete", ref: "refs/heads/feature"},
		{operation: "git_tag_update", ref: "refs/tags/v1"},
	}
	for i, tc := range tests {
		body := fmt.Sprintf(`{"operation":%q,"target":"dataset/acme/repo","ref":%q,"reason":"recover","client_request_id":%q}`, tc.operation, tc.ref, tc.operation)
		resp, text := doRequest(t, http.MethodPost, broker.URL+"/grants", "Bearer "+testSecret, strings.NewReader(body))
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
		{operation: "git_history_rewrite", ref: "refs/tags/v1"},
		{operation: "git_history_rewrite", ref: "refs/replace/abc"},
		{operation: "git_ref_delete", ref: "refs/tags/v1"},
		{operation: "git_ref_delete", ref: "refs/replace/abc"},
		{operation: "git_tag_update", ref: "refs/heads/main"},
	}
	for _, tc := range invalid {
		body := fmt.Sprintf(`{"operation":%q,"target":"dataset/acme/repo","ref":%q,"reason":"recover"}`, tc.operation, tc.ref)
		resp, _ := doRequest(t, http.MethodPost, broker.URL+"/grants", "Bearer "+testSecret, strings.NewReader(body))
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("%s grant request for %s = %d, want 400", tc.operation, tc.ref, resp.StatusCode)
		}
	}
}

func TestGrantRequestErrors(t *testing.T) {
	dir := t.TempDir()
	var auditLog bytes.Buffer
	scp, err := scope.Parse([]byte(`{"repos":[{"id":"acme/repo","type":"dataset","mode":"append-only","grant_policy":{"git_history_rewrite":{"max_uses":2}}}]}`))
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
	validBody := `{"operation":"git_history_rewrite","target":"dataset/acme/repo","ref":"refs/heads/main","reason":"recover","minutes":5}`
	resp, _ := doRequest(t, http.MethodPost, broker.URL+"/grants", "Bearer "+testSecret, strings.NewReader(validBody))
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("grant without notifier = %d, want 503", resp.StatusCode)
	}

	notifier := &captureGrantNotifier{}
	handler, err = New(Options{Config: baseCfg, Scope: scp, Audit: audit.New(&auditLog), UpstreamBaseURL: "http://127.0.0.1:1", GrantNotifier: notifier})
	if err != nil {
		t.Fatal(err)
	}
	broker.Config.Handler = handler
	beforeBadTargetAudit := auditLog.Len()
	resp, _ = doRequest(t, http.MethodPost, broker.URL+"/grants", "Bearer "+testSecret, strings.NewReader(fmt.Sprintf(`{
		"operation":"git_history_rewrite",
		"target":%q,
		"ref":"refs/heads/main",
		"reason":"recover"
	}`, testSecret)))
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("bad target status = %d, want 400", resp.StatusCode)
	}
	if got := auditLog.String()[beforeBadTargetAudit:]; strings.Contains(got, testSecret) || !strings.Contains(got, `"target":""`) {
		t.Fatalf("bad grant target audit leaked request body or missed empty target:\n%s", got)
	}
	tests := []struct {
		name   string
		method string
		body   string
		want   int
	}{
		{name: "wrong method", method: http.MethodGet, want: http.StatusMethodNotAllowed},
		{name: "bad json", method: http.MethodPost, body: `{`, want: http.StatusBadRequest},
		{name: "trailing json", method: http.MethodPost, body: validBody + `{}`, want: http.StatusBadRequest},
		{name: "bad operation", method: http.MethodPost, body: `{"operation":"git_upload_pack","target":"dataset/acme/repo","ref":"refs/heads/main","reason":"recover"}`, want: http.StatusBadRequest},
		{name: "transport operation", method: http.MethodPost, body: `{"operation":"git_receive_pack","target":"dataset/acme/repo","ref":"refs/heads/main","reason":"recover"}`, want: http.StatusBadRequest},
		{name: "unconfigured capability", method: http.MethodPost, body: `{"operation":"git_ref_delete","target":"dataset/acme/repo","ref":"refs/heads/main","reason":"recover"}`, want: http.StatusForbidden},
		{name: "bad ref", method: http.MethodPost, body: `{"operation":"git_history_rewrite","target":"dataset/acme/repo","ref":"main","reason":"recover"}`, want: http.StatusBadRequest},
		{name: "out of scope", method: http.MethodPost, body: `{"operation":"git_history_rewrite","target":"dataset/acme/other","ref":"refs/heads/main","reason":"recover"}`, want: http.StatusForbidden},
		{name: "negative minutes", method: http.MethodPost, body: `{"operation":"git_history_rewrite","target":"dataset/acme/repo","ref":"refs/heads/main","reason":"recover","minutes":-1}`, want: http.StatusBadRequest},
		{name: "too many minutes", method: http.MethodPost, body: `{"operation":"git_history_rewrite","target":"dataset/acme/repo","ref":"refs/heads/main","reason":"recover","minutes":61}`, want: http.StatusBadRequest},
		{name: "negative max uses", method: http.MethodPost, body: `{"operation":"git_history_rewrite","target":"dataset/acme/repo","ref":"refs/heads/main","reason":"recover","max_uses":-1}`, want: http.StatusBadRequest},
		{name: "too many uses", method: http.MethodPost, body: `{"operation":"git_history_rewrite","target":"dataset/acme/repo","ref":"refs/heads/main","reason":"recover","max_uses":3}`, want: http.StatusBadRequest},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp, _ := doRequest(t, tc.method, broker.URL+"/grants", "Bearer "+testSecret, strings.NewReader(tc.body))
			if resp.StatusCode != tc.want {
				t.Fatalf("status = %d, want %d", resp.StatusCode, tc.want)
			}
		})
	}

	handler, err = New(Options{Config: baseCfg, Scope: scp, Audit: audit.New(&auditLog), UpstreamBaseURL: "http://127.0.0.1:1", GrantNotifier: failingGrantNotifier{}})
	if err != nil {
		t.Fatal(err)
	}
	broker.Config.Handler = handler
	resp, _ = doRequest(t, http.MethodPost, broker.URL+"/grants", "Bearer "+testSecret, strings.NewReader(validBody))
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("notifier failure status = %d, want 502", resp.StatusCode)
	}
}

func TestGrantRequestRetryNotifiesPendingGrantWithoutMessage(t *testing.T) {
	dir := t.TempDir()
	notifier := &captureGrantNotifier{}
	scp, err := scope.Parse([]byte(`{"repos":[{"id":"acme/repo","type":"dataset","mode":"append-only","grant_policy":{"git_history_rewrite":{}}}]}`))
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
	if _, _, err := handler.grants.Request(grants.Request{
		Client:          "agent",
		ClientRequestID: "retry-missing-message",
		Operation:       string(scope.OpGitHistoryRewrite),
		Target:          "dataset/acme/repo",
		Ref:             "refs/heads/main",
		Reason:          "recover",
		MaxUses:         1,
	}); err != nil {
		t.Fatalf("preseed Request() error = %v", err)
	}
	broker := httptest.NewServer(handler)
	defer broker.Close()

	resp, body := doRequest(t, http.MethodPost, broker.URL+"/grants", "Bearer "+testSecret, strings.NewReader(`{
		"operation":"git_history_rewrite",
		"target":"dataset/acme/repo",
		"ref":"refs/heads/main",
		"reason":"recover",
		"client_request_id":"retry-missing-message"
	}`))
	if resp.StatusCode != http.StatusAccepted || len(notifier.messages) != 1 {
		t.Fatalf("retry grant status=%d body=%q messages=%d, want 202 and one message", resp.StatusCode, body, len(notifier.messages))
	}
}

func TestConcurrentIdempotentGrantRequestsSendOneNotification(t *testing.T) {
	dir := t.TempDir()
	notifier := newBlockingGrantNotifier()
	scp, err := scope.Parse([]byte(`{"repos":[{"id":"acme/repo","type":"dataset","mode":"append-only","grant_policy":{"git_history_rewrite":{}}}]}`))
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
	body := `{
		"operation":"git_history_rewrite",
		"target":"dataset/acme/repo",
		"ref":"refs/heads/main",
		"reason":"recover",
		"client_request_id":"concurrent-notify"
	}`

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

func TestConcurrentGrantRetrySeesNotificationFailure(t *testing.T) {
	dir := t.TempDir()
	notifier := newBlockingGrantNotifier()
	notifier.err = errors.New("notify failed")
	scp, err := scope.Parse([]byte(`{"repos":[{"id":"acme/repo","type":"dataset","mode":"append-only","grant_policy":{"git_history_rewrite":{}}}]}`))
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
	body := `{
		"operation":"git_history_rewrite",
		"target":"dataset/acme/repo",
		"ref":"refs/heads/main",
		"reason":"recover",
		"client_request_id":"concurrent-notify-failure"
	}`

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
	scp, err := scope.Parse([]byte(`{"repos":[{"id":"acme/repo","type":"dataset","mode":"append-only","grant_policy":{"git_history_rewrite":{}}}]}`))
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
	body := `{
		"operation":"git_history_rewrite",
		"target":"dataset/acme/repo",
		"ref":"refs/heads/main",
		"reason":"recover",
		"client_request_id":"stale-notify-failure"
	}`

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
	var retry grantResponseBody
	select {
	case got := <-retryDone:
		if got.err != nil {
			t.Fatalf("retry grant request error = %v", got.err)
		}
		if got.status != http.StatusAccepted {
			t.Fatalf("retry grant status=%d body=%q, want 202", got.status, got.body)
		}
		if err := json.Unmarshal([]byte(got.body), &retry); err != nil {
			t.Fatalf("retry grant response JSON error = %v body=%q", err, got.body)
		}
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
	if updated.Status != grants.StatusPending || updated.Notifier == nil || updated.Notifier.MessageID != 2 || !updated.NotifierClaimedAt.IsZero() {
		t.Fatalf("grant after stale notifier failure = %+v, want pending grant with newer notifier", updated)
	}
}

func TestGrantRequestWithNonEditableNotifierIsIdempotent(t *testing.T) {
	dir := t.TempDir()
	notifier := &zeroMessageGrantNotifier{}
	scp, err := scope.Parse([]byte(`{"repos":[{"id":"acme/repo","type":"dataset","mode":"append-only","grant_policy":{"git_history_rewrite":{}}}]}`))
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
	body := `{
		"operation":"git_history_rewrite",
		"target":"dataset/acme/repo",
		"ref":"refs/heads/main",
		"reason":"recover",
		"client_request_id":"non-editable-notifier"
	}`

	resp, bodyText := doRequest(t, http.MethodPost, broker.URL+"/grants", "Bearer "+testSecret, strings.NewReader(body))
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("grant request status=%d body=%q, want 202", resp.StatusCode, bodyText)
	}
	resp, bodyText = doRequest(t, http.MethodPost, broker.URL+"/grants", "Bearer "+testSecret, strings.NewReader(body))
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("retry grant status=%d body=%q, want 202", resp.StatusCode, bodyText)
	}
	if notifier.calls != 1 {
		t.Fatalf("notifier calls = %d, want one", notifier.calls)
	}
}

func TestReserveGrantUseFailureRefusesBeforeUpstream(t *testing.T) {
	dir := t.TempDir()
	store := grants.New(filepath.Join(dir, "grants.json"), grants.Options{})
	grant, _, err := store.Request(grants.Request{
		Client:    "agent",
		Operation: string(scope.OpGitHistoryRewrite),
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
	if _, ok, err := store.MatchActive(approved.Client, approved.Operation, approved.Target, approved.Ref); err != nil || !ok {
		t.Fatalf("MatchActive() after failed reservation ok=%v err=%v, want true nil", ok, err)
	}
}

func TestReleaseGrantUsesRestoresReservedGrant(t *testing.T) {
	store := grants.New(filepath.Join(t.TempDir(), "grants.json"), grants.Options{})
	grant, _, err := store.Request(grants.Request{
		Client:    "agent",
		Operation: string(scope.OpGitHistoryRewrite),
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
	if _, ok, err := store.MatchActive(approved.Client, approved.Operation, approved.Target, approved.Ref); err != nil || ok {
		t.Fatalf("MatchActive() while reserved ok=%v err=%v, want false nil", ok, err)
	}

	server.releaseGrantUses(reserved)
	if _, ok, err := store.MatchActive(approved.Client, approved.Operation, approved.Target, approved.Ref); err != nil || !ok {
		t.Fatalf("MatchActive() after release ok=%v err=%v, want true nil", ok, err)
	}
}

func TestRetainGrantUseReservationsPersistsReviewMarker(t *testing.T) {
	store := grants.New(filepath.Join(t.TempDir(), "grants.json"), grants.Options{})
	grant, _, err := store.Request(grants.Request{
		Client:    "agent",
		Operation: string(scope.OpGitHistoryRewrite),
		Target:    "dataset/acme/repo",
		Ref:       "refs/heads/main",
		Reason:    "ambiguous push",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.SetNotifier(grant.ID, grants.NotifierMessage{Kind: "telegram", ChatID: 1, MessageID: 2, Text: "grant text"}); err != nil {
		t.Fatalf("SetNotifier() error = %v", err)
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
	if len(updates) != 1 || updates[0].Status != grants.NotifierStatusReserved {
		t.Fatalf("StatusUpdatesDue() = %+v, want retained reservation update", updates)
	}
}

func TestUpdateRetainedGrantReservationMessageReloadsExpiredGrant(t *testing.T) {
	now := time.Date(2026, 7, 6, 1, 2, 3, 0, time.UTC)
	store := grants.New(filepath.Join(t.TempDir(), "grants.json"), grants.Options{Now: func() time.Time { return now }})
	grant, _, err := store.Request(grants.Request{
		Client:            "agent",
		Operation:         string(scope.OpGitHistoryRewrite),
		Target:            "dataset/acme/repo",
		Ref:               "refs/heads/main",
		Reason:            "slow ambiguous push",
		RequestedDuration: time.Minute,
		MaxUses:           3,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.SetNotifier(grant.ID, grants.NotifierMessage{Kind: "telegram", ChatID: 1, MessageID: 2, Text: "grant text"}); err != nil {
		t.Fatalf("SetNotifier() error = %v", err)
	}
	approved, err := store.Approve(grant.ID, grant.DecisionToken, "telegram:1")
	if err != nil {
		t.Fatalf("Approve() error = %v", err)
	}
	if err := store.MarkNotifierStatus(grant.ID, string(grants.StatusActive)); err != nil {
		t.Fatalf("MarkNotifierStatus(active) error = %v", err)
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
	if updated.Status != grants.StatusExpired || !updated.ReservationRetained || updated.NotifierStatus != "reserved:expired" {
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
			update: grants.StatusUpdate{Status: grants.StatusConsumed, Grant: grants.Grant{Status: grants.StatusConsumed, MaxUses: 1, UsedCount: 1}},
			want:   "✅ Used. Access is now closed.",
		},
		{
			name:   "reserved",
			update: grants.StatusUpdate{Status: grants.NotifierStatusReserved, Grant: grants.Grant{Status: grants.StatusActive, MaxUses: 2, UsedCount: 1, ReservedCount: 1}},
			want:   "⚠️ Push result is ambiguous. 2 of 2 uses are held; 0 uses remain.",
		},
		{
			name:   "reserved expired",
			update: grants.StatusUpdate{Status: grants.NotifierStatusReserved, Grant: grants.Grant{Status: grants.StatusExpired, MaxUses: 3, UsedCount: 1, ReservedCount: 1}},
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

func TestGrantOperationForPushFailure(t *testing.T) {
	tests := []struct {
		name   string
		ref    string
		reason string
		want   scope.Operation
		ok     bool
	}{
		{name: "history rewrite", ref: "refs/heads/main", reason: "history rewrite refused", want: scope.OpGitHistoryRewrite, ok: true},
		{name: "branch deletion", ref: "refs/heads/main", reason: "deletion refused", want: scope.OpGitRefDelete, ok: true},
		{name: "tag deletion", ref: "refs/tags/v1", reason: "deletion refused", want: scope.OpGitTagUpdate, ok: true},
		{name: "tag update", ref: "refs/tags/v1", reason: "tag update refused", want: scope.OpGitTagUpdate, ok: true},
		{name: "replace deletion", ref: "refs/replace/abc", reason: "deletion refused", ok: false},
		{name: "replace ref", ref: "refs/replace/abc", reason: "replace refs refused", ok: false},
		{name: "stale client", ref: "refs/heads/main", reason: "client ref is stale", ok: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := grantOperationForPushFailure(gitproxy.Command{Ref: tc.ref}, tc.reason)
			if got != tc.want || ok != tc.ok {
				t.Fatalf("grantOperationForPushFailure() = %q, %v; want %q, %v", got, ok, tc.want, tc.ok)
			}
		})
	}
}

func TestParseGrantTarget(t *testing.T) {
	tests := []struct {
		target string
		ok     bool
		typ    scope.RepoType
	}{
		{target: "model/acme/repo", ok: true, typ: scope.TypeModel},
		{target: "dataset/acme/repo", ok: true, typ: scope.TypeDataset},
		{target: "space/acme/repo", ok: true, typ: scope.TypeSpace},
		{target: "dataset/acme", ok: false},
		{target: "bucket/acme/repo", ok: false},
		{target: "dataset/acme/../repo", ok: false},
		{target: "dataset//repo", ok: false},
		{target: "dataset/acme/bad repo", ok: false},
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
	scp, err := scope.Parse([]byte(`{"repos":[]}`))
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
	broker := newTestBroker(t, dir, upstream.server.URL, &auditLog, `{
		"repos": [{"id": "acme/repo", "type": "dataset", "mode": "append-only"}]
	}`)
	defer broker.Close()

	resp, body := doRequest(t, http.MethodGet, broker.URL+"/healthz", "", nil)
	if resp.StatusCode != http.StatusOK || strings.TrimSpace(body) != `{"ok": true}` {
		t.Fatalf("health = %d %q", resp.StatusCode, body)
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

func TestLFSPassThroughAndPolicy(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	dir := t.TempDir()
	upstreamRepo := seedBareRepo(t, dir)
	upstream := newGitUpstream(t, upstreamRepo, testToken)
	defer upstream.server.Close()
	var auditLog bytes.Buffer
	broker := newTestBroker(t, dir, upstream.server.URL, &auditLog, `{
		"repos": [
			{"id": "acme/repo", "type": "dataset", "mode": "append-only"},
			{"id": "acme/other", "type": "dataset", "mode": "append-only"},
			{"id": "acme/readonly", "type": "dataset", "mode": "read-only"}
		]
	}`)
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
	scp, err := scope.Parse([]byte(`{"repos":[{"id":"acme/repo","type":"dataset","mode":"append-only"}]}`))
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
	resp, _ = doRequest(t, http.MethodGet, server.URL+"/datasets/acme/repo.git/info/refs?service=git-upload-pack", "Bearer "+testSecret, nil)
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("upstream failure status = %d, want 502", resp.StatusCode)
	}
	if rt, ok := parseRepoRoute("/spaces/acme/repo.git/info/refs"); !ok || rt.repoType != scope.TypeSpace {
		t.Fatalf("space route = %+v ok=%v", rt, ok)
	}
	if rt, ok := parseRepoRoute("/acme/repo.git/info/refs"); !ok || rt.repoType != scope.TypeModel {
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
	broker := newTestBroker(t, dir, upstream.server.URL, io.Discard, `{
		"repos": [{"id": "acme/repo", "type": "dataset", "mode": "append-only"}]
	}`)
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
	broker := newTestBroker(t, dir, upstream.server.URL, &auditLog, `{
		"repos": [{"id": "acme/repo", "type": "dataset", "mode": "append-only"}]
	}`)
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

	scp, err := scope.Parse([]byte(`{"repos":[]}`))
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
		repoType: scope.TypeDataset,
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
	scp, err := scope.Parse([]byte(scopeJSON))
	if err != nil {
		t.Fatalf("scope.Parse() error = %v", err)
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
	messages []notify.GrantMessage
	updates  []string
}

func (n *captureGrantNotifier) SendGrantRequest(_ context.Context, msg notify.GrantMessage) (notify.MessageRef, error) {
	n.messages = append(n.messages, msg)
	return notify.MessageRef{Kind: "capture", ChatID: 123, MessageID: len(n.messages), Text: "grant text"}, nil
}

func (n *captureGrantNotifier) UpdateGrantStatus(_ context.Context, _ notify.MessageRef, status string) error {
	n.updates = append(n.updates, status)
	return nil
}

type blockingGrantNotifier struct {
	mu       sync.Mutex
	messages []notify.GrantMessage
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

func (n *blockingGrantNotifier) SendGrantRequest(ctx context.Context, msg notify.GrantMessage) (notify.MessageRef, error) {
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

type zeroMessageGrantNotifier struct {
	calls int
}

func (n *zeroMessageGrantNotifier) SendGrantRequest(context.Context, notify.GrantMessage) (notify.MessageRef, error) {
	n.calls++
	return notify.MessageRef{Kind: "capture", ChatID: 123, Text: "grant text"}, nil
}

type failingGrantNotifier struct{}

func (failingGrantNotifier) SendGrantRequest(context.Context, notify.GrantMessage) (notify.MessageRef, error) {
	return notify.MessageRef{}, errors.New("notify failed")
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
	req, err := http.NewRequest(http.MethodPost, serverURL+"/grants", strings.NewReader(body))
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
