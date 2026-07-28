package httpapi

import (
	"bytes"
	"context"
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

	"github.com/osolmaz/unyolo/approval/notifier"
	"github.com/osolmaz/unyolo/authorization/grants"
	"github.com/osolmaz/unyolo/brokers/huggingface/internal/config"
	"github.com/osolmaz/unyolo/brokers/huggingface/internal/gitproxy"
	"github.com/osolmaz/unyolo/brokers/huggingface/internal/policy"
	"github.com/osolmaz/unyolo/telemetry/audit"
)

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
	resp, refusal := doRequest(t, http.MethodGet, infoRefs, "Bearer "+testSecret, nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("fetch before grant = %d, want 403", resp.StatusCode)
	}
	if got := upstream.totalHits(); got != beforeGrant {
		t.Fatalf("fetch before grant reached upstream: hits=%d want %d", got, beforeGrant)
	}
	automatic, err := handler.grants.ListForClient("agent")
	if err != nil || len(automatic) != 1 || !strings.Contains(refusal, automatic[0].ID) {
		t.Fatalf("automatic fetch approval = %+v, err=%v, refusal=%q", automatic, err, refusal)
	}
	if err := handler.grants.Cancel(automatic[0].ID); err != nil {
		t.Fatal(err)
	}

	body := apiGrantRequestJSON(policy.OpGitFetch, "", "read once", "fetch-once", 0, 0)
	resp, text := doRequest(t, http.MethodPost, broker.URL+"/api/grants", "Bearer "+testSecret, strings.NewReader(body))
	if resp.StatusCode != http.StatusAccepted || len(notifier.messages) != 1 {
		t.Fatalf("fetch grant request = %d %s messages=%d, want 202 and one message", resp.StatusCode, text, len(notifier.messages))
	}
	msg := notifier.messages[0]
	answer := handler.handleTelegramDecision(context.Background(), telegramGrantDecision(notify.ActionApprove, msg))
	if answer.Answer != notify.AnswerApproved {
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

func TestRewriteLFSBatchResponseRefusesXetWithoutLeakingActions(t *testing.T) {
	t.Parallel()
	server := &Server{lfsActions: map[string]lfsAction{}}
	request := httptest.NewRequest(http.MethodPost, "http://broker/datasets/acme/repo.git/info/lfs/objects/batch", nil)
	body := `{"transfer":"xet","objects":[{"oid":"` + strings.Repeat("a", 64) + `","size":1,"actions":{"download":{"href":"https://cas.example/signed?secret=value","header":{"Authorization":"secret"}}}}]}`
	result, err := server.rewriteLFSBatchResponse(request, "agent", route{repoType: policy.TypeDataset, owner: "acme", name: "repo"}, strings.NewReader(body))
	if !errors.Is(err, errUnsupportedXet) || result != nil {
		t.Fatalf("rewrite = %s, %v", result, err)
	}
	if len(server.lfsActions) != 0 {
		t.Fatal("unsupported Xet response registered an action")
	}
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
		Audit: testAuditRecorder(),
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
	resp, refusal := doRequest(t, http.MethodPost, batchURL, "Bearer "+testSecret, strings.NewReader(fmt.Sprintf(`{"operation":"download","objects":[{"oid":%q,"size":123}]}`, oid)))
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("LFS batch before grant = %d, want 403", resp.StatusCode)
	}
	if got := upstream.totalHits(); got != beforeGrant {
		t.Fatalf("LFS batch before grant reached upstream: hits=%d want %d", got, beforeGrant)
	}
	automatic, err := handler.grants.ListForClient("agent")
	if err != nil || len(automatic) != 1 || !strings.Contains(refusal, automatic[0].ID) {
		t.Fatalf("automatic LFS approval = %+v, err=%v, refusal=%q", automatic, err, refusal)
	}
	if err := handler.grants.Cancel(automatic[0].ID); err != nil {
		t.Fatal(err)
	}

	grantBody := apiGrantRequestJSON(policy.OpRepoContentsRead, "", "download one LFS object", "lfs-download", 0, 0)
	resp, text := doRequest(t, http.MethodPost, broker.URL+"/api/grants", "Bearer "+testSecret, strings.NewReader(grantBody))
	if resp.StatusCode != http.StatusAccepted || len(notifier.messages) != 1 {
		t.Fatalf("LFS grant request = %d %s messages=%d, want 202 and one message", resp.StatusCode, text, len(notifier.messages))
	}
	msg := notifier.messages[0]
	answer := handler.handleTelegramDecision(context.Background(), telegramGrantDecision(notify.ActionApprove, msg))
	if answer.Answer != notify.AnswerApproved {
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
		Audit: testAuditRecorder(),
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
	if answer.Answer != notify.AnswerApproved {
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
