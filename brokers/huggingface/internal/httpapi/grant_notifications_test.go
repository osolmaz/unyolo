package httpapi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/osolmaz/brokerkit/approval"
	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/config"
	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/hfgrant"
	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/hfplan"
	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/policy"
	"github.com/osolmaz/brokerkit/grants"
	"github.com/osolmaz/brokerkit/notify"
)

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
		Audit: testAuditRecorder(),
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
	if _, _, err := requestHFGrant(t, handler.grants, handler.plans, hfgrant.Input{
		Client:            "agent",
		ClientRequestID:   "retry-missing-message",
		Operation:         string(policy.OpGitPushForce),
		PolicyTarget:      &policy.Target{Kind: policy.KindRepo, Type: policy.TypeDataset, Owner: "acme", Name: "repo", Refs: []string{"refs/heads/main"}},
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
		Audit: testAuditRecorder(),
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
		Audit: testAuditRecorder(),
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
	if result.Answer != notify.AnswerApproved || result.Retry {
		t.Fatalf("callback result = %+v", result)
	}
	for _, status := range updates {
		if status.Kind == notify.StatusSuperseded {
			t.Fatalf("callback-owned message was superseded: %+v", status)
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
		Audit: testAuditRecorder(),
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
		Audit: testAuditRecorder(),
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
		Now:             nowFunc,
	})
	if err != nil {
		t.Fatal(err)
	}
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
		Audit: testAuditRecorder(),
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
	plans := testPlanStore(t)
	grant, _, err := requestHFGrant(t, store, plans, hfgrant.Input{
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
	server := &Server{grants: store, plans: plans, planValidator: hfplan.Validator{Store: plans}}

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
	plans := testPlanStore(t)
	grant, _, err := requestHFGrant(t, store, plans, hfgrant.Input{
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
	server := &Server{grants: store, plans: plans, planValidator: hfplan.Validator{Store: plans}}

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
	plans := testPlanStore(t)
	grant, _, err := requestHFGrant(t, store, plans, hfgrant.Input{
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
	server := &Server{grants: store, plans: plans, planValidator: hfplan.Validator{Store: plans}}
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
	grant, _, err := requestHFGrant(t, store, testPlanStore(t), hfgrant.Input{
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

	if len(notifier.updates) != 1 || notifier.updates[0].Kind != notify.StatusRetained {
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

func TestGrantStatusUpdatesUseSharedStates(t *testing.T) {
	tests := []struct {
		name   string
		update grants.StatusUpdate
		want   notify.StatusKind
	}{
		{
			name:   "active",
			update: grants.StatusUpdate{Status: grants.StatusActive},
			want:   notify.StatusActive,
		},
		{
			name:   "denied",
			update: grants.StatusUpdate{Status: grants.StatusDenied},
			want:   notify.StatusDenied,
		},
		{
			name:   "consumed",
			update: grants.StatusUpdate{Kind: grants.StatusUpdateUsed, Status: grants.StatusConsumed, Grant: grants.Grant{Status: grants.StatusConsumed, MaxUses: 1, UsedCount: 1}},
			want:   notify.StatusConsumed,
		},
		{
			name:   "reserved",
			update: grants.StatusUpdate{Kind: grants.StatusUpdateRetainedReservation, Status: grants.StatusActive, Grant: grants.Grant{Status: grants.StatusActive, MaxUses: 2, UsedCount: 1, ReservedCount: 1}},
			want:   notify.StatusRetained,
		},
		{
			name:   "reserved expired",
			update: grants.StatusUpdate{Kind: grants.StatusUpdateRetainedReservation, Status: grants.StatusExpired, Grant: grants.Grant{Status: grants.StatusExpired, MaxUses: 3, UsedCount: 1, ReservedCount: 1}},
			want:   notify.StatusRetained,
		},
		{
			name:   "expired",
			update: grants.StatusUpdate{Status: grants.StatusExpired, Grant: grants.Grant{ExpiredFrom: grants.StatusActive}},
			want:   notify.StatusActiveExpired,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := approval.StatusForUpdate(tc.update); got.Kind != tc.want {
				t.Fatalf("StatusForUpdate() = %+v, want %q", got, tc.want)
			}
		})
	}
}
