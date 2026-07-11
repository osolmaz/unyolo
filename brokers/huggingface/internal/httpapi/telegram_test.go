package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/osolmaz/brokerkit/controlplane"
	"github.com/osolmaz/brokerkit/grants"
	"github.com/osolmaz/brokerkit/notify"
	bktelegram "github.com/osolmaz/brokerkit/notify/telegram"
	"github.com/osolmaz/hf-broker/internal/hfgrant"
)

func TestTelegramDecisionRetriesDurableStatusAfterRestart(t *testing.T) {
	bot := &fakeTelegramBot{failFirstEdit: true}
	botAPI := httptest.NewServer(http.HandlerFunc(bot.serveHTTP))
	defer botAPI.Close()

	client, err := bktelegram.NewWithOptions("telegram_token_value", 123, botAPI.Client(), botAPI.URL, bktelegram.Options{
		IgnoredAnswer: "Grant decision ignored",
		ApproveText:   "✅ Approve",
		DenyText:      "❌ Deny",
	})
	if err != nil {
		t.Fatal(err)
	}
	path := t.TempDir() + "/grants.json"
	store := grants.New(path, grants.Options{})
	requested, _, err := requestHFGrant(store, hfgrant.Input{
		Client:            "agent",
		ClientRequestID:   "telegram-restart",
		Operation:         "git.push.force",
		Mode:              hfgrant.ModeWindow,
		Target:            "dataset/acme/repo",
		Ref:               "refs/heads/main",
		Attrs:             map[string]any{"ref_change": "non_fast_forward"},
		Reason:            "recover main",
		RequestedDuration: 5 * time.Minute,
		PendingTimeout:    10 * time.Minute,
		MaxUses:           1,
	})
	if err != nil {
		t.Fatal(err)
	}
	claimed, ok, err := store.ClaimNotification(requested.ID, time.Minute)
	if err != nil || !ok {
		t.Fatalf("ClaimNotification() = %+v, %v, %v", claimed, ok, err)
	}
	ref, err := client.SendApproval(context.Background(), grantApprovalMessage(claimed.Grant, claimed.DecisionToken))
	if err != nil {
		t.Fatalf("SendApproval() error = %v", err)
	}
	if _, recorded, err := store.SetNotificationIfClaimed(claimed.Grant.ID, claimed.Grant.NotificationClaimedAt, ref); err != nil || !recorded {
		t.Fatalf("SetNotificationIfClaimed() recorded=%v err=%v", recorded, err)
	}
	bot.callbackData = bktelegram.CallbackData(notify.ActionApprove, claimed.Grant.ID, claimed.DecisionToken)

	server := newTelegramDecisionTestServer(t, store, client)
	offset, err := client.PollOnce(context.Background(), 0, server.handleTelegramDecision)
	if err != nil || offset != 2 {
		t.Fatalf("PollOnce() offset=%d err=%v", offset, err)
	}
	if bot.editAttempts != 0 || len(bot.answers) != 1 || bot.answers[0] != "Grant approved" {
		t.Fatalf("callback performed edit before acknowledgement: edits=%d answers=%+v", bot.editAttempts, bot.answers)
	}
	afterDecision, err := store.Get(claimed.Grant.ID)
	if err != nil {
		t.Fatal(err)
	}
	if afterDecision.Status != grants.StatusActive || afterDecision.NotificationStatus == string(grants.StatusActive) {
		t.Fatalf("grant after failed edit = %+v, want active with status still due", afterDecision)
	}

	server.sweepGrantNotifications(context.Background())
	if bot.editAttempts != 1 {
		t.Fatalf("first durable sweep edit attempts = %d, want one failed attempt", bot.editAttempts)
	}

	restartedStore := grants.New(path, grants.Options{})
	restarted := newTelegramDecisionTestServer(t, restartedStore, client)
	restarted.sweepGrantNotifications(context.Background())
	if bot.editAttempts != 2 || !strings.Contains(bot.edits[1], "Status: ✅ Approved. Access is active.") {
		t.Fatalf("restart edits = %+v attempts=%d", bot.edits, bot.editAttempts)
	}
	delivered, err := restartedStore.Get(claimed.Grant.ID)
	if err != nil || delivered.NotificationStatus != string(grants.StatusActive) {
		t.Fatalf("delivered grant = %+v err=%v", delivered, err)
	}

	if _, err := client.PollOnce(context.Background(), 0, restarted.handleTelegramDecision); err != nil {
		t.Fatalf("replay PollOnce() error = %v", err)
	}
	if bot.editAttempts != 2 {
		t.Fatalf("replay caused an implicit edit: attempts=%d", bot.editAttempts)
	}
	if len(bot.answers) != 2 || bot.answers[0] != "Grant approved" || bot.answers[1] != "Grant is no longer pending" {
		t.Fatalf("callback answers = %+v", bot.answers)
	}
	if !strings.Contains(bot.sentText, "Approval needed for hf-broker") || strings.Contains(bot.sentText, claimed.DecisionToken) {
		t.Fatalf("approval text missing HF summary or leaked token: %q", bot.sentText)
	}
}

func TestTelegramCallbackRecoversReferenceAfterAmbiguousSend(t *testing.T) {
	bot := &fakeTelegramBot{}
	botAPI := httptest.NewServer(http.HandlerFunc(bot.serveHTTP))
	defer botAPI.Close()
	client, err := bktelegram.New("telegram_token_value", 123, botAPI.Client(), botAPI.URL)
	if err != nil {
		t.Fatal(err)
	}
	store := grants.New(t.TempDir()+"/grants.json", grants.Options{})
	requested, _, err := requestHFGrant(store, hfgrant.Input{
		Client:    "agent",
		Operation: "git.push.force",
		Mode:      hfgrant.ModeWindow,
		Target:    "dataset/acme/repo",
		Ref:       "refs/heads/main",
		Reason:    "recover main",
	})
	if err != nil {
		t.Fatal(err)
	}
	claimed, ok, err := store.ClaimNotification(requested.ID, time.Minute)
	if err != nil || !ok {
		t.Fatalf("ClaimNotification() = %+v claimed=%v err=%v", claimed, ok, err)
	}
	if _, retained, err := store.RetainNotificationClaim(claimed.Grant.ID, claimed.Grant.NotificationClaimedAt); err != nil || !retained {
		t.Fatalf("RetainNotificationClaim() retained=%v err=%v", retained, err)
	}
	bot.sentText = approvalTextForTest(claimed)
	bot.callbackData = bktelegram.CallbackData(notify.ActionApprove, claimed.Grant.ID, claimed.DecisionToken)
	server := newTelegramDecisionTestServer(t, store, client)
	if _, err := client.PollOnce(context.Background(), 0, server.handleTelegramDecision); err != nil {
		t.Fatal(err)
	}
	stored, err := store.Get(claimed.Grant.ID)
	if err != nil || stored.Status != grants.StatusActive || stored.Notification == nil || stored.Notification.MessageID != 7 || stored.Notification.Text != bot.sentText {
		t.Fatalf("recovered callback grant = %+v err=%v", stored, err)
	}
	if bot.editAttempts != 0 || len(bot.answers) != 1 || bot.answers[0] != "Grant approved" {
		t.Fatalf("callback was not acknowledged before edit: edits=%d answers=%+v", bot.editAttempts, bot.answers)
	}
	server.sweepGrantNotifications(context.Background())
	if bot.editAttempts != 1 || !strings.Contains(bot.edits[0], "Status: ✅ Approved. Access is active.") {
		t.Fatalf("recovered status edits = %+v attempts=%d", bot.edits, bot.editAttempts)
	}
}

func TestTelegramCallbackRetriesAfterDurableWriteFailure(t *testing.T) {
	bot := &fakeTelegramBot{}
	botAPI := httptest.NewServer(http.HandlerFunc(bot.serveHTTP))
	defer botAPI.Close()
	client, err := bktelegram.New("telegram_token_value", 123, botAPI.Client(), botAPI.URL)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	store := grants.New(dir+"/grants.json", grants.Options{})
	requested, _, err := requestHFGrant(store, hfgrant.Input{
		Client: "agent", Operation: "git.push.force", Mode: hfgrant.ModeWindow,
		Target: "dataset/acme/repo", Ref: "refs/heads/main", Reason: "recover main",
	})
	if err != nil {
		t.Fatal(err)
	}
	claimed, ok, err := store.ClaimNotification(requested.ID, time.Minute)
	if err != nil || !ok {
		t.Fatalf("ClaimNotification() = %+v claimed=%v err=%v", claimed, ok, err)
	}
	bot.sentText = approvalTextForTest(claimed)
	bot.callbackData = bktelegram.CallbackData(notify.ActionApprove, claimed.Grant.ID, claimed.DecisionToken)
	server := newTelegramDecisionTestServer(t, store, client)
	if err := os.Chmod(dir, 0o500); err != nil { // #nosec G302 -- test intentionally blocks atomic replacement.
		t.Fatal(err)
	}
	offset, pollErr := client.PollOnce(context.Background(), 0, server.handleTelegramDecision)
	if err := os.Chmod(dir, 0o700); err != nil { // #nosec G302 -- restore access to the private test directory.
		t.Fatal(err)
	}
	if pollErr == nil {
		t.Skip("filesystem does not enforce directory write permissions")
	}
	if !errors.Is(pollErr, bktelegram.ErrDecisionRetry) || offset != 0 || len(bot.answers) != 0 {
		t.Fatalf("failed callback offset=%d answers=%v err=%v", offset, bot.answers, pollErr)
	}
	pending, err := store.Get(claimed.Grant.ID)
	if err != nil || pending.Status != grants.StatusPending || pending.Notification != nil {
		t.Fatalf("grant after failed callback = %+v err=%v", pending, err)
	}
	offset, err = client.PollOnce(context.Background(), offset, server.handleTelegramDecision)
	if err != nil || offset != 2 || len(bot.answers) != 1 || bot.answers[0] != "Grant approved" {
		t.Fatalf("retried callback offset=%d answers=%v err=%v", offset, bot.answers, err)
	}
	active, err := store.Get(claimed.Grant.ID)
	if err != nil || active.Status != grants.StatusActive || active.Notification == nil {
		t.Fatalf("grant after callback retry = %+v err=%v", active, err)
	}
}

func approvalTextForTest(claim grants.NotificationClaim) string {
	return grantApprovalMessage(claim.Grant, claim.DecisionToken).Text
}

func newTelegramDecisionTestServer(t *testing.T, store *grants.Store, notifier notify.Notifier) *Server {
	t.Helper()
	runtime, err := controlplane.New(controlplane.Options{
		Broker:        "hf-broker",
		Store:         store,
		ClientSecrets: map[string]string{"agent": testSecret},
	})
	if err != nil {
		t.Fatal(err)
	}
	return &Server{grants: store, notifier: notifier, control: runtime}
}

type fakeTelegramBot struct {
	callbackData  string
	sentText      string
	answers       []string
	edits         []string
	editAttempts  int
	failFirstEdit bool
}

func (b *fakeTelegramBot) serveHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case strings.HasSuffix(r.URL.Path, "/sendMessage"):
		payload := decodeTelegramPayload(r)
		b.sentText, _ = payload["text"].(string)
		_, _ = w.Write([]byte(`{"ok":true,"result":{"message_id":7,"chat":{"id":123}}}`))
	case strings.HasSuffix(r.URL.Path, "/getUpdates"):
		_, _ = w.Write([]byte(`{"ok":true,"result":[{"update_id":1,"callback_query":{"id":"callback-1","from":{"id":42,"username":"operator"},"message":{"message_id":7,"chat":{"id":123},"text":` + quotedJSON(b.sentText) + `},"data":` + quotedJSON(b.callbackData) + `}}]}`))
	case strings.HasSuffix(r.URL.Path, "/answerCallbackQuery"):
		payload := decodeTelegramPayload(r)
		answer, _ := payload["text"].(string)
		b.answers = append(b.answers, answer)
		_, _ = w.Write([]byte(`{"ok":true}`))
	case strings.HasSuffix(r.URL.Path, "/editMessageText"):
		payload := decodeTelegramPayload(r)
		text, _ := payload["text"].(string)
		b.edits = append(b.edits, text)
		b.editAttempts++
		if b.failFirstEdit && b.editAttempts == 1 {
			http.Error(w, "temporary failure", http.StatusBadGateway)
			return
		}
		_, _ = w.Write([]byte(`{"ok":true}`))
	default:
		http.Error(w, "unexpected Telegram method", http.StatusNotFound)
	}
}

func decodeTelegramPayload(r *http.Request) map[string]any {
	var payload map[string]any
	_ = json.NewDecoder(r.Body).Decode(&payload)
	return payload
}

func quotedJSON(value string) string {
	data, _ := json.Marshal(value)
	return string(data)
}
