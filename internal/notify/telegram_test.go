package notify

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	bktelegram "github.com/osolmaz/brokerkit/notify/telegram"
)

func TestTelegramSendGrantRequest(t *testing.T) {
	state := &telegramServerState{}
	server := newTelegramServer(t, state)
	defer server.Close()
	telegram := NewTelegram("telegram_token_value", 123, server.Client(), server.URL)

	ref, err := telegram.SendGrantRequest(context.Background(), forcePushMessage(time.Date(2026, 7, 6, 1, 2, 3, 0, time.UTC)))
	if err != nil {
		t.Fatalf("SendGrantRequest() error = %v", err)
	}
	if ref.Kind != "telegram" || ref.ChatID != 123 || ref.MessageID != 7 || ref.Text == "" {
		t.Fatalf("message ref = %+v", ref)
	}
	assertForcePushText(t, state.sent["text"].(string))
	assertApprovalButtons(t, state.sent)
}

func TestTelegramGrantTextShowsNonPushUses(t *testing.T) {
	text := grantText(GrantMessage{
		Client:           "agent",
		Operation:        "repo.contents.read",
		Mode:             "window",
		Target:           "dataset/acme/repo",
		Attrs:            map[string]any{"max_bytes": int64(12)},
		Reason:           "inspect one file",
		RequestedMinutes: 5,
		MaxUses:          1,
		PendingExpiresAt: time.Date(2026, 7, 6, 1, 2, 3, 0, time.UTC),
	})
	for _, want := range []string{
		"agent is asking to read repo contents.",
		"⚙️ Mode: window",
		`🏷️ Attrs: {"max_bytes":12}`,
		"🔁 Uses: 1 use",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("grantText() missing %q in %q", want, text)
		}
	}
	if strings.Contains(text, "push") || strings.Contains(text, "🌿 Ref:") {
		t.Fatalf("grantText() has push/ref wording for non-push grant: %q", text)
	}
}

func TestTelegramPollOnceAcceptsOnlyConfiguredChat(t *testing.T) {
	state := &telegramServerState{updates: pollUpdates("g2", "t2")}
	server := newTelegramServer(t, state)
	defer server.Close()
	telegram := NewTelegram("telegram_token_value", 123, server.Client(), server.URL)
	var decisions []Decision

	offset, err := telegram.PollOnce(context.Background(), 0, func(_ context.Context, decision Decision) DecisionResult {
		decisions = append(decisions, decision)
		return DecisionResult{Answer: "handled"}
	})
	if err != nil {
		t.Fatalf("PollOnce() error = %v", err)
	}
	if offset != 12 {
		t.Fatalf("offset = %d, want 12", offset)
	}
	assertPolledDecision(t, decisions)
	assertAnswers(t, state.answers)
	assertEditStatus(t, state.edits, "Status: handled")
}

func TestTelegramTracksPendingAndActiveExpiry(t *testing.T) {
	now := time.Date(2026, 7, 6, 1, 2, 3, 0, time.UTC)
	state := &telegramServerState{updates: pollUpdates("grant-id", "decision-token")}
	server := newTelegramServer(t, state)
	defer server.Close()
	telegram := NewTelegram("telegram_token_value", 123, server.Client(), server.URL)

	_, err := telegram.SendGrantRequest(context.Background(), forcePushMessage(now.Add(time.Minute)))
	if err != nil {
		t.Fatalf("SendGrantRequest() error = %v", err)
	}
	telegram.expireTracked(context.Background(), now.Add(time.Minute))
	assertEditStatus(t, state.edits, "Status: ⌛ Expired. Request was not approved in time.")

	if _, err := telegram.PollOnce(context.Background(), 0, activeDecision(now.Add(5*time.Minute))); err != nil {
		t.Fatalf("PollOnce() error = %v", err)
	}
	telegram.expireTracked(context.Background(), now.Add(5*time.Minute))
	assertEditStatus(t, state.edits[2:], "Status: ⌛ Expired. Access window ended.")
}

func TestTelegramTerminalUpdateClearsTrackedExpiry(t *testing.T) {
	now := time.Date(2026, 7, 6, 1, 2, 3, 0, time.UTC)
	state := &telegramServerState{updates: pollUpdates("grant-id", "decision-token")}
	server := newTelegramServer(t, state)
	defer server.Close()
	telegram := NewTelegram("telegram_token_value", 123, server.Client(), server.URL)

	ref, err := telegram.SendGrantRequest(context.Background(), forcePushMessage(now.Add(time.Minute)))
	if err != nil {
		t.Fatalf("SendGrantRequest() error = %v", err)
	}
	if _, err := telegram.PollOnce(context.Background(), 0, activeDecision(now.Add(5*time.Minute))); err != nil {
		t.Fatalf("PollOnce() error = %v", err)
	}
	if err := telegram.UpdateGrantStatus(context.Background(), ref, "✅ Used. Access is now closed."); err != nil {
		t.Fatalf("UpdateGrantStatus() error = %v", err)
	}
	telegram.expireTracked(context.Background(), now.Add(5*time.Minute))
	if len(state.edits) != 2 {
		t.Fatalf("edits after terminal update = %+v, want decision and used only", state.edits)
	}
	assertEditStatus(t, state.edits[1:], "Status: ✅ Used. Access is now closed.")
}

func TestTelegramPostErrorsDoNotExposeToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "nope", http.StatusInternalServerError)
	}))
	defer server.Close()
	telegram := NewTelegram("telegram_token_value", 123, server.Client(), server.URL)
	_, err := telegram.SendGrantRequest(context.Background(), forcePushMessage(time.Now()))
	if err == nil {
		t.Fatalf("SendGrantRequest() succeeded, want error")
	}
	if strings.Contains(err.Error(), "telegram_token_value") {
		t.Fatalf("error leaked telegram token: %v", err)
	}

	telegram = NewTelegram("telegram_token_value", 123, server.Client(), "://bad")
	if _, err := telegram.SendGrantRequest(context.Background(), GrantMessage{}); err == nil || strings.Contains(err.Error(), "telegram_token_value") {
		t.Fatalf("bad URL error = %v, want sanitized error", err)
	}
}

func TestTelegramPollStopsWhenCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	NewTelegram("token", 1, nil, "").Poll(ctx, func(context.Context, Decision) DecisionResult {
		t.Fatal("handler should not be called")
		return DecisionResult{}
	})
}

type telegramServerState struct {
	sent    map[string]any
	answers []string
	edits   []map[string]any
	updates string
}

func newTelegramServer(t *testing.T, state *telegramServerState) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/sendMessage"):
			state.sent = decodePayload(t, r)
			_, _ = w.Write([]byte(`{"ok":true,"result":{"message_id":7,"chat":{"id":123}}}`))
		case strings.HasSuffix(r.URL.Path, "/getUpdates"):
			_, _ = w.Write([]byte(state.updates))
		case strings.HasSuffix(r.URL.Path, "/answerCallbackQuery"):
			payload := decodePayload(t, r)
			state.answers = append(state.answers, payload["callback_query_id"].(string)+":"+payload["text"].(string))
			_, _ = w.Write([]byte(`{"ok":true}`))
		case strings.HasSuffix(r.URL.Path, "/editMessageText"):
			state.edits = append(state.edits, decodePayload(t, r))
			_, _ = w.Write([]byte(`{"ok":true}`))
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
	}))
}

func forcePushMessage(pendingExpiresAt time.Time) GrantMessage {
	return GrantMessage{
		ID:               "grant-id",
		DecisionToken:    "decision-token",
		Client:           "agent",
		Operation:        "git.push.force",
		Mode:             "window",
		Target:           "dataset/acme/repo",
		Ref:              "refs/heads/main",
		Attrs:            map[string]any{"ref_change": "non_fast_forward"},
		Reason:           "recover",
		RequestedMinutes: 15,
		MaxUses:          3,
		PendingExpiresAt: pendingExpiresAt,
	}
}

func pollUpdates(id string, token string) string {
	wrong := bktelegram.CallbackData(DecisionApprove, "g1", "t1")
	right := bktelegram.CallbackData(DecisionDeny, id, token)
	return `{"ok":true,"result":[` +
		`{"update_id":10,"callback_query":{"id":"wrong","from":{"id":1,"username":"bad"},"message":{"message_id":41,"chat":{"id":999},"text":"Approval"},"data":"` + wrong + `"}},` +
		`{"update_id":11,"callback_query":{"id":"right","from":{"id":2,"username":"operator"},"message":{"message_id":7,"chat":{"id":123},"text":"🔐 Approval needed for hf-broker"},"data":"` + right + `"}}` +
		`]}`
}

func activeDecision(expiresAt time.Time) DecisionHandler {
	return func(context.Context, Decision) DecisionResult {
		return DecisionResult{Answer: "Grant approved", ActiveExpiresAt: expiresAt}
	}
}

func decodePayload(t *testing.T, r *http.Request) map[string]any {
	t.Helper()
	var payload map[string]any
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		t.Fatal(err)
	}
	return payload
}

func assertForcePushText(t *testing.T, text string) {
	t.Helper()
	for _, want := range []string{
		"🔐 Approval needed for hf-broker",
		"agent is asking to force-push / rewrite Git history.",
		"⚙️ Mode: window",
		`🏷️ Attrs: {"ref_change":"non_fast_forward"}`,
		"⏱️ Access: 15 minutes",
		"🔁 Uses: up to 3 pushes",
		"⚠️ Approve only if this looks right.",
		"dataset/acme/repo",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("message text missing %q in %q", want, text)
		}
	}
	if strings.Contains(text, "decision-token") {
		t.Fatalf("message text leaked decision token: %q", text)
	}
}

func assertApprovalButtons(t *testing.T, sent map[string]any) {
	t.Helper()
	row := sent["reply_markup"].(map[string]any)["inline_keyboard"].([]any)[0].([]any)
	if row[0].(map[string]any)["text"] != "✅ Approve" || row[1].(map[string]any)["text"] != "❌ Deny" {
		t.Fatalf("button row = %+v", row)
	}
	action, id, token, ok := bktelegram.ParseCallbackData(row[0].(map[string]any)["callback_data"].(string))
	if !ok || action != DecisionApprove || id != "grant-id" || token != "decision-token" {
		t.Fatalf("approve callback = %q %q %q %v", action, id, token, ok)
	}
}

func assertPolledDecision(t *testing.T, decisions []Decision) {
	t.Helper()
	if len(decisions) != 1 {
		t.Fatalf("decisions = %+v, want one", decisions)
	}
	if decisions[0].ID != "g2" || decisions[0].Token != "t2" || decisions[0].Action != DecisionDeny || decisions[0].OperatorTag != "operator" {
		t.Fatalf("decision = %+v", decisions[0])
	}
}

func assertAnswers(t *testing.T, answers []string) {
	t.Helper()
	if len(answers) != 2 || answers[0] != "wrong:Grant decision ignored" || answers[1] != "right:handled" {
		t.Fatalf("answers = %+v", answers)
	}
}

func assertEditStatus(t *testing.T, edits []map[string]any, want string) {
	t.Helper()
	if len(edits) == 0 {
		t.Fatalf("edits = %+v, want status %q", edits, want)
	}
	if text := edits[len(edits)-1]["text"].(string); !strings.Contains(text, want) {
		t.Fatalf("edit text = %q, want %q", text, want)
	}
}
