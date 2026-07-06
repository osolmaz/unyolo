package notify

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestTelegramSendGrantRequest(t *testing.T) {
	var sent map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/sendMessage") {
			t.Fatalf("path = %s, want sendMessage", r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&sent); err != nil {
			t.Fatal(err)
		}
		_, _ = w.Write([]byte(`{"ok":true,"result":{"message_id":1}}`))
	}))
	defer server.Close()
	telegram := NewTelegram("telegram_token_value", 123, server.Client(), server.URL)

	err := telegram.SendGrantRequest(context.Background(), GrantMessage{
		ID:               "grant-id",
		DecisionToken:    "decision-token",
		Client:           "agent",
		Operation:        "git_receive_pack",
		Target:           "dataset/acme/repo",
		Ref:              "refs/heads/main",
		Reason:           "recover",
		RequestedMinutes: 15,
		PendingExpiresAt: time.Date(2026, 7, 6, 1, 2, 3, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("SendGrantRequest() error = %v", err)
	}
	if sent["chat_id"].(float64) != 123 {
		t.Fatalf("chat_id = %v, want 123", sent["chat_id"])
	}
	text := sent["text"].(string)
	if !strings.Contains(text, "Approval needed for hf-broker") ||
		!strings.Contains(text, "agent is asking to push to a Git repo.") ||
		!strings.Contains(text, "Access: 15 minutes") ||
		!strings.Contains(text, "Request expires: 2026-07-06 01:02 UTC") ||
		!strings.Contains(text, "Approve only if this looks right.") ||
		!strings.Contains(text, "dataset/acme/repo") ||
		strings.Contains(text, "decision-token") {
		t.Fatalf("unexpected message text: %q", text)
	}
	replyMarkup := sent["reply_markup"].(map[string]any)
	keyboard := replyMarkup["inline_keyboard"].([]any)
	row := keyboard[0].([]any)
	approve := row[0].(map[string]any)
	if approve["callback_data"] != "hfbg:approve:grant-id:decision-token" {
		t.Fatalf("approve callback = %v", approve["callback_data"])
	}
}

func TestTelegramPollOnceAcceptsOnlyConfiguredChat(t *testing.T) {
	var answered []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/getUpdates"):
			_, _ = w.Write([]byte(`{"ok":true,"result":[` +
				`{"update_id":10,"callback_query":{"id":"wrong","from":{"id":1,"username":"bad"},"message":{"chat":{"id":999}},"data":"hfbg:approve:g1:t1"}},` +
				`{"update_id":11,"callback_query":{"id":"right","from":{"id":2,"username":"operator"},"message":{"chat":{"id":123}},"data":"hfbg:deny:g2:t2"}}` +
				`]}`))
		case strings.HasSuffix(r.URL.Path, "/answerCallbackQuery"):
			var payload map[string]any
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Fatal(err)
			}
			answered = append(answered, payload["callback_query_id"].(string)+":"+payload["text"].(string))
			_, _ = w.Write([]byte(`{"ok":true,"result":true}`))
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
	}))
	defer server.Close()
	telegram := NewTelegram("telegram_token_value", 123, server.Client(), server.URL)
	telegram.pollTimeoutSeconds = 0
	var decisions []Decision

	offset, err := telegram.PollOnce(context.Background(), 0, func(_ context.Context, decision Decision) string {
		decisions = append(decisions, decision)
		return "handled"
	})
	if err != nil {
		t.Fatalf("PollOnce() error = %v", err)
	}
	if offset != 12 {
		t.Fatalf("offset = %d, want 12", offset)
	}
	if len(decisions) != 1 || decisions[0].ID != "g2" || decisions[0].Action != DecisionDeny || decisions[0].OperatorTag != "operator" {
		t.Fatalf("decisions = %+v", decisions)
	}
	if len(answered) != 2 || answered[0] != "wrong:Grant decision ignored" || answered[1] != "right:handled" {
		t.Fatalf("answered = %+v", answered)
	}
}

func TestTelegramPostErrorsDoNotExposeToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusInternalServerError)
	}))
	defer server.Close()
	telegram := NewTelegram("telegram_token_value", 123, server.Client(), server.URL)
	err := telegram.SendGrantRequest(context.Background(), GrantMessage{
		ID:               "grant-id",
		DecisionToken:    "decision-token",
		Client:           "agent",
		Operation:        "git_receive_pack",
		Target:           "dataset/acme/repo",
		Ref:              "refs/heads/main",
		Reason:           "recover",
		RequestedMinutes: 15,
		PendingExpiresAt: time.Now(),
	})
	if err == nil {
		t.Fatalf("SendGrantRequest() succeeded, want error")
	}
	if strings.Contains(err.Error(), "telegram_token_value") {
		t.Fatalf("error leaked telegram token: %v", err)
	}

	telegram = NewTelegram("telegram_token_value", 123, server.Client(), "://bad")
	if err := telegram.SendGrantRequest(context.Background(), GrantMessage{}); err == nil || strings.Contains(err.Error(), "telegram_token_value") {
		t.Fatalf("bad URL error = %v, want sanitized error", err)
	}
}

func TestTelegramParsingHelpers(t *testing.T) {
	telegram := NewTelegram("token", 1, nil, "")
	if telegram.baseURL != defaultTelegramBaseURL {
		t.Fatalf("baseURL = %q, want default", telegram.baseURL)
	}
	tests := []string{
		"",
		"other:approve:g:t",
		"hfbg:maybe:g:t",
		"hfbg:approve::t",
		"hfbg:approve:g:",
	}
	for _, data := range tests {
		if _, _, _, err := parseCallbackData(data); err == nil {
			t.Fatalf("parseCallbackData(%q) succeeded, want error", data)
		}
	}
	if decision, ok := parseDecision(telegramUpdate{}); ok || decision.ID != "" {
		t.Fatalf("parseDecision(empty) = %+v %v, want no decision", decision, ok)
	}
	if decision, ok := parseDecision(telegramUpdate{CallbackQuery: &telegramCallbackQuery{ID: "cb", Data: "hfbg:approve:g:t"}}); ok || decision.ID != "" {
		t.Fatalf("parseDecision(no message) = %+v %v, want no decision", decision, ok)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	wait(ctx, time.Hour)
}

func TestTelegramPollStopsWhenCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	NewTelegram("token", 1, nil, "").Poll(ctx, func(context.Context, Decision) string {
		t.Fatal("handler should not be called")
		return ""
	})
}
