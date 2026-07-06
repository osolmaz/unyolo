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
		_, _ = w.Write([]byte(`{"ok":true,"result":{"message_id":1,"chat":{"id":123}}}`))
	}))
	defer server.Close()
	telegram := NewTelegram("telegram_token_value", 123, server.Client(), server.URL)

	ref, err := telegram.SendGrantRequest(context.Background(), GrantMessage{
		ID:               "grant-id",
		DecisionToken:    "decision-token",
		Client:           "agent",
		Operation:        "git_history_rewrite",
		Target:           "dataset/acme/repo",
		Ref:              "refs/heads/main",
		Reason:           "recover",
		RequestedMinutes: 15,
		MaxUses:          3,
		PendingExpiresAt: time.Date(2026, 7, 6, 1, 2, 3, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("SendGrantRequest() error = %v", err)
	}
	if ref.Kind != "telegram" || ref.ChatID != 123 || ref.MessageID != 1 || ref.Text == "" {
		t.Fatalf("message ref = %+v", ref)
	}
	if sent["chat_id"].(float64) != 123 {
		t.Fatalf("chat_id = %v, want 123", sent["chat_id"])
	}
	text := sent["text"].(string)
	if !strings.Contains(text, "🔐 Approval needed for hf-broker") ||
		!strings.Contains(text, "agent is asking to force-push / rewrite Git history.") ||
		!strings.Contains(text, "⏱️ Access: 15 minutes") ||
		!strings.Contains(text, "🔁 Uses: up to 3 pushes") ||
		!strings.Contains(text, "⌛ Request expires: 2026-07-06 01:02 UTC") ||
		!strings.Contains(text, "⚠️ Approve only if this looks right.") ||
		!strings.Contains(text, "dataset/acme/repo") ||
		strings.Contains(text, "decision-token") {
		t.Fatalf("unexpected message text: %q", text)
	}
	replyMarkup := sent["reply_markup"].(map[string]any)
	keyboard := replyMarkup["inline_keyboard"].([]any)
	row := keyboard[0].([]any)
	approve := row[0].(map[string]any)
	if approve["text"] != "✅ Approve" {
		t.Fatalf("approve text = %v", approve["text"])
	}
	if approve["callback_data"] != "hfbg:approve:grant-id:decision-token" {
		t.Fatalf("approve callback = %v", approve["callback_data"])
	}
}

func TestTelegramPollOnceAcceptsOnlyConfiguredChat(t *testing.T) {
	var answered []string
	var edits []map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/getUpdates"):
			_, _ = w.Write([]byte(`{"ok":true,"result":[` +
				`{"update_id":10,"callback_query":{"id":"wrong","from":{"id":1,"username":"bad"},"message":{"chat":{"id":999}},"data":"hfbg:approve:g1:t1"}},` +
				`{"update_id":11,"callback_query":{"id":"right","from":{"id":2,"username":"operator"},"message":{"message_id":42,"chat":{"id":123},"text":"🔐 Approval needed for hf-broker\n\n⚠️ Approve only if this looks right."},"data":"hfbg:deny:g2:t2"}}` +
				`]}`))
		case strings.HasSuffix(r.URL.Path, "/answerCallbackQuery"):
			var payload map[string]any
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Fatal(err)
			}
			answered = append(answered, payload["callback_query_id"].(string)+":"+payload["text"].(string))
			_, _ = w.Write([]byte(`{"ok":true,"result":true}`))
		case strings.HasSuffix(r.URL.Path, "/editMessageText"):
			var payload map[string]any
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Fatal(err)
			}
			edits = append(edits, payload)
			_, _ = w.Write([]byte(`{"ok":true,"result":{"message_id":42}}`))
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
	}))
	defer server.Close()
	telegram := NewTelegram("telegram_token_value", 123, server.Client(), server.URL)
	telegram.pollTimeoutSeconds = 0
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
	if len(decisions) != 1 || decisions[0].ID != "g2" || decisions[0].Action != DecisionDeny || decisions[0].OperatorTag != "operator" || decisions[0].MessageID != 42 {
		t.Fatalf("decisions = %+v", decisions)
	}
	if len(answered) != 2 || answered[0] != "wrong:Grant decision ignored" || answered[1] != "right:handled" {
		t.Fatalf("answered = %+v", answered)
	}
	if len(edits) != 1 {
		t.Fatalf("edits = %+v, want one edit", edits)
	}
	if edits[0]["chat_id"].(float64) != 123 || edits[0]["message_id"].(float64) != 42 {
		t.Fatalf("edit target = %+v", edits[0])
	}
	if text := edits[0]["text"].(string); !strings.Contains(text, "Status: handled") || strings.Contains(text, "hfbg:") {
		t.Fatalf("edit text = %q", text)
	}
	replyMarkup := edits[0]["reply_markup"].(map[string]any)
	if keyboard := replyMarkup["inline_keyboard"].([]any); len(keyboard) != 0 {
		t.Fatalf("edit keyboard = %+v, want empty", keyboard)
	}
}

func TestTelegramMarksPendingAndActiveExpiry(t *testing.T) {
	now := time.Date(2026, 7, 6, 1, 2, 3, 0, time.UTC)
	var edits []map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/sendMessage"):
			_, _ = w.Write([]byte(`{"ok":true,"result":{"message_id":7,"chat":{"id":123}}}`))
		case strings.HasSuffix(r.URL.Path, "/editMessageText"):
			var payload map[string]any
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Fatal(err)
			}
			edits = append(edits, payload)
			_, _ = w.Write([]byte(`{"ok":true,"result":{"message_id":7}}`))
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
	}))
	defer server.Close()
	telegram := NewTelegram("telegram_token_value", 123, server.Client(), server.URL)

	_, err := telegram.SendGrantRequest(context.Background(), GrantMessage{
		ID:               "grant-id",
		DecisionToken:    "decision-token",
		Client:           "agent",
		Operation:        "git_history_rewrite",
		Target:           "dataset/acme/repo",
		Ref:              "refs/heads/main",
		Reason:           "recover",
		RequestedMinutes: 5,
		MaxUses:          1,
		PendingExpiresAt: now.Add(time.Minute),
	})
	if err != nil {
		t.Fatalf("SendGrantRequest() error = %v", err)
	}
	telegram.expireTracked(context.Background(), now.Add(time.Minute))
	if len(edits) != 1 || !strings.Contains(edits[0]["text"].(string), "Status: ⌛ Expired. Request was not approved in time.") {
		t.Fatalf("pending expiry edits = %+v", edits)
	}

	telegram.trackAfterDecision(Decision{
		ID:          "grant-id",
		ChatID:      123,
		MessageID:   7,
		MessageText: edits[0]["text"].(string),
	}, DecisionResult{Answer: "Grant approved", ActiveExpiresAt: now.Add(5 * time.Minute)})
	telegram.expireTracked(context.Background(), now.Add(5*time.Minute))
	if len(edits) != 2 || !strings.Contains(edits[1]["text"].(string), "Status: ⌛ Expired. Access window ended.") {
		t.Fatalf("active expiry edits = %+v", edits)
	}
	if strings.Contains(edits[1]["text"].(string), "Request was not approved") {
		t.Fatalf("active expiry kept old status: %q", edits[1]["text"].(string))
	}
}

func TestTelegramConsumedUpdateClearsTrackedExpiry(t *testing.T) {
	now := time.Date(2026, 7, 6, 1, 2, 3, 0, time.UTC)
	var edits []map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/sendMessage"):
			_, _ = w.Write([]byte(`{"ok":true,"result":{"message_id":7,"chat":{"id":123}}}`))
		case strings.HasSuffix(r.URL.Path, "/editMessageText"):
			var payload map[string]any
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Fatal(err)
			}
			edits = append(edits, payload)
			_, _ = w.Write([]byte(`{"ok":true,"result":{"message_id":7}}`))
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
	}))
	defer server.Close()
	telegram := NewTelegram("telegram_token_value", 123, server.Client(), server.URL)

	ref, err := telegram.SendGrantRequest(context.Background(), GrantMessage{
		ID:               "grant-id",
		DecisionToken:    "decision-token",
		Client:           "agent",
		Operation:        "git_history_rewrite",
		Target:           "dataset/acme/repo",
		Ref:              "refs/heads/main",
		Reason:           "recover",
		RequestedMinutes: 5,
		MaxUses:          1,
		PendingExpiresAt: now.Add(time.Minute),
	})
	if err != nil {
		t.Fatalf("SendGrantRequest() error = %v", err)
	}
	telegram.trackAfterDecision(Decision{
		ID:          "grant-id",
		ChatID:      ref.ChatID,
		MessageID:   ref.MessageID,
		MessageText: ref.Text,
	}, DecisionResult{Answer: "Grant approved", ActiveExpiresAt: now.Add(5 * time.Minute)})
	if err := telegram.UpdateGrantStatus(context.Background(), ref, "✅ Used. Access is now closed."); err != nil {
		t.Fatalf("UpdateGrantStatus() error = %v", err)
	}
	telegram.expireTracked(context.Background(), now.Add(5*time.Minute))
	if len(edits) != 1 || !strings.Contains(edits[0]["text"].(string), "Status: ✅ Used. Access is now closed.") {
		t.Fatalf("edits after consumed update = %+v, want only consumed status", edits)
	}
}

func TestTelegramAmbiguousUpdateClearsTrackedExpiry(t *testing.T) {
	now := time.Date(2026, 7, 6, 1, 2, 3, 0, time.UTC)
	var edits []map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/sendMessage"):
			_, _ = w.Write([]byte(`{"ok":true,"result":{"message_id":7,"chat":{"id":123}}}`))
		case strings.HasSuffix(r.URL.Path, "/editMessageText"):
			var payload map[string]any
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Fatal(err)
			}
			edits = append(edits, payload)
			_, _ = w.Write([]byte(`{"ok":true,"result":{"message_id":7}}`))
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
	}))
	defer server.Close()
	telegram := NewTelegram("telegram_token_value", 123, server.Client(), server.URL)

	ref, err := telegram.SendGrantRequest(context.Background(), GrantMessage{
		ID:               "grant-id",
		DecisionToken:    "decision-token",
		Client:           "agent",
		Operation:        "git_history_rewrite",
		Target:           "dataset/acme/repo",
		Ref:              "refs/heads/main",
		Reason:           "recover",
		RequestedMinutes: 5,
		MaxUses:          1,
		PendingExpiresAt: now.Add(time.Minute),
	})
	if err != nil {
		t.Fatalf("SendGrantRequest() error = %v", err)
	}
	telegram.trackAfterDecision(Decision{
		ID:          "grant-id",
		ChatID:      ref.ChatID,
		MessageID:   ref.MessageID,
		MessageText: ref.Text,
	}, DecisionResult{Answer: "Grant approved", ActiveExpiresAt: now.Add(5 * time.Minute)})
	status := "⚠️ Push result is ambiguous. Access is closed until an operator reviews it."
	if err := telegram.UpdateGrantStatus(context.Background(), ref, status); err != nil {
		t.Fatalf("UpdateGrantStatus() error = %v", err)
	}
	telegram.expireTracked(context.Background(), now.Add(5*time.Minute))
	if len(edits) != 1 || !strings.Contains(edits[0]["text"].(string), "Status: "+status) {
		t.Fatalf("edits after ambiguous update = %+v, want only ambiguous status", edits)
	}
}

func TestTelegramPostErrorsDoNotExposeToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusInternalServerError)
	}))
	defer server.Close()
	telegram := NewTelegram("telegram_token_value", 123, server.Client(), server.URL)
	_, err := telegram.SendGrantRequest(context.Background(), GrantMessage{
		ID:               "grant-id",
		DecisionToken:    "decision-token",
		Client:           "agent",
		Operation:        "git_history_rewrite",
		Target:           "dataset/acme/repo",
		Ref:              "refs/heads/main",
		Reason:           "recover",
		RequestedMinutes: 15,
		MaxUses:          1,
		PendingExpiresAt: time.Now(),
	})
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
	NewTelegram("token", 1, nil, "").Poll(ctx, func(context.Context, Decision) DecisionResult {
		t.Fatal("handler should not be called")
		return DecisionResult{}
	})
}
