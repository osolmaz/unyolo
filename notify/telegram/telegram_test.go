package telegram

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/osolmaz/brokerkit/notify"
)

func TestSendApprovalAndUpdateStatus(t *testing.T) {
	calls := make([]map[string]any, 0)
	server := httptest.NewServer(telegramTestHandler(t, &calls))
	defer server.Close()

	client, err := New("test-token", 123, server.Client(), server.URL)
	if err != nil {
		t.Fatal(err)
	}
	ref, err := client.SendApproval(context.Background(), notify.ApprovalMessage{
		GrantID:          "grant-1",
		DecisionToken:    "decision-token",
		Client:           "bob",
		Operation:        "git.ref.delete",
		Target:           "repo/osolmaz/demo",
		Reason:           "cleanup branch",
		RequestedMinutes: 5,
		MaxUses:          1,
		PendingExpiresAt: time.Now().Add(time.Minute),
	})
	if err != nil || ref.MessageID != 42 || ref.ChatID != 123 {
		t.Fatalf("SendApproval() = %+v err=%v", ref, err)
	}
	if err := client.UpdateStatus(context.Background(), ref, "Approved"); err != nil {
		t.Fatalf("UpdateStatus() error = %v", err)
	}
	if len(calls) != 2 {
		t.Fatalf("calls = %d, want 2", len(calls))
	}
	assertKeyboard(t, calls[0])
	if text := calls[1]["text"].(string); !strings.Contains(text, "Status: Approved") {
		t.Fatalf("status edit text = %q", text)
	}
}

func TestUpdateStatusTreatsUnmodifiedMessageAsDelivered(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"ok":false,"error_code":400,"description":"Bad Request: message is not modified"}`))
	}))
	defer server.Close()
	client, err := New("test-token", 123, server.Client(), server.URL)
	if err != nil {
		t.Fatal(err)
	}
	ref := notify.MessageRef{Kind: "telegram", ChatID: 123, MessageID: 42, Text: "Approval"}
	if err := client.UpdateStatus(context.Background(), ref, "Approved"); err != nil {
		t.Fatalf("UpdateStatus() error = %v, want idempotent success", err)
	}
}

func TestUpdateStatusReturnsOtherTelegramErrors(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"ok":false,"error_code":400,"description":"Bad Request: leaked-secret chat not found"}`))
	}))
	defer server.Close()
	client, err := New("test-token", 123, server.Client(), server.URL)
	if err != nil {
		t.Fatal(err)
	}
	ref := notify.MessageRef{Kind: "telegram", ChatID: 123, MessageID: 42, Text: "Approval"}
	err = client.UpdateStatus(context.Background(), ref, "Approved")
	if err == nil || strings.Contains(err.Error(), "leaked-secret") || !strings.Contains(err.Error(), "status 400") {
		t.Fatalf("UpdateStatus() error = %v, want opaque Telegram API error", err)
	}
}

func TestSendApprovalUsesBrokerTextAndButtonLabels(t *testing.T) {
	calls := make([]map[string]any, 0)
	server := httptest.NewServer(telegramTestHandler(t, &calls))
	defer server.Close()

	client, err := NewWithOptions("test-token", 123, server.Client(), server.URL, Options{
		ApproveText: "Yes",
		DenyText:    "No",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.SendApproval(context.Background(), notify.ApprovalMessage{
		GrantID:       "grant-1",
		DecisionToken: "decision-token",
		Text:          "broker-specific approval text",
	}); err != nil {
		t.Fatalf("SendApproval() error = %v", err)
	}
	if calls[0]["text"] != "broker-specific approval text" {
		t.Fatalf("message text = %q", calls[0]["text"])
	}
	row := calls[0]["reply_markup"].(map[string]any)["inline_keyboard"].([]any)[0].([]any)
	if row[0].(map[string]any)["text"] != "Yes" || row[1].(map[string]any)["text"] != "No" {
		t.Fatalf("button row = %+v", row)
	}
}

func TestPollOnceAcceptsOnlyConfiguredChat(t *testing.T) {
	state := &pollServerState{}
	server := newPollServer(t, state)
	defer server.Close()
	client, err := NewWithOptions("test-token", 123, server.Client(), server.URL, Options{PollTimeoutSeconds: 1})
	if err != nil {
		t.Fatal(err)
	}
	var decisions []notify.Decision

	offset, err := client.PollOnce(context.Background(), 0, func(_ context.Context, decision notify.Decision) notify.DecisionResult {
		decisions = append(decisions, decision)
		return notify.DecisionResult{Answer: "handled"}
	})
	if err != nil {
		t.Fatalf("PollOnce() error = %v", err)
	}
	if offset != 12 {
		t.Fatalf("offset = %d, want 12", offset)
	}
	assertPollDecision(t, decisions)
	assertPollAnswers(t, state.answered)
	assertPollEdit(t, state.edits)
}

func TestTrackedPendingAndActiveExpiry(t *testing.T) {
	now := time.Date(2026, 7, 6, 1, 2, 3, 0, time.UTC)
	var edits []map[string]any
	server := newTrackingServer(t, &edits)
	defer server.Close()
	client, err := New("test-token", 123, server.Client(), server.URL)
	if err != nil {
		t.Fatal(err)
	}

	ref, err := client.SendApproval(context.Background(), notify.ApprovalMessage{
		GrantID:          "grant-1",
		DecisionToken:    "decision-token",
		Client:           "bob",
		Operation:        "git.ref.delete",
		Target:           "repo/osolmaz/demo",
		Reason:           "cleanup branch",
		RequestedMinutes: 5,
		MaxUses:          1,
		PendingExpiresAt: now.Add(time.Minute),
	})
	if err != nil {
		t.Fatalf("SendApproval() error = %v", err)
	}
	client.ExpireTracked(context.Background(), now.Add(time.Minute))
	if len(edits) != 1 || !strings.Contains(edits[0]["text"].(string), "Status: Expired. Request was not approved in time.") {
		t.Fatalf("pending expiry edits = %+v", edits)
	}

	client.trackAfterDecision(notify.Decision{
		GrantID:     "grant-1",
		ChatID:      ref.ChatID,
		MessageID:   ref.MessageID,
		MessageText: ref.Text,
	}, notify.DecisionResult{Answer: "approved", ActiveExpiresAt: now.Add(5 * time.Minute)})
	client.ExpireTracked(context.Background(), now.Add(5*time.Minute))
	if len(edits) != 2 || !strings.Contains(edits[1]["text"].(string), "Status: Expired. Access window ended.") {
		t.Fatalf("active expiry edits = %+v", edits)
	}
	if strings.Contains(edits[1]["text"].(string), "Request was not approved") {
		t.Fatalf("active expiry kept old status: %q", edits[1]["text"].(string))
	}
}

func TestUpdateStatusClearsConfiguredTerminalExpiry(t *testing.T) {
	now := time.Date(2026, 7, 6, 1, 2, 3, 0, time.UTC)
	var edits []map[string]any
	server := newTrackingServer(t, &edits)
	defer server.Close()
	client, err := NewWithOptions("test-token", 123, server.Client(), server.URL, Options{
		TerminalStatuses: []string{"used"},
	})
	if err != nil {
		t.Fatal(err)
	}
	ref, err := client.SendApproval(context.Background(), notify.ApprovalMessage{
		GrantID:          "grant-1",
		DecisionToken:    "decision-token",
		Client:           "bob",
		Operation:        "git.ref.delete",
		Target:           "repo/osolmaz/demo",
		Reason:           "cleanup branch",
		RequestedMinutes: 5,
		MaxUses:          1,
		PendingExpiresAt: now.Add(time.Minute),
	})
	if err != nil {
		t.Fatalf("SendApproval() error = %v", err)
	}
	client.trackAfterDecision(notify.Decision{
		GrantID:     "grant-1",
		ChatID:      ref.ChatID,
		MessageID:   ref.MessageID,
		MessageText: ref.Text,
	}, notify.DecisionResult{Answer: "approved", ActiveExpiresAt: now.Add(5 * time.Minute)})
	if err := client.UpdateStatus(context.Background(), ref, "used"); err != nil {
		t.Fatalf("UpdateStatus() error = %v", err)
	}
	client.ExpireTracked(context.Background(), now.Add(5*time.Minute))
	if len(edits) != 1 || !strings.Contains(edits[0]["text"].(string), "Status: used") {
		t.Fatalf("edits after terminal update = %+v, want only used status", edits)
	}
}

func TestCallbackData(t *testing.T) {
	data := CallbackData(notify.ActionApprove, "grant-1", "token-1")
	action, grantID, token, ok := ParseCallbackData(data)
	if !ok || action != notify.ActionApprove || grantID != "grant-1" || token != "token-1" {
		t.Fatalf("ParseCallbackData() = %q %q %q %v", action, grantID, token, ok)
	}
}

func TestCallbackDataRejectsInvalid(t *testing.T) {
	if _, _, _, ok := ParseCallbackData("bad:data"); ok {
		t.Fatal("ParseCallbackData(bad) ok = true, want false")
	}
	if _, _, _, ok := ParseCallbackData("bk:bad:grant:token"); ok {
		t.Fatal("ParseCallbackData(bad action) ok = true, want false")
	}
	if _, _, _, ok := ParseCallbackData("bk:approve::token"); ok {
		t.Fatal("ParseCallbackData(empty grant) ok = true, want false")
	}
}

func TestParseDecisionRejectsInvalid(t *testing.T) {
	if decision, ok := parseDecision(telegramUpdate{}); ok || decision.GrantID != "" {
		t.Fatalf("parseDecision(empty) = %+v %v, want no decision", decision, ok)
	}
	if decision, ok := parseDecision(telegramUpdate{CallbackQuery: &telegramCallbackQuery{ID: "cb", Data: CallbackData(notify.ActionApprove, "g", "t")}}); ok || decision.GrantID != "" {
		t.Fatalf("parseDecision(no message) = %+v %v, want no decision", decision, ok)
	}
}

func TestCallbackDataRoundTripsDelimiterCharacters(t *testing.T) {
	data := CallbackData(notify.ActionDeny, "grant:with:colons", "token:with:colons")
	action, grantID, token, ok := ParseCallbackData(data)
	if !ok || action != notify.ActionDeny || grantID != "grant:with:colons" || token != "token:with:colons" {
		t.Fatalf("ParseCallbackData() = %q %q %q %v", action, grantID, token, ok)
	}
}

func TestNewValidation(t *testing.T) {
	if _, err := New("", 1, nil, ""); err == nil {
		t.Fatal("New(empty token) error = nil, want error")
	}
	if _, err := New("token", 0, nil, ""); err == nil {
		t.Fatal("New(empty chat) error = nil, want error")
	}
}

func TestTelegramRequestErrorsDoNotIncludeToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "nope", http.StatusTeapot)
	}))
	defer server.Close()
	client, err := New("secret-token", 123, server.Client(), server.URL)
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.SendApproval(context.Background(), notify.ApprovalMessage{GrantID: "g", DecisionToken: "t"})
	if err == nil {
		t.Fatal("SendApproval() error = nil, want status error")
	}
	if strings.Contains(err.Error(), "secret-token") {
		t.Fatalf("error leaked token: %v", err)
	}
}

func TestTelegramOKFalseIsError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"ok":false,"description":"bad request"}`))
	}))
	defer server.Close()
	client, err := New("secret-token", 123, server.Client(), server.URL)
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.SendApproval(context.Background(), notify.ApprovalMessage{GrantID: "g", DecisionToken: "t"})
	if err == nil || !strings.Contains(err.Error(), "ok=false") {
		t.Fatalf("SendApproval(ok=false) error = %v, want ok=false error", err)
	}
}

func TestTelegramTransportErrorsDoNotIncludeToken(t *testing.T) {
	httpClient := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("network down")
	})}
	client, err := New("secret-token", 123, httpClient, "https://api.telegram.org")
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.SendApproval(context.Background(), notify.ApprovalMessage{GrantID: "g", DecisionToken: "t"})
	if err == nil {
		t.Fatal("SendApproval() error = nil, want transport error")
	}
	if strings.Contains(err.Error(), "secret-token") {
		t.Fatalf("error leaked token: %v", err)
	}
}

func TestPollStopsWhenCanceled(t *testing.T) {
	client, err := New("test-token", 1, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	client.Poll(ctx, func(context.Context, notify.Decision) notify.DecisionResult {
		t.Fatal("handler should not be called")
		return notify.DecisionResult{}
	})
	wait(ctx, time.Hour)
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

type pollServerState struct {
	answered []string
	edits    []map[string]any
}

func newPollServer(t *testing.T, state *pollServerState) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/getUpdates"):
			writePollUpdates(w)
		case strings.HasSuffix(r.URL.Path, "/answerCallbackQuery"):
			payload := decodePayload(t, r)
			state.answered = append(state.answered, payload["callback_query_id"].(string)+":"+payload["text"].(string))
			writeOK(w)
		case strings.HasSuffix(r.URL.Path, "/editMessageText"):
			state.edits = append(state.edits, decodePayload(t, r))
			writeOK(w)
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
	}))
}

func newTrackingServer(t *testing.T, edits *[]map[string]any) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/sendMessage"):
			writeMessage(w, 7)
		case strings.HasSuffix(r.URL.Path, "/editMessageText"):
			*edits = append(*edits, decodePayload(t, r))
			writeOK(w)
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
	}))
}

func telegramTestHandler(t *testing.T, calls *[]map[string]any) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*calls = append(*calls, decodePayload(t, r))
		if strings.Contains(r.URL.Path, "sendMessage") {
			writeMessage(w, 42)
			return
		}
		writeOK(w)
	})
}

func writePollUpdates(w http.ResponseWriter) {
	_, _ = w.Write([]byte(`{"ok":true,"result":[` +
		`{"update_id":10,"callback_query":{"id":"wrong","from":{"id":1,"username":"bad"},"message":{"message_id":41,"chat":{"id":999},"text":"Approval"},"data":"` + CallbackData(notify.ActionApprove, "g1", "t1") + `"}},` +
		`{"update_id":11,"callback_query":{"id":"right","from":{"id":2,"username":"operator"},"message":{"message_id":42,"chat":{"id":123},"text":"Approval requested"},"data":"` + CallbackData(notify.ActionDeny, "g2", "t2") + `"}}` +
		`]}`))
}

func writeMessage(w http.ResponseWriter, messageID int) {
	_, _ = w.Write([]byte(`{"ok":true,"result":{"message_id":` + strconv.Itoa(messageID) + `,"chat":{"id":123}}}`))
}

func writeOK(w http.ResponseWriter) {
	_, _ = w.Write([]byte(`{"ok":true}`))
}

func decodePayload(t *testing.T, r *http.Request) map[string]any {
	t.Helper()
	var payload map[string]any
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		t.Fatalf("decode request: %v", err)
	}
	return payload
}

func assertPollDecision(t *testing.T, decisions []notify.Decision) {
	t.Helper()
	if len(decisions) != 1 {
		t.Fatalf("decisions = %+v, want one", decisions)
	}
	decision := decisions[0]
	if decision.GrantID != "g2" {
		t.Fatalf("decision grant = %q, want g2", decision.GrantID)
	}
	if decision.Action != notify.ActionDeny {
		t.Fatalf("decision action = %q, want deny", decision.Action)
	}
	if decision.OperatorTag != "operator" {
		t.Fatalf("decision operator = %q, want operator", decision.OperatorTag)
	}
	if decision.MessageID != 42 {
		t.Fatalf("decision message = %d, want 42", decision.MessageID)
	}
}

func assertPollAnswers(t *testing.T, answered []string) {
	t.Helper()
	if len(answered) != 2 {
		t.Fatalf("answered = %+v, want two answers", answered)
	}
	if answered[0] != "wrong:Decision ignored" {
		t.Fatalf("wrong-chat answer = %q", answered[0])
	}
	if answered[1] != "right:handled" {
		t.Fatalf("right-chat answer = %q", answered[1])
	}
}

func assertPollEdit(t *testing.T, edits []map[string]any) {
	t.Helper()
	if len(edits) != 1 {
		t.Fatalf("edits = %+v, want one edit", edits)
	}
	if edits[0]["chat_id"].(float64) != 123 {
		t.Fatalf("edit chat = %+v", edits[0])
	}
	if edits[0]["message_id"].(float64) != 42 {
		t.Fatalf("edit message = %+v", edits[0])
	}
	text := edits[0]["text"].(string)
	if !strings.Contains(text, "Status: handled") {
		t.Fatalf("edit text = %q", text)
	}
	if strings.Contains(text, "bk:") {
		t.Fatalf("edit text leaked callback data: %q", text)
	}
	replyMarkup := edits[0]["reply_markup"].(map[string]any)
	if keyboard := replyMarkup["inline_keyboard"].([]any); len(keyboard) != 0 {
		t.Fatalf("edit keyboard = %+v, want empty", keyboard)
	}
}

func assertKeyboard(t *testing.T, payload map[string]any) {
	t.Helper()
	markup, ok := payload["reply_markup"].(map[string]any)
	if !ok {
		t.Fatalf("reply_markup = %+v", payload["reply_markup"])
	}
	keyboard, ok := markup["inline_keyboard"].([]any)
	if !ok || len(keyboard) != 1 {
		t.Fatalf("keyboard = %+v", markup["inline_keyboard"])
	}
}
