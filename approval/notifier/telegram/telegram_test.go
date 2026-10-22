package telegram

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/osolmaz/unyolo/approval/notifier"
	"github.com/osolmaz/unyolo/approval/view"
	"github.com/osolmaz/unyolo/authorization/budget"
)

func TestSendCardAndUpdateCard(t *testing.T) {
	calls := make([]map[string]any, 0)
	server := httptest.NewServer(telegramTestHandler(t, &calls))
	defer server.Close()

	client, err := New("test-token", 123, server.Client(), server.URL)
	if err != nil {
		t.Fatal(err)
	}
	chatID, messageID, err := client.sendCard(context.Background(), RouteGitHub, "grant-1", "card-token", "Approval")
	if err != nil || messageID != 42 || chatID != 123 {
		t.Fatalf("sendCard() = %d/%d err=%v", chatID, messageID, err)
	}
	if err := client.updateCard(context.Background(), chatID, messageID, "Approval", notify.Status{Kind: notify.StatusActive}); err != nil {
		t.Fatalf("updateCard() error = %v", err)
	}
	if len(calls) != 2 {
		t.Fatalf("calls = %d, want 2", len(calls))
	}
	assertKeyboard(t, calls[0])
	if text := calls[1]["text"].(string); !strings.Contains(text, "Approved. Access is active.") {
		t.Fatalf("status edit text = %q", text)
	}
	assertEmptyKeyboard(t, calls[1])
}

func TestUpdateCardTreatsUnmodifiedMessageAsDelivered(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"ok":false,"error_code":400,"description":"Bad Request: message is not modified"}`))
	}))
	defer server.Close()
	client, err := New("test-token", 123, server.Client(), server.URL)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.updateCard(context.Background(), 123, 42, "Approval", notify.Status{Kind: notify.StatusActive}); err != nil {
		t.Fatalf("updateCard() error = %v, want idempotent success", err)
	}
}

func TestUpdateCardReturnsOtherTelegramErrors(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"ok":false,"error_code":400,"description":"Bad Request: leaked-secret chat not found"}`))
	}))
	defer server.Close()
	client, err := New("test-token", 123, server.Client(), server.URL)
	if err != nil {
		t.Fatal(err)
	}
	err = client.updateCard(context.Background(), 123, 42, "Approval", notify.Status{Kind: notify.StatusActive})
	if err == nil || strings.Contains(err.Error(), "leaked-secret") || !strings.Contains(err.Error(), "status 400") {
		t.Fatalf("updateCard() error = %v, want opaque Telegram API error", err)
	}
}

func TestSendCardUsesFixedRoutedButtons(t *testing.T) {
	calls := make([]map[string]any, 0)
	server := httptest.NewServer(telegramTestHandler(t, &calls))
	defer server.Close()

	client, err := New("test-token", 123, server.Client(), server.URL)
	if err != nil {
		t.Fatal(err)
	}
	text, err := RenderApproval(validApproval())
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := client.sendCard(context.Background(), RouteGitHub, "grant-1", "card-token", text); err != nil {
		t.Fatalf("sendCard() error = %v", err)
	}
	if !strings.Contains(calls[0]["text"].(string), "Approval needed for GitHub") || calls[0]["parse_mode"] != "HTML" {
		t.Fatalf("message text = %q", calls[0]["text"])
	}
	row := calls[0]["reply_markup"].(map[string]any)["inline_keyboard"].([]any)[0].([]any)
	if row[0].(map[string]any)["text"] != approveButtonText || row[1].(map[string]any)["text"] != denyButtonText {
		t.Fatalf("button row = %+v", row)
	}
	route, action, grantID, token, ok := parseCallbackData(row[0].(map[string]any)["callback_data"].(string))
	if !ok || route != RouteGitHub || action != notify.ActionApprove || grantID != "grant-1" || token != "card-token" {
		t.Fatalf("routed callback = %q %q %q %q valid=%v", route, action, grantID, token, ok)
	}
}

func TestSendCardRejectsMissingAuthorityAndMessage(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"ok":true,"result":{"chat":{"id":123}}}`))
	}))
	defer server.Close()
	client, err := New("test-token", 123, server.Client(), server.URL)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := client.sendCard(t.Context(), RouteGitHub, "grant-1", " ", "Approval"); err == nil {
		t.Fatal("sendCard() without a token succeeded")
	}
	if _, _, err := client.sendCard(t.Context(), RouteGitHub, "grant-1", "card-token", "Approval"); err == nil {
		t.Fatal("sendCard() accepted a response without a message id")
	}
}

func validApproval() Approval {
	return Approval{
		GrantID: "grant-1", DecisionToken: "decision-token", Broker: "GitHub", Requester: "agent-a",
		Operation: "repo.delete", Mode: "execution", Reason: "remove an obsolete test repository", RequestedDurationSeconds: 300,
		MaxUses: usebudget.Limit(1), PendingExpiresAt: time.Date(2026, 7, 17, 10, 0, 0, 0, time.UTC),
		Presentation: approvalview.Presentation{Risk: approvalview.RiskCritical, Title: "Delete repository", Target: "example/project",
			Summary: "Permanently delete the selected repository.", Facts: []approvalview.Fact{{Label: "Visibility", Value: "private"}},
			Warnings: []approvalview.Warning{{Severity: approvalview.RiskCritical, Text: "This operation permanently deletes the repository."}}},
	}
}

func assertEmptyKeyboard(t *testing.T, payload map[string]any) {
	t.Helper()
	markup, ok := payload["reply_markup"].(map[string]any)
	if !ok {
		t.Fatalf("edited message reply markup = %#v", payload["reply_markup"])
	}
	keyboard, ok := markup["inline_keyboard"].([]any)
	if !ok || len(keyboard) != 0 {
		t.Fatalf("edited message keyboard = %#v, want empty", markup["inline_keyboard"])
	}
}

func TestRoutedCallbackData(t *testing.T) {
	data := callbackData(RouteGitHub, notify.ActionDeny, "grant-1", "token-1")
	route, action, grantID, token, ok := parseCallbackData(data)
	if !ok || route != RouteGitHub || action != notify.ActionDeny || grantID != "grant-1" || token != "token-1" {
		t.Fatalf("parseCallbackData() = %q %q %q %q %v", route, action, grantID, token, ok)
	}
}

func TestCallbackDataRejectsInvalid(t *testing.T) {
	for _, data := range []string{
		callbackData(RouteGitHub, notify.Action("unknown"), "grant", "token"),
		"bad:data",
		"bk:bad:grant:token",
		"bk:approve::token",
	} {
		if _, _, _, _, ok := parseCallbackData(data); ok {
			t.Fatalf("parseCallbackData(%q) ok = true, want false", data)
		}
	}
}

func TestParseCallbackDataRejectsMalformedParts(t *testing.T) {
	tests := []string{
		"bk:g:a:Zw:dA:extra",
		"other:g:a:Zw:dA",
		"bk:route:a:Zw:dA",
		"bk:g:x:Zw:dA",
		"bk:g:a::dA",
		"bk:g:a:Zw:",
	}
	for _, data := range tests {
		if _, _, _, _, ok := parseCallbackData(data); ok {
			t.Fatalf("parseCallbackData(%q) ok = true, want false", data)
		}
	}
}

func TestParseDecisionRejectsInvalid(t *testing.T) {
	validData := callbackData(RouteGitHub, notify.ActionApprove, "g", "t")
	validMessage := telegramMessage{MessageID: 7, Chat: telegramChat{ID: 123}, Text: "Approval"}
	tests := []struct {
		name   string
		update telegramUpdate
	}{
		{name: "empty"},
		{name: "invalid data", update: telegramUpdate{CallbackQuery: &telegramCallbackQuery{ID: "cb", Data: "bad", Message: &validMessage}}},
		{name: "empty callback id", update: telegramUpdate{CallbackQuery: &telegramCallbackQuery{Data: validData, Message: &validMessage}}},
		{name: "no message", update: telegramUpdate{CallbackQuery: &telegramCallbackQuery{ID: "cb", Data: validData}}},
		{name: "zero chat", update: telegramUpdate{CallbackQuery: &telegramCallbackQuery{ID: "cb", Data: validData, Message: &telegramMessage{MessageID: 7, Text: "Approval"}}}},
		{name: "zero message id", update: telegramUpdate{CallbackQuery: &telegramCallbackQuery{ID: "cb", Data: validData, Message: &telegramMessage{Chat: telegramChat{ID: 123}, Text: "Approval"}}}},
		{name: "empty text", update: telegramUpdate{CallbackQuery: &telegramCallbackQuery{ID: "cb", Data: validData, Message: &telegramMessage{MessageID: 7, Chat: telegramChat{ID: 123}}}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if decision, ok := parseDecision(test.update); ok || decision.GrantID != "" {
				t.Fatalf("parseDecision() = %+v %v, want no decision", decision, ok)
			}
		})
	}
}

func TestParseDecisionReadsTheClickedButton(t *testing.T) {
	data := callbackData(RouteGitHub, notify.ActionApprove, "g", "t")
	update := telegramUpdate{CallbackQuery: &telegramCallbackQuery{
		ID:   "cb",
		Data: data,
		Message: &telegramMessage{
			MessageID: 1,
			Chat:      telegramChat{ID: 123},
			Text:      "Approval",
			ReplyMarkup: &telegramInlineMarkup{InlineKeyboard: [][]telegramInlineButton{{
				{Text: approveButtonText, CallbackData: data},
				{Text: denyButtonText, CallbackData: callbackData(RouteGitHub, notify.ActionDeny, "g", "t")},
			}}},
		},
	}}
	decision, ok := parseDecision(update)
	if !ok || decision.MessageID != 1 || decision.ButtonText != approveButtonText || decision.Route != RouteGitHub {
		t.Fatalf("parseDecision() = %+v %v", decision, ok)
	}
}

func TestCallbackDataRoundTripsDelimiterCharacters(t *testing.T) {
	data := callbackData(RouteSudo, notify.ActionDeny, "grant:with:colons", "token:with:colons")
	_, action, grantID, token, ok := parseCallbackData(data)
	if !ok || action != notify.ActionDeny || grantID != "grant:with:colons" || token != "token:with:colons" {
		t.Fatalf("parseCallbackData() = %q %q %q %v", action, grantID, token, ok)
	}
}

func TestCallbackDataFitsTelegramLimitForProductionIdentifiers(t *testing.T) {
	token, err := newCardToken()
	if err != nil {
		t.Fatal(err)
	}
	data := callbackData(RouteHuggingFace, notify.ActionApprove, "abcdefghijklmnopqrstuv", token)
	if len(data) > 64 {
		t.Fatalf("callback_data length = %d, want at most 64", len(data))
	}
}

func FuzzParseCallbackData(f *testing.F) {
	f.Add(callbackData(RouteGitHub, notify.ActionApprove, "grant-1", "token-1"))
	f.Add("bk:bad:grant:token")
	f.Add("")
	f.Fuzz(func(t *testing.T, data string) {
		route, action, grantID, token, ok := parseCallbackData(data)
		if !ok {
			return
		}
		if action != notify.ActionApprove && action != notify.ActionDeny {
			t.Fatalf("accepted action %q", action)
		}
		if grantID == "" || token == "" {
			t.Fatal("accepted empty callback authority")
		}
		roundTrip := callbackData(route, action, grantID, token)
		nextRoute, nextAction, nextGrantID, nextToken, nextOK := parseCallbackData(roundTrip)
		if !nextOK || nextRoute != route || nextAction != action || nextGrantID != grantID || nextToken != token {
			t.Fatalf("callback round trip = %q %q %q %q %v", nextRoute, nextAction, nextGrantID, nextToken, nextOK)
		}
	})
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
	_, _, err = client.sendCard(context.Background(), RouteGitHub, "grant-1", "card-token", "Approval")
	if err == nil {
		t.Fatal("sendCard() error = nil, want status error")
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
	_, _, err = client.sendCard(context.Background(), RouteGitHub, "grant-1", "card-token", "Approval")
	if err == nil || !strings.Contains(err.Error(), "ok=false") {
		t.Fatalf("sendCard(ok=false) error = %v, want ok=false error", err)
	}
}

func TestTelegramResponseIsBoundedAndUnambiguous(t *testing.T) {
	for name, body := range map[string]string{
		"oversized": strings.Repeat(" ", 64*1024+1),
		"duplicate": `{"ok":true,"ok":false}`,
		"trailing":  `{"ok":true} {}`,
	} {
		t.Run(name, func(t *testing.T) {
			response := &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body))}
			var result okResponse
			if err := decodeTelegramResponse(response, &result); err == nil {
				t.Fatal("decodeTelegramResponse() accepted an invalid response")
			}
		})
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
	_, _, err = client.sendCard(context.Background(), RouteGitHub, "grant-1", "card-token", "Approval")
	if err == nil {
		t.Fatal("sendCard() error = nil, want transport error")
	}
	if strings.Contains(err.Error(), "secret-token") {
		t.Fatalf("error leaked token: %v", err)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
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
