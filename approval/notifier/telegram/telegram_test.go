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

	"github.com/osolmaz/brokerkit/approval/notification"
	"github.com/osolmaz/brokerkit/approval/notifier"
	"github.com/osolmaz/brokerkit/approval/view"
	"github.com/osolmaz/brokerkit/authorization/budget"
)

func TestSendApprovalAndUpdateStatus(t *testing.T) {
	calls := make([]map[string]any, 0)
	server := httptest.NewServer(telegramTestHandler(t, &calls))
	defer server.Close()

	client, err := New("test-token", 123, server.Client(), server.URL)
	if err != nil {
		t.Fatal(err)
	}
	ref, err := client.SendApproval(context.Background(), validApproval())
	if err != nil || ref.MessageID != 42 || ref.ChatID != 123 {
		t.Fatalf("SendApproval() = %+v err=%v", ref, err)
	}
	if err := client.UpdateStatus(context.Background(), ref, notify.Status{Kind: notify.StatusActive}); err != nil {
		t.Fatalf("UpdateStatus() error = %v", err)
	}
	if len(calls) != 2 {
		t.Fatalf("calls = %d, want 2", len(calls))
	}
	assertKeyboard(t, calls[0])
	if text := calls[1]["text"].(string); !strings.Contains(text, "Approved. Access is active.") {
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
	if err := client.UpdateStatus(context.Background(), ref, notify.Status{Kind: notify.StatusActive}); err != nil {
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
	err = client.UpdateStatus(context.Background(), ref, notify.Status{Kind: notify.StatusActive})
	if err == nil || strings.Contains(err.Error(), "leaked-secret") || !strings.Contains(err.Error(), "status 400") {
		t.Fatalf("UpdateStatus() error = %v, want opaque Telegram API error", err)
	}
}

func TestSendApprovalUsesSharedRendererAndFixedButtons(t *testing.T) {
	calls := make([]map[string]any, 0)
	server := httptest.NewServer(telegramTestHandler(t, &calls))
	defer server.Close()

	client, err := NewWithOptions("test-token", 123, server.Client(), server.URL, Options{Route: RouteGitHub})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.SendApproval(context.Background(), validApproval()); err != nil {
		t.Fatalf("SendApproval() error = %v", err)
	}
	if !strings.Contains(calls[0]["text"].(string), "Approval needed for GitHub") || calls[0]["parse_mode"] != "HTML" {
		t.Fatalf("message text = %q", calls[0]["text"])
	}
	row := calls[0]["reply_markup"].(map[string]any)["inline_keyboard"].([]any)[0].([]any)
	if row[0].(map[string]any)["text"] != "✅ Approve" || row[1].(map[string]any)["text"] != "❌ Deny" {
		t.Fatalf("button row = %+v", row)
	}
	route, action, _, _, ok := parseCallbackData(row[0].(map[string]any)["callback_data"].(string))
	if !ok || route != RouteGitHub || action != notify.ActionApprove {
		t.Fatalf("routed callback = %q %q valid=%v", route, action, ok)
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
		return notify.DecisionResult{Answer: notify.AnswerDenied, MessageStatus: notify.Status{Kind: notify.StatusDenied}}
	})
	if err != nil {
		t.Fatalf("PollOnce() error = %v", err)
	}
	if offset != 12 {
		t.Fatalf("offset = %d, want 12", offset)
	}
	assertPollDecision(t, decisions)
	assertPollAnswers(t, state.answered)
	if len(state.edits) != 1 {
		t.Fatalf("callback edits = %+v, want one terminal status edit", state.edits)
	}
	assertClosedDecisionMessage(t, state.edits[0], "Denied. Access was not granted.")
}

func assertClosedDecisionMessage(t *testing.T, payload map[string]any, status string) {
	t.Helper()
	if text, _ := payload["text"].(string); !strings.Contains(text, status) || payload["parse_mode"] != "HTML" {
		t.Fatalf("edited message text = %q, want status %q", text, status)
	}
	assertEmptyKeyboard(t, payload)
}

func validApproval() approvalnotify.Approval {
	return approvalnotify.Approval{
		GrantID: "grant-1", DecisionToken: "decision-token", Broker: "GitHub", Requester: "agent-a",
		Operation: "repo.delete", Reason: "remove an obsolete test repository", RequestedDurationSeconds: 300,
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

func TestPollOnceLeavesRetriedDecisionPending(t *testing.T) {
	answers := 0
	updateCalls := 0
	var offsets []int64
	server := newRetryPollServer(t, &answers, &updateCalls, &offsets)
	defer server.Close()
	client, err := NewWithOptions("test-token", 123, server.Client(), server.URL, Options{PollTimeoutSeconds: 1})
	if err != nil {
		t.Fatal(err)
	}

	offset, err := client.PollOnce(context.Background(), 0, retryGrantOne)
	assertRetryPollResult(t, offset, answers, err, 5, 1, true)
	offset, err = client.PollOnce(context.Background(), offset, func(context.Context, notify.Decision) notify.DecisionResult {
		return notify.DecisionResult{Answer: notify.AnswerApproved}
	})
	assertRetryPollResult(t, offset, answers, err, 6, 2, false)
	assertRetryPollOffsets(t, offsets)
}

func TestPollOnceCommitsCallbackWhenImmediateEditFails(t *testing.T) {
	answers := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/getUpdates"):
			_, _ = w.Write([]byte(`{"ok":true,"result":[{"update_id":7,"callback_query":{"id":"callback","from":{"id":2},"message":{"message_id":42,"chat":{"id":123},"text":"Approval requested"},"data":"` + CallbackData(notify.ActionApprove, "g1", "t1") + `"}}]}`))
		case strings.HasSuffix(r.URL.Path, "/answerCallbackQuery"):
			answers++
			writeOK(w)
		case strings.HasSuffix(r.URL.Path, "/editMessageText"):
			http.Error(w, "temporary failure", http.StatusBadGateway)
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
	}))
	defer server.Close()
	client, err := New("test-token", 123, server.Client(), server.URL)
	if err != nil {
		t.Fatal(err)
	}
	offset, err := client.PollOnce(t.Context(), 0, func(context.Context, notify.Decision) notify.DecisionResult {
		return notify.DecisionResult{Answer: notify.AnswerApproved, MessageStatus: notify.Status{Kind: notify.StatusActive}}
	})
	if err != nil || offset != 8 || answers != 1 {
		t.Fatalf("PollOnce() offset=%d answers=%d err=%v, want committed callback", offset, answers, err)
	}
}

func TestPollOnceClearsButtonsWithoutReplacingStatusText(t *testing.T) {
	state := &pollServerState{}
	server := newPollServer(t, state)
	defer server.Close()
	client, err := New("test-token", 123, server.Client(), server.URL)
	if err != nil {
		t.Fatal(err)
	}
	offset, err := client.PollOnce(t.Context(), 0, func(context.Context, notify.Decision) notify.DecisionResult {
		return notify.DecisionResult{Answer: notify.AnswerApproved, ClearButtons: true}
	})
	if err != nil || offset != 12 || len(state.edits) != 1 {
		t.Fatalf("PollOnce() offset=%d edits=%d err=%v", offset, len(state.edits), err)
	}
	if _, hasText := state.edits[0]["text"]; hasText {
		t.Fatalf("button-only edit replaced message text: %+v", state.edits[0])
	}
	assertEmptyKeyboard(t, state.edits[0])
}

func retryGrantOne(_ context.Context, decision notify.Decision) notify.DecisionResult {
	if decision.GrantID == "g1" {
		return notify.DecisionResult{Retry: true}
	}
	return notify.DecisionResult{Answer: notify.AnswerApproved}
}

func assertRetryPollResult(t *testing.T, offset int64, answers int, err error, wantOffset int64, wantAnswers int, wantRetry bool) {
	t.Helper()
	if wantRetry && !errors.Is(err, ErrDecisionRetry) {
		t.Fatalf("PollOnce() error = %v, want ErrDecisionRetry", err)
	}
	if !wantRetry && err != nil {
		t.Fatalf("PollOnce() error = %v, want nil", err)
	}
	if offset != wantOffset || answers != wantAnswers {
		t.Fatalf("PollOnce() offset=%d answers=%d, want %d and %d", offset, answers, wantOffset, wantAnswers)
	}
}

func assertRetryPollOffsets(t *testing.T, offsets []int64) {
	t.Helper()
	if len(offsets) != 2 || offsets[0] != 0 || offsets[1] != 5 {
		t.Fatalf("getUpdates offsets = %v, want [0 5]", offsets)
	}
}

func TestPollRetainsCompletedBatchProgressBeforeRetry(t *testing.T) {
	answers := 0
	updateCalls := 0
	var offsets []int64
	server := newRetryPollServer(t, &answers, &updateCalls, &offsets)
	defer server.Close()
	client, err := NewWithOptions("test-token", 123, server.Client(), server.URL, Options{PollTimeoutSeconds: 1})
	if err != nil {
		t.Fatal(err)
	}
	client.retryDelay = time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	firstCalls := 0
	retryCalls := 0
	client.Poll(ctx, func(_ context.Context, decision notify.Decision) notify.DecisionResult {
		if decision.GrantID == "g0" {
			firstCalls++
			return notify.DecisionResult{Answer: notify.AnswerApproved}
		}
		retryCalls++
		if retryCalls == 1 {
			return notify.DecisionResult{Retry: true}
		}
		cancel()
		return notify.DecisionResult{Answer: notify.AnswerApproved}
	})
	if firstCalls != 1 || retryCalls != 2 {
		t.Fatalf("handler calls first=%d retry=%d, want 1 and 2", firstCalls, retryCalls)
	}
	assertRetryPollOffsets(t, offsets)
}

func newRetryPollServer(t *testing.T, answers *int, updateCalls *int, offsets *[]int64) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/getUpdates"):
			var payload struct {
				Offset int64 `json:"offset"`
			}
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Fatalf("decode getUpdates payload: %v", err)
			}
			*offsets = append(*offsets, payload.Offset)
			*updateCalls++
			if *updateCalls == 1 {
				_, _ = w.Write([]byte(`{"ok":true,"result":[` + retryPollUpdate(4, "saved", "g0") + `,` + retryPollUpdate(5, "retry", "g1") + `]}`))
				return
			}
			_, _ = w.Write([]byte(`{"ok":true,"result":[` + retryPollUpdate(5, "retry", "g1") + `]}`))
		case strings.HasSuffix(r.URL.Path, "/answerCallbackQuery"):
			*answers++
			writeOK(w)
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
	}))
}

func retryPollUpdate(updateID int, callbackID string, grantID string) string {
	return `{"update_id":` + strconv.Itoa(updateID) + `,"callback_query":{"id":"` + callbackID + `","from":{"id":2,"username":"operator"},"message":{"message_id":42,"chat":{"id":123},"text":"Approval requested"},"data":"` + CallbackData(notify.ActionApprove, grantID, "t1") + `"}}`
}

func TestCallbackData(t *testing.T) {
	data := CallbackData(notify.ActionApprove, "grant-1", "token-1")
	action, grantID, token, ok := ParseCallbackData(data)
	if !ok || action != notify.ActionApprove || grantID != "grant-1" || token != "token-1" {
		t.Fatalf("ParseCallbackData() = %q %q %q %v", action, grantID, token, ok)
	}
}

func TestRoutedCallbackData(t *testing.T) {
	data := callbackData(RouteGitHub, notify.ActionDeny, "grant-1", "token-1")
	route, action, grantID, token, ok := parseCallbackData(data)
	if !ok || route != RouteGitHub || action != notify.ActionDeny || grantID != "grant-1" || token != "token-1" {
		t.Fatalf("parseCallbackData() = %q %q %q %q %v", route, action, grantID, token, ok)
	}
}

func TestNewRejectsInvalidCallbackRoute(t *testing.T) {
	if _, err := NewWithOptions("test-token", 123, nil, "", Options{Route: "github"}); err == nil {
		t.Fatal("multi-character callback route was accepted")
	}
}

func TestNormalizeOptions(t *testing.T) {
	defaults := normalizeOptions(Options{})
	if defaults.PollTimeoutSeconds != defaultPollTimeoutSeconds || defaults.Route != defaultRoute {
		t.Fatalf("normalizeOptions(defaults) = %+v", defaults)
	}
	invalid := normalizeOptions(Options{PollTimeoutSeconds: -1, Route: "invalid"})
	if invalid.PollTimeoutSeconds != defaultPollTimeoutSeconds || invalid.Route != defaultRoute {
		t.Fatalf("normalizeOptions(invalid) = %+v", invalid)
	}

	custom := Options{PollTimeoutSeconds: 5, Route: RouteGitHub}
	if got := normalizeOptions(custom); got != custom {
		t.Fatalf("normalizeOptions(custom) = %+v, want %+v", got, custom)
	}
}

func TestCallbackDataRejectsInvalid(t *testing.T) {
	if _, _, _, ok := ParseCallbackData(CallbackData(notify.Action("unknown"), "grant", "token")); ok {
		t.Fatal("CallbackData(unknown action) parsed as valid")
	}
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

func TestParseCallbackDataRejectsMalformedParts(t *testing.T) {
	tests := []string{
		"bk:d:a:Zw:dA:extra",
		"other:d:a:Zw:dA",
		"bk:route:a:Zw:dA",
		"bk:d:x:Zw:dA",
		"bk:d:a::dA",
		"bk:d:a:Zw:",
	}
	for _, data := range tests {
		if _, _, _, _, ok := parseCallbackData(data); ok {
			t.Fatalf("parseCallbackData(%q) ok = true, want false", data)
		}
	}
}

func TestParseDecisionRejectsInvalid(t *testing.T) {
	validData := CallbackData(notify.ActionApprove, "g", "t")
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

func TestParseDecisionAcceptsMinimumMessageID(t *testing.T) {
	update := telegramUpdate{CallbackQuery: &telegramCallbackQuery{
		ID:   "cb",
		Data: CallbackData(notify.ActionApprove, "g", "t"),
		Message: &telegramMessage{
			MessageID: 1,
			Chat:      telegramChat{ID: 123},
			Text:      "Approval",
		},
	}}
	decision, ok := parseDecision(update)
	if !ok || decision.MessageID != 1 {
		t.Fatalf("parseDecision(message id 1) = %+v %v", decision, ok)
	}
}

func TestCallbackDataRoundTripsDelimiterCharacters(t *testing.T) {
	data := CallbackData(notify.ActionDeny, "grant:with:colons", "token:with:colons")
	action, grantID, token, ok := ParseCallbackData(data)
	if !ok || action != notify.ActionDeny || grantID != "grant:with:colons" || token != "token:with:colons" {
		t.Fatalf("ParseCallbackData() = %q %q %q %v", action, grantID, token, ok)
	}
}

func TestCallbackDataFitsTelegramLimitForProductionIdentifiers(t *testing.T) {
	data := CallbackData(notify.ActionApprove, "abcdefghijklmnopqrstuv", "abcdefghijklmnop")
	if len(data) > 64 {
		t.Fatalf("callback_data length = %d, want at most 64", len(data))
	}
}

func FuzzParseCallbackData(f *testing.F) {
	f.Add(CallbackData(notify.ActionApprove, "grant-1", "token-1"))
	f.Add("bk:bad:grant:token")
	f.Add("")
	f.Fuzz(func(t *testing.T, data string) {
		action, grantID, token, ok := ParseCallbackData(data)
		if !ok {
			return
		}
		if action != notify.ActionApprove && action != notify.ActionDeny {
			t.Fatalf("accepted action %q", action)
		}
		if grantID == "" || token == "" {
			t.Fatal("accepted empty callback authority")
		}
		roundTrip := CallbackData(action, grantID, token)
		nextAction, nextGrantID, nextToken, nextOK := ParseCallbackData(roundTrip)
		if !nextOK || nextAction != action || nextGrantID != grantID || nextToken != token {
			t.Fatalf("callback round trip = %q %q %q %v", nextAction, nextGrantID, nextToken, nextOK)
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
	_, err = client.SendApproval(context.Background(), validApproval())
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
	_, err = client.SendApproval(context.Background(), validApproval())
	if err == nil || !strings.Contains(err.Error(), "ok=false") {
		t.Fatalf("SendApproval(ok=false) error = %v, want ok=false error", err)
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
	_, err = client.SendApproval(context.Background(), validApproval())
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
		case strings.HasSuffix(r.URL.Path, "/sendMessage"):
			writeMessage(w, 42)
		case strings.HasSuffix(r.URL.Path, "/getUpdates"):
			writePollUpdates(w)
		case strings.HasSuffix(r.URL.Path, "/answerCallbackQuery"):
			payload := decodePayload(t, r)
			state.answered = append(state.answered, payload["callback_query_id"].(string)+":"+payload["text"].(string))
			writeOK(w)
		case strings.HasSuffix(r.URL.Path, "/editMessageText"), strings.HasSuffix(r.URL.Path, "/editMessageReplyMarkup"):
			state.edits = append(state.edits, decodePayload(t, r))
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
	if answered[0] != "wrong:Grant decision ignored" {
		t.Fatalf("wrong-chat answer = %q", answered[0])
	}
	if answered[1] != "right:Grant denied" {
		t.Fatalf("right-chat answer = %q", answered[1])
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
