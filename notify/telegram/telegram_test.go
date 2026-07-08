package telegram

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
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
}

func TestCallbackData(t *testing.T) {
	data := CallbackData(notify.ActionApprove, "grant-1", "token-1")
	action, grantID, token, ok := ParseCallbackData(data)
	if !ok || action != notify.ActionApprove || grantID != "grant-1" || token != "token-1" {
		t.Fatalf("ParseCallbackData() = %q %q %q %v", action, grantID, token, ok)
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

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func telegramTestHandler(t *testing.T, calls *[]map[string]any) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload map[string]any
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		*calls = append(*calls, payload)
		if strings.Contains(r.URL.Path, "sendMessage") {
			_, _ = w.Write([]byte(`{"ok":true,"result":{"message_id":42,"chat":{"id":123}}}`))
			return
		}
		_, _ = w.Write([]byte(`{"ok":true}`))
	})
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
