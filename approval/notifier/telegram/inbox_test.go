package telegram

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/osolmaz/unyolo/approval/notifier"
)

func TestInboxPersistsEncryptedCallbackAndClearsAuthority(t *testing.T) {
	path := filepath.Join(t.TempDir(), "callbacks.db")
	key := bytes.Repeat([]byte{7}, 32)
	inbox, err := OpenInbox(t.Context(), path, key)
	if err != nil {
		t.Fatal(err)
	}
	decision := testDurableDecision()
	if err := inbox.persistUpdate(t.Context(), 7, &decision); err != nil {
		t.Fatal(err)
	}
	if offset, err := inbox.nextOffset(t.Context()); err != nil || offset != 8 {
		t.Fatalf("nextOffset() = %d, %v", offset, err)
	}
	if err := inbox.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil || bytes.Contains(data, []byte(decision.DecisionToken)) {
		t.Fatalf("inbox stores plaintext authority: %v", err)
	}
	inbox, err = OpenInbox(t.Context(), path, key)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = inbox.Close() }()
	items, err := inbox.pending(t.Context())
	if err != nil || len(items) != 1 || items[0].Decision.DecisionToken != decision.DecisionToken {
		t.Fatalf("pending() = %+v, %v", items, err)
	}
	if err := inbox.terminal(t.Context(), items[0], notify.AnswerApproved); err != nil {
		t.Fatal(err)
	}
	var nonce, ciphertext []byte
	if err := inbox.db.QueryRowContext(t.Context(), `SELECT nonce, ciphertext FROM callbacks WHERE update_id = 7`).Scan(&nonce, &ciphertext); err != nil {
		t.Fatal(err)
	}
	if nonce != nil || ciphertext != nil {
		t.Fatal("terminal callback retained decision authority")
	}
}

func TestPollDurableRetriesWithoutLosingTelegramUpdate(t *testing.T) {
	var updates, decisions, edits atomic.Int32
	ctx, cancel := context.WithCancel(t.Context())
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(request.URL.Path, "/getUpdates"):
			if updates.Add(1) == 1 {
				payload := map[string]any{"ok": true, "result": []any{map[string]any{
					"update_id": 11, "callback_query": map[string]any{"id": "callback-11", "from": map[string]any{"id": 9, "username": "operator"},
						"message": map[string]any{"message_id": 12, "chat": map[string]any{"id": 42}, "text": "approval"},
						"data":    callbackData(RouteGitHub, notify.ActionApprove, "grant-11", "secret-token")},
				}}}
				_ = json.NewEncoder(writer).Encode(payload)
				return
			}
			_ = json.NewEncoder(writer).Encode(map[string]any{"ok": true, "result": []any{}})
		case strings.HasSuffix(request.URL.Path, "/editMessageText"):
			edits.Add(1)
			_ = json.NewEncoder(writer).Encode(map[string]any{"ok": true})
			cancel()
		default:
			_ = json.NewEncoder(writer).Encode(map[string]any{"ok": true})
		}
	}))
	defer server.Close()
	client, err := NewWithOptions("token", 42, server.Client(), server.URL, Options{PollTimeoutSeconds: 1})
	if err != nil {
		t.Fatal(err)
	}
	inbox, err := OpenInbox(t.Context(), filepath.Join(t.TempDir(), "callbacks.db"), bytes.Repeat([]byte{3}, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = inbox.Close() }()
	err = client.PollDurable(ctx, inbox, func(context.Context, notify.Decision) notify.DecisionResult {
		if decisions.Add(1) == 1 {
			return notify.DecisionResult{Answer: notify.AnswerUnavailable}
		}
		return notify.DecisionResult{Answer: notify.AnswerApproved, MessageStatus: notify.Status{Kind: notify.StatusActive}}
	})
	if err != nil && !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if decisions.Load() != 2 || edits.Load() != 1 {
		t.Fatalf("decisions=%d edits=%d", decisions.Load(), edits.Load())
	}
	if offset, err := inbox.nextOffset(t.Context()); err != nil || offset != 12 {
		t.Fatalf("nextOffset() = %d, %v", offset, err)
	}
}

func TestInboxRejectsUnsafeConfigurationAndEncryptedReplay(t *testing.T) {
	key := bytes.Repeat([]byte{9}, 32)
	if _, err := OpenInbox(t.Context(), "relative.db", key); err == nil {
		t.Fatal("relative inbox path was accepted")
	}
	if _, err := OpenInbox(t.Context(), filepath.Join(t.TempDir(), "callbacks.db"), key[:16]); err == nil {
		t.Fatal("short inbox key was accepted")
	}
	path := filepath.Join(t.TempDir(), "callbacks.db")
	inbox, err := OpenInbox(t.Context(), path, key)
	if err != nil {
		t.Fatal(err)
	}
	decision := testDurableDecision()
	if err := inbox.persistUpdate(t.Context(), 21, &decision); err != nil {
		t.Fatal(err)
	}
	if err := inbox.persistUpdate(t.Context(), 21, &decision); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := inbox.db.QueryRowContext(t.Context(), `SELECT COUNT(*) FROM callbacks`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("replayed callback count = %d, %v", count, err)
	}
	if err := inbox.Close(); err != nil {
		t.Fatal(err)
	}
	wrongKeyInbox, err := OpenInbox(t.Context(), path, bytes.Repeat([]byte{8}, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = wrongKeyInbox.Close() }()
	if _, err := wrongKeyInbox.pending(t.Context()); err == nil {
		t.Fatal("callback authority decrypted with the wrong key")
	}
}

func TestRetryBackoffIsBounded(t *testing.T) {
	if got := retryBackoff(0); got != time.Second {
		t.Fatalf("retryBackoff(0) = %s", got)
	}
	if got := retryBackoff(100); got != 128*time.Second {
		t.Fatalf("retryBackoff(100) = %s", got)
	}
}

func testDurableDecision() notify.Decision {
	return notify.Decision{Route: RouteGitHub, Action: notify.ActionApprove, GrantID: "grant-7",
		DecisionToken: "super-secret-decision-token", CallbackID: "callback-7", ChatID: 42,
		MessageID: 8, MessageText: "approval", OperatorID: 9, OperatorTag: "operator", Approver: "operator"}
}
