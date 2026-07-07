package notify

import (
	"context"
	"net/http"
	"os"
	"strconv"
	"testing"
	"time"
)

func TestTelegramLiveSendGrantRequest(t *testing.T) {
	token := os.Getenv("HF_BROKER_TELEGRAM_BOT_TOKEN")
	rawChatID := os.Getenv("HF_BROKER_TELEGRAM_CHAT_ID")
	if token == "" || rawChatID == "" {
		t.Skip("HF_BROKER_TELEGRAM_BOT_TOKEN and HF_BROKER_TELEGRAM_CHAT_ID are not set")
	}
	chatID, err := strconv.ParseInt(rawChatID, 10, 64)
	if err != nil {
		t.Fatalf("HF_BROKER_TELEGRAM_CHAT_ID is invalid: %v", err)
	}
	telegram := NewTelegram(token, chatID, &http.Client{Timeout: 10 * time.Second}, "")
	_, err = telegram.SendGrantRequest(context.Background(), GrantMessage{
		ID:               "live-smoke",
		DecisionToken:    "not-a-real-grant",
		Client:           "local-smoke",
		Operation:        "git.push.force",
		Target:           "dataset/dutifulbob/hf-broker-smoke",
		Ref:              "refs/heads/main",
		Reason:           "live Telegram delivery smoke test",
		RequestedMinutes: 5,
		MaxUses:          1,
		PendingExpiresAt: time.Now().UTC().Add(5 * time.Minute),
	})
	if err != nil {
		t.Fatalf("SendGrantRequest() live error = %v", err)
	}
}
