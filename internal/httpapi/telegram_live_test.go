package httpapi

import (
	"context"
	"net/http"
	"os"
	"strconv"
	"testing"
	"time"

	bktelegram "github.com/osolmaz/brokerkit/notify/telegram"
	"github.com/osolmaz/hf-broker/internal/grants"
)

func TestTelegramLiveSendApproval(t *testing.T) {
	token := os.Getenv("HF_BROKER_TELEGRAM_BOT_TOKEN")
	rawChatID := os.Getenv("HF_BROKER_TELEGRAM_CHAT_ID")
	if token == "" || rawChatID == "" {
		t.Skip("HF_BROKER_TELEGRAM_BOT_TOKEN and HF_BROKER_TELEGRAM_CHAT_ID are not set")
	}
	chatID, err := strconv.ParseInt(rawChatID, 10, 64)
	if err != nil {
		t.Fatalf("HF_BROKER_TELEGRAM_CHAT_ID is invalid: %v", err)
	}
	client, err := bktelegram.New(token, chatID, &http.Client{Timeout: 10 * time.Second}, "")
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.SendApproval(context.Background(), grantApprovalMessage(grants.Grant{
		ID:               "live-smoke",
		DecisionToken:    "not-a-real-grant",
		Client:           "local-smoke",
		Operation:        "git.push.force",
		Mode:             grants.ModeWindow,
		Target:           "dataset/dutifulbob/hf-broker-smoke",
		Ref:              "refs/heads/main",
		Reason:           "live Telegram delivery smoke test",
		RequestedMinutes: 5,
		MaxUses:          1,
		PendingExpiresAt: time.Now().UTC().Add(5 * time.Minute),
	}))
	if err != nil {
		t.Fatalf("SendApproval() live error = %v", err)
	}
}
