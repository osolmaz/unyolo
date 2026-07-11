package httpapi

import (
	"context"
	"net/http"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/osolmaz/brokerkit/grants"
	bktelegram "github.com/osolmaz/brokerkit/notify/telegram"
	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/hfgrant"
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
	request, err := hfgrant.CanonicalRequest(hfgrant.Input{
		Client: "local-smoke", Operation: "git.push.force", Mode: hfgrant.ModeWindow,
		Target: "dataset/dutifulbob/hf-broker-smoke", Ref: "refs/heads/main",
		Reason: "live Telegram delivery smoke test", RequestedDuration: 5 * time.Minute, MaxUses: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	grant := grants.Grant{
		ID: "live-smoke", Client: request.Client, Operation: request.Operation, Target: request.Target,
		Metadata: request.Metadata, Attrs: request.Attrs, Reason: request.Reason, Duration: request.Duration,
		MaxUses: request.MaxUses, PendingExpiresAt: time.Now().UTC().Add(5 * time.Minute),
	}
	_, err = client.SendApproval(context.Background(), grantApprovalMessage(grant, "not-a-real-grant"))
	if err != nil {
		t.Fatalf("SendApproval() live error = %v", err)
	}
}
