package httpapi

import (
	"net/http"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/osolmaz/unyolo/approval/notifier/telegram"
	"github.com/osolmaz/unyolo/authorization/budget"
	"github.com/osolmaz/unyolo/authorization/grants"
	"github.com/osolmaz/unyolo/authorization/policy"
)

func TestTelegramLiveSendApproval(t *testing.T) {
	token := os.Getenv("GH_BROKER_TELEGRAM_BOT_TOKEN")
	rawChatID := os.Getenv("GH_BROKER_TELEGRAM_CHAT_ID")
	if token == "" || rawChatID == "" {
		t.Skip("GH_BROKER_TELEGRAM_BOT_TOKEN and GH_BROKER_TELEGRAM_CHAT_ID are not set")
	}
	chatID, err := strconv.ParseInt(rawChatID, 10, 64)
	if err != nil {
		t.Fatalf("GH_BROKER_TELEGRAM_CHAT_ID is invalid: %v", err)
	}
	client, err := telegram.New(token, chatID, &http.Client{Timeout: 10 * time.Second}, "")
	if err != nil {
		t.Fatal(err)
	}
	grant := grants.Grant{
		ID: "live-github-smoke", Client: "local-smoke", Operation: "git.push.force",
		Target: policy.Target{Kind: "repo", Fields: map[string][]string{"owner": {"example"}, "name": {"project"}}},
		Attrs:  map[string][]string{"ref": {"refs/heads/main"}}, Reason: "Live Telegram delivery smoke test; buttons are intentionally inactive",
		Duration: 5 * time.Minute, MaxUses: usebudget.Limit(1), PendingExpiresAt: time.Now().UTC().Add(5 * time.Minute),
	}
	if _, err := client.SendApproval(t.Context(), grantApprovalMessage(t.Context(), grant, "not-a-real-grant")); err != nil {
		t.Fatalf("SendApproval() live error = %v", err)
	}
}
