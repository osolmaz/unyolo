package routes

import (
	"fmt"
	"net/http"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/osolmaz/brokerkit/approvalnotify"
	"github.com/osolmaz/brokerkit/brokers/sudo/internal/catalog"
	"github.com/osolmaz/brokerkit/brokers/sudo/internal/presenter"
	"github.com/osolmaz/brokerkit/brokers/sudo/internal/sudopolicy"
	"github.com/osolmaz/brokerkit/grants"
	"github.com/osolmaz/brokerkit/notify/telegram"
	"github.com/osolmaz/brokerkit/policy"
	"github.com/osolmaz/brokerkit/usebudget"
)

func TestTelegramLiveSendApproval(t *testing.T) {
	token := os.Getenv("SUDO_BROKER_TELEGRAM_BOT_TOKEN")
	rawChatID := os.Getenv("SUDO_BROKER_TELEGRAM_CHAT_ID")
	if token == "" || rawChatID == "" {
		t.Skip("SUDO_BROKER_TELEGRAM_BOT_TOKEN and SUDO_BROKER_TELEGRAM_CHAT_ID are not set")
	}
	chatID, err := strconv.ParseInt(rawChatID, 10, 64)
	if err != nil {
		t.Fatalf("SUDO_BROKER_TELEGRAM_CHAT_ID is invalid: %v", err)
	}
	snapshot, err := catalog.Parse([]byte(fmt.Sprintf(`{"version":1,"commands":[{
		"id":"restart-service","executable":"/usr/bin/true","arguments":[],"target_users":["deploy"],
		"working_directory":%q,"timeout_seconds":5,"max_output_bytes":100,"risk":"high",
		"description":"Restart a reviewed service."}]}`, t.TempDir())))
	if err != nil {
		t.Fatal(err)
	}
	client, err := telegram.New(token, chatID, &http.Client{Timeout: 10 * time.Second}, "")
	if err != nil {
		t.Fatal(err)
	}
	grant := grants.Grant{
		ID: "live-sudo-smoke", Client: "local-smoke", Operation: sudopolicy.OperationExecCommand,
		Target:   policy.Target{Kind: sudopolicy.TargetUser, Fields: map[string][]string{sudopolicy.TargetName: {"deploy"}}},
		Attrs:    map[string][]string{sudopolicy.AttrCommandID: {"restart-service"}},
		Reason:   "Live Telegram delivery smoke test; buttons are intentionally inactive",
		Duration: 5 * time.Minute, MaxUses: usebudget.Limit(1), PendingExpiresAt: time.Now().UTC().Add(5 * time.Minute),
	}
	message := approvalnotify.Project(t.Context(), "sudo", presenter.Presenter{Catalog: snapshot}, grant, "not-a-real-grant")
	if _, err := client.SendApproval(t.Context(), message); err != nil {
		t.Fatalf("SendApproval() live error = %v", err)
	}
}
