package httpapi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/osolmaz/brokerkit/grants"
	"github.com/osolmaz/brokerkit/notify"
	bktelegram "github.com/osolmaz/brokerkit/notify/telegram"
)

func TestTelegramCallbackRecoversAmbiguousNotification(t *testing.T) {
	server := newTestServer(t)
	state, telegram := newCutoverTelegram(t)
	server.notifier = telegram
	server.telegram = telegram
	grant, token := claimCutoverGrant(t, server)
	if _, retained, err := server.grants.RetainNotificationClaim(grant.ID, grant.NotificationClaimedAt); err != nil || !retained {
		t.Fatalf("RetainNotificationClaim() retained=%v err=%v", retained, err)
	}
	setCutoverCallback(state, grant, token)
	offset, err := telegram.PollOnce(context.Background(), 0, server.handleTelegramDecision)
	assertSuccessfulCutoverPoll(t, offset, state, err)
	assertRecoveredCutoverGrant(t, server, grant.ID, state.messageID)
}

func TestTelegramCallbackRetriesDurableWriteFailure(t *testing.T) {
	dir := t.TempDir()
	server := newTestServer(t)
	server.grants = grants.New(filepath.Join(dir, "grants.json"), grants.Options{})
	state, telegram := newCutoverTelegram(t)
	server.notifier = telegram
	server.telegram = telegram
	grant, token := claimCutoverGrant(t, server)
	setCutoverCallback(state, grant, token)
	setCutoverDirectoryMode(t, dir, 0o500)
	offset, pollErr := telegram.PollOnce(context.Background(), 0, server.handleTelegramDecision)
	setCutoverDirectoryMode(t, dir, 0o700)
	assertRetryableCutoverPoll(t, offset, state, pollErr)
	assertPendingCutoverGrant(t, server, grant.ID)
	state.updateSent = false
	offset, pollErr = telegram.PollOnce(context.Background(), offset, server.handleTelegramDecision)
	assertSuccessfulCutoverPoll(t, offset, state, pollErr)
}

func TestCallbackWinningSendRaceKeepsMessageActive(t *testing.T) {
	server := newTestServerWithPolicyAndHandler(t, requestPRPolicy(t), func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
	})
	notifier := &callbackDuringSendNotifier{server: server}
	server.notifier = notifier
	response := createGrant(t, server, "callback-wins-send", "open the work PR")
	if response.Code != http.StatusCreated || notifier.result.Answer != "Grant approved" || notifier.result.Retry {
		t.Fatalf("grant response=%d result=%+v body=%s", response.Code, notifier.result, response.Body.String())
	}
	for _, status := range notifier.statuses {
		if strings.Contains(status, "Superseded") {
			t.Fatalf("callback-owned message was superseded: %q", status)
		}
	}
	stored, err := server.grants.Get(decodeGrantResponse(t, response).ID)
	if err != nil || stored.Status != grants.StatusActive || stored.Notification == nil || *stored.Notification != notifier.ref {
		t.Fatalf("stored grant = %+v err=%v", stored, err)
	}
}

func newCutoverTelegram(t *testing.T) (*fakeTelegramState, *bktelegram.Client) {
	t.Helper()
	state := &fakeTelegramState{chatID: 123, messageID: 77}
	api := httptest.NewServer(fakeTelegramHandler(t, state))
	t.Cleanup(api.Close)
	client, err := bktelegram.NewWithOptions("bot-token", state.chatID, api.Client(), api.URL, bktelegram.Options{PollTimeoutSeconds: 1})
	if err != nil {
		t.Fatal(err)
	}
	return state, client
}

func setCutoverCallback(state *fakeTelegramState, grant grants.Grant, token string) {
	state.messageText = grantApprovalText(grant)
	state.callbackData = bktelegram.CallbackData(notify.ActionApprove, grant.ID, token)
}

func claimCutoverGrant(t *testing.T, server *Server) (grants.Grant, string) {
	t.Helper()
	result, _, err := server.grants.Request(grantsRequestForMainPush(t))
	if err != nil {
		t.Fatal(err)
	}
	claim, claimed, err := server.grants.ClaimNotification(result.Grant.ID, time.Minute)
	if err != nil || !claimed {
		t.Fatalf("ClaimNotification() = %+v claimed=%v err=%v", claim, claimed, err)
	}
	return claim.Grant, claim.DecisionToken
}

func setCutoverDirectoryMode(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	if err := os.Chmod(path, mode); err != nil { // #nosec G302 -- test controls private directory permissions.
		t.Fatal(err)
	}
}

func assertRetryableCutoverPoll(t *testing.T, offset int64, state *fakeTelegramState, err error) {
	t.Helper()
	if err == nil {
		t.Skip("filesystem does not enforce directory write permissions")
	}
	if !errors.Is(err, bktelegram.ErrDecisionRetry) || offset != 0 || state.answered {
		t.Fatalf("failed callback offset=%d answered=%v err=%v", offset, state.answered, err)
	}
}

func assertSuccessfulCutoverPoll(t *testing.T, offset int64, state *fakeTelegramState, err error) {
	t.Helper()
	if err != nil || offset != 2 || !state.answered {
		t.Fatalf("PollOnce() offset=%d answered=%v err=%v", offset, state.answered, err)
	}
}

func assertPendingCutoverGrant(t *testing.T, server *Server, id string) {
	t.Helper()
	pending, err := server.grants.Get(id)
	if err != nil || pending.Status != grants.StatusPending || pending.Notification != nil {
		t.Fatalf("grant after failed callback = %+v err=%v", pending, err)
	}
}

func assertRecoveredCutoverGrant(t *testing.T, server *Server, id string, messageID int) {
	t.Helper()
	stored, err := server.grants.Get(id)
	if err != nil || stored.Status != grants.StatusActive || stored.Notification == nil || stored.Notification.MessageID != messageID {
		t.Fatalf("recovered grant = %+v err=%v", stored, err)
	}
}

type callbackDuringSendNotifier struct {
	server   *Server
	ref      notify.MessageRef
	result   notify.DecisionResult
	statuses []string
}

func (n *callbackDuringSendNotifier) SendApproval(ctx context.Context, message notify.ApprovalMessage) (notify.MessageRef, error) {
	n.ref = notify.MessageRef{Kind: "telegram", ChatID: 1, MessageID: 7, Text: message.Text}
	n.result = n.server.handleTelegramDecision(ctx, notify.Decision{
		Action: notify.ActionApprove, GrantID: message.GrantID, DecisionToken: message.DecisionToken,
		ChatID: n.ref.ChatID, MessageID: n.ref.MessageID, MessageText: n.ref.Text, OperatorID: 42,
	})
	return n.ref, nil
}

func (n *callbackDuringSendNotifier) UpdateStatus(_ context.Context, _ notify.MessageRef, status string) error {
	n.statuses = append(n.statuses, status)
	return nil
}
