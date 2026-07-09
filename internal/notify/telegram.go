// Package notify contains operator notification channels for grants.
package notify

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	bknotify "github.com/osolmaz/brokerkit/notify"
	bktelegram "github.com/osolmaz/brokerkit/notify/telegram"
)

var decisionStatusTexts = map[string]string{
	"Grant approved":                     "✅ Approved. Access is active.",
	"Grant denied":                       "❌ Denied. Access was not granted.",
	"Grant is no longer pending":         "⚠️ No change. This request is no longer pending.",
	"Grant not found":                    "⚠️ No change. This request was not found.",
	"Grant decision token did not match": "⚠️ No change. This approval button did not match the request.",
	"Grant decision ignored":             "⚠️ No change. This decision was ignored.",
}

var operationTexts = map[string]string{
	"repo.contents.read":   "read repo contents",
	"git.fetch":            "fetch from a Git repo",
	"git.push.append":      "append-push to a Git repo",
	"git.push.force":       "force-push / rewrite Git history",
	"git.ref.delete":       "delete a Git ref",
	"git.tag.update":       "move or delete a Git tag",
	"bucket.object.read":   "read a bucket object",
	"bucket.object.write":  "write a bucket object",
	"bucket.object.delete": "delete a bucket object",
}

const (
	pendingExpiredStatus = "⌛ Expired. Request was not approved in time."
	activeExpiredStatus  = "⌛ Expired. Access window ended."
)

// MessageRef identifies one editable operator notification.
type MessageRef = bknotify.MessageRef

// GrantMessage is the grant metadata sent to an operator.
type GrantMessage struct {
	ID               string
	DecisionToken    string
	Client           string
	Operation        string
	Mode             string
	Target           string
	Ref              string
	Attrs            map[string]any
	Reason           string
	RequestedMinutes int
	MaxUses          int
	PendingExpiresAt time.Time
}

// DecisionAction is a Telegram button decision.
type DecisionAction = bknotify.Action

// Supported Telegram decision actions.
const (
	DecisionApprove DecisionAction = bknotify.ActionApprove
	DecisionDeny    DecisionAction = bknotify.ActionDeny
)

// Decision is one parsed Telegram callback query.
type Decision struct {
	Action      DecisionAction
	ID          string
	Token       string
	CallbackID  string
	ChatID      int64
	MessageID   int
	MessageText string
	OperatorID  int64
	OperatorTag string
}

// DecisionResult is the visible result of one Telegram approval decision.
type DecisionResult = bknotify.DecisionResult

// DecisionHandler applies one approved-chat decision.
type DecisionHandler func(context.Context, Decision) DecisionResult

// Telegram adapts hf-broker grant messages to brokerkit's Telegram transport.
type Telegram struct {
	client  *bktelegram.Client
	initErr error
}

// NewTelegram returns a Telegram notifier.
func NewTelegram(token string, chatID int64, client *http.Client, baseURL string) *Telegram {
	telegram, err := bktelegram.NewWithOptions(token, chatID, client, baseURL, bktelegram.Options{
		IgnoredAnswer:       "Grant decision ignored",
		PendingExpired:      pendingExpiredStatus,
		ActiveExpired:       activeExpiredStatus,
		ApproveText:         "✅ Approve",
		DenyText:            "❌ Deny",
		StatusByAnswer:      decisionStatusTexts,
		TerminalStatuses:    []string{pendingExpiredStatus, activeExpiredStatus, "✅ Used. Access is now closed."},
		TerminalStatusStart: []string{"⚠️ Push result is ambiguous."},
	})
	return &Telegram{client: telegram, initErr: err}
}

// SendGrantRequest sends one pending grant request with Approve and Deny buttons.
func (t *Telegram) SendGrantRequest(ctx context.Context, msg GrantMessage) (MessageRef, error) {
	if t.initErr != nil {
		return MessageRef{}, t.initErr
	}
	return t.client.SendApproval(ctx, bknotify.ApprovalMessage{
		GrantID:          msg.ID,
		DecisionToken:    msg.DecisionToken,
		Text:             grantText(msg),
		Client:           msg.Client,
		Operation:        msg.Operation,
		Target:           msg.Target,
		Reason:           msg.Reason,
		RequestedMinutes: msg.RequestedMinutes,
		MaxUses:          msg.MaxUses,
		PendingExpiresAt: msg.PendingExpiresAt,
	})
}

// Poll runs Telegram long polling until ctx is canceled.
func (t *Telegram) Poll(ctx context.Context, handler DecisionHandler) {
	if t.initErr != nil {
		return
	}
	t.client.Poll(ctx, func(ctx context.Context, decision bknotify.Decision) bknotify.DecisionResult {
		return handler(ctx, fromBrokerkitDecision(decision))
	})
}

// PollOnce fetches one update batch. It is exported for tests.
func (t *Telegram) PollOnce(ctx context.Context, offset int64, handler DecisionHandler) (int64, error) {
	if t.initErr != nil {
		return offset, t.initErr
	}
	return t.client.PollOnce(ctx, offset, func(ctx context.Context, decision bknotify.Decision) bknotify.DecisionResult {
		return handler(ctx, fromBrokerkitDecision(decision))
	})
}

// UpdateGrantStatus edits a persisted grant notification.
func (t *Telegram) UpdateGrantStatus(ctx context.Context, ref MessageRef, status string) error {
	if t.initErr != nil {
		return t.initErr
	}
	return t.client.UpdateStatus(ctx, ref, status)
}

func (t *Telegram) expireTracked(ctx context.Context, now time.Time) {
	if t.initErr == nil {
		t.client.ExpireTracked(ctx, now)
	}
}

func fromBrokerkitDecision(decision bknotify.Decision) Decision {
	return Decision{
		Action:      decision.Action,
		ID:          decision.GrantID,
		Token:       decision.DecisionToken,
		CallbackID:  decision.CallbackID,
		ChatID:      decision.ChatID,
		MessageID:   decision.MessageID,
		MessageText: decision.MessageText,
		OperatorID:  decision.OperatorID,
		OperatorTag: decision.OperatorTag,
	}
}

func grantText(msg GrantMessage) string {
	return fmt.Sprintf("🔐 Approval needed for hf-broker\n\n%s is asking to %s.\n\n%s\n\n📝 Reason: %s\n\n⚠️ Approve only if this looks right.",
		msg.Client,
		operationText(msg.Operation),
		strings.Join(grantDetailLines(msg), "\n"),
		msg.Reason,
	)
}

func grantDetailLines(msg GrantMessage) []string {
	lines := []string{fmt.Sprintf("📍 Target: %s", msg.Target)}
	if msg.Ref != "" {
		lines = append(lines, fmt.Sprintf("🌿 Ref: %s", msg.Ref))
	}
	if msg.Mode != "" {
		lines = append(lines, fmt.Sprintf("⚙️ Mode: %s", msg.Mode))
	}
	if attrs := attrsText(msg.Attrs); attrs != "" {
		lines = append(lines, fmt.Sprintf("🏷️ Attrs: %s", attrs))
	}
	return append(lines,
		fmt.Sprintf("⏱️ Access: %d minutes", msg.RequestedMinutes),
		fmt.Sprintf("🔁 Uses: %s", usesText(msg.Operation, msg.MaxUses)),
		fmt.Sprintf("⌛ Request expires: %s", formatTelegramTime(msg.PendingExpiresAt)),
	)
}

func attrsText(attrs map[string]any) string {
	if len(attrs) == 0 {
		return ""
	}
	data, err := json.Marshal(attrs)
	if err != nil {
		return "present"
	}
	return string(data)
}

func usesText(operation string, maxUses int) string {
	noun := "use"
	if pushBudgetOperation(operation) {
		noun = "push"
	}
	if maxUses <= 1 {
		return "1 " + noun
	}
	return fmt.Sprintf("up to %d %s", maxUses, pluralNoun(noun))
}

func pluralNoun(noun string) string {
	switch noun {
	case "push":
		return "pushes"
	default:
		return noun + "s"
	}
}

func pushBudgetOperation(operation string) bool {
	return strings.HasPrefix(operation, "git.push.")
}

func operationText(operation string) string {
	return lookupText(operationTexts, operation)
}

func formatTelegramTime(value time.Time) string {
	return value.UTC().Format("2006-01-02 15:04 UTC")
}

func lookupText(values map[string]string, fallback string) string {
	if value, ok := values[fallback]; ok {
		return value
	}
	return fallback
}
