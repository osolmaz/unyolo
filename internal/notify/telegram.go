// Package notify contains operator notification channels for grants.
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	defaultTelegramBaseURL = "https://api.telegram.org"
	callbackPrefix         = "hfbg"
)

var decisionStatusTexts = map[string]string{
	"Grant approved":                     "✅ Approved. Access is active.",
	"Grant denied":                       "❌ Denied. Access was not granted.",
	"Grant is no longer pending":         "⚠️ No change. This request is no longer pending.",
	"Grant not found":                    "⚠️ No change. This request was not found.",
	"Grant decision token did not match": "⚠️ No change. This approval button did not match the request.",
	"Grant decision ignored":             "⚠️ No change. This decision was ignored.",
}

const (
	pendingExpiredStatus = "⌛ Expired. Request was not approved in time."
	activeExpiredStatus  = "⌛ Expired. Access window ended."
)

// MessageRef identifies one editable operator notification.
type MessageRef struct {
	Kind      string
	ChatID    int64
	MessageID int
	Text      string
}

// GrantMessage is the grant metadata sent to an operator.
type GrantMessage struct {
	ID               string
	DecisionToken    string
	Client           string
	Operation        string
	Target           string
	Ref              string
	Reason           string
	RequestedMinutes int
	MaxUses          int
	PendingExpiresAt time.Time
}

// DecisionAction is a Telegram button decision.
type DecisionAction string

// Supported Telegram decision actions.
const (
	DecisionApprove DecisionAction = "approve"
	DecisionDeny    DecisionAction = "deny"
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
type DecisionResult struct {
	// Answer is the short text sent back to Telegram's callback answer.
	Answer string
	// Status overrides the status line edited into the approval message.
	Status string
	// ActiveExpiresAt tracks the approved access window for a second expiry edit.
	ActiveExpiresAt time.Time
}

// DecisionHandler applies one approved-chat decision.
type DecisionHandler func(context.Context, Decision) DecisionResult

type trackedMessage struct {
	id             string
	chatID         int64
	messageID      int
	text           string
	expiresAt      time.Time
	statusOnExpire string
}

// Telegram long-polls the Bot API for grant decisions.
type Telegram struct {
	token              string
	chatID             int64
	baseURL            string
	client             *http.Client
	pollTimeoutSeconds int

	trackedMu sync.Mutex
	tracked   map[string]trackedMessage
}

// NewTelegram returns a Telegram notifier.
func NewTelegram(token string, chatID int64, client *http.Client, baseURL string) *Telegram {
	if client == nil {
		client = &http.Client{Timeout: 35 * time.Second}
	}
	if baseURL == "" {
		baseURL = defaultTelegramBaseURL
	}
	return &Telegram{
		token:              token,
		chatID:             chatID,
		baseURL:            strings.TrimRight(baseURL, "/"),
		client:             client,
		pollTimeoutSeconds: 30,
		tracked:            map[string]trackedMessage{},
	}
}

// SendGrantRequest sends one pending grant request with Approve and Deny buttons.
func (t *Telegram) SendGrantRequest(ctx context.Context, msg GrantMessage) (MessageRef, error) {
	text := grantText(msg)
	payload := map[string]any{
		"chat_id": t.chatID,
		"text":    text,
		"reply_markup": map[string]any{
			"inline_keyboard": [][]map[string]string{{
				{"text": "✅ Approve", "callback_data": callbackData(DecisionApprove, msg.ID, msg.DecisionToken)},
				{"text": "❌ Deny", "callback_data": callbackData(DecisionDeny, msg.ID, msg.DecisionToken)},
			}},
		},
	}
	var response telegramMessageResponse
	if err := t.post(ctx, "sendMessage", payload, &response); err != nil {
		return MessageRef{}, err
	}
	chatID := response.Result.Chat.ID
	if chatID == 0 {
		chatID = t.chatID
	}
	ref := MessageRef{Kind: "telegram", ChatID: chatID, MessageID: response.Result.MessageID, Text: text}
	t.track(trackedMessage{
		id:             msg.ID,
		chatID:         chatID,
		messageID:      response.Result.MessageID,
		text:           text,
		expiresAt:      msg.PendingExpiresAt,
		statusOnExpire: pendingExpiredStatus,
	})
	return ref, nil
}

// Poll runs Telegram long polling until ctx is canceled.
func (t *Telegram) Poll(ctx context.Context, handler DecisionHandler) {
	var offset int64
	for ctx.Err() == nil {
		nextOffset, err := t.PollOnce(ctx, offset, handler)
		if err != nil {
			wait(ctx, time.Second)
			continue
		}
		offset = nextOffset
	}
}

// PollOnce fetches one update batch. It is exported for tests.
func (t *Telegram) PollOnce(ctx context.Context, offset int64, handler DecisionHandler) (int64, error) {
	updates, err := t.getUpdates(ctx, offset)
	if err != nil {
		return offset, err
	}
	nextOffset := offset
	for _, update := range updates {
		if update.UpdateID >= nextOffset {
			nextOffset = update.UpdateID + 1
		}
		decision, ok := parseDecision(update)
		if !ok {
			continue
		}
		result := DecisionResult{Answer: "Grant decision ignored"}
		if decision.ChatID == t.chatID {
			result = normalizeDecisionResult(handler(ctx, decision))
		}
		_ = t.answerCallback(ctx, decision.CallbackID, result.Answer)
		if decision.ChatID == t.chatID {
			_ = t.markDecision(ctx, decision, result)
			t.trackAfterDecision(decision, result)
		}
	}
	return nextOffset, nil
}

func (t *Telegram) getUpdates(ctx context.Context, offset int64) ([]telegramUpdate, error) {
	payload := map[string]any{
		"offset":          offset,
		"timeout":         t.pollTimeoutSeconds,
		"allowed_updates": []string{"callback_query"},
	}
	var response telegramUpdatesResponse
	if err := t.post(ctx, "getUpdates", payload, &response); err != nil {
		return nil, err
	}
	return response.Result, nil
}

func (t *Telegram) answerCallback(ctx context.Context, callbackID, text string) error {
	payload := map[string]any{
		"callback_query_id": callbackID,
		"text":              text,
	}
	return t.post(ctx, "answerCallbackQuery", payload, nil)
}

func (t *Telegram) markDecision(ctx context.Context, decision Decision, result DecisionResult) error {
	if decision.MessageID == 0 || decision.MessageText == "" {
		return nil
	}
	status := result.Status
	if status == "" {
		status = decisionStatusText(result.Answer)
	}
	payload := map[string]any{
		"chat_id":    decision.ChatID,
		"message_id": decision.MessageID,
		"text":       withDecisionStatus(decision.MessageText, status),
		"reply_markup": map[string]any{
			"inline_keyboard": []any{},
		},
	}
	return t.post(ctx, "editMessageText", payload, nil)
}

func (t *Telegram) trackAfterDecision(decision Decision, result DecisionResult) {
	if result.ActiveExpiresAt.IsZero() {
		t.forget(decision.ID)
		return
	}
	t.track(trackedMessage{
		id:             decision.ID,
		chatID:         decision.ChatID,
		messageID:      decision.MessageID,
		text:           decision.MessageText,
		expiresAt:      result.ActiveExpiresAt,
		statusOnExpire: activeExpiredStatus,
	})
}

func normalizeDecisionResult(result DecisionResult) DecisionResult {
	if result.Answer == "" {
		result.Answer = "Grant decision ignored"
	}
	return result
}

func (t *Telegram) track(message trackedMessage) {
	if message.id == "" || message.chatID == 0 || message.messageID == 0 || message.text == "" || message.expiresAt.IsZero() {
		return
	}
	t.trackedMu.Lock()
	defer t.trackedMu.Unlock()
	t.tracked[message.id] = message
}

func (t *Telegram) forget(id string) {
	t.trackedMu.Lock()
	defer t.trackedMu.Unlock()
	delete(t.tracked, id)
}

func (t *Telegram) expireTracked(ctx context.Context, now time.Time) {
	for _, message := range t.dueMessages(now.UTC()) {
		_ = t.editMessageStatus(ctx, message, message.statusOnExpire)
	}
}

func (t *Telegram) dueMessages(now time.Time) []trackedMessage {
	t.trackedMu.Lock()
	defer t.trackedMu.Unlock()
	var due []trackedMessage
	for id, message := range t.tracked {
		if now.Before(message.expiresAt) {
			continue
		}
		due = append(due, message)
		delete(t.tracked, id)
	}
	return due
}

func (t *Telegram) editMessageStatus(ctx context.Context, message trackedMessage, status string) error {
	payload := map[string]any{
		"chat_id":    message.chatID,
		"message_id": message.messageID,
		"text":       withDecisionStatus(message.text, status),
		"reply_markup": map[string]any{
			"inline_keyboard": []any{},
		},
	}
	return t.post(ctx, "editMessageText", payload, nil)
}

// UpdateGrantStatus edits a persisted grant notification.
func (t *Telegram) UpdateGrantStatus(ctx context.Context, ref MessageRef, status string) error {
	err := t.editMessageStatus(ctx, trackedMessage{
		chatID:    ref.ChatID,
		messageID: ref.MessageID,
		text:      ref.Text,
	}, status)
	if err == nil && terminalGrantStatus(status) {
		t.forgetMessage(ref.ChatID, ref.MessageID)
	}
	return err
}

func terminalGrantStatus(status string) bool {
	switch status {
	case pendingExpiredStatus, activeExpiredStatus, "✅ Used. Access is now closed.":
		return true
	default:
		return false
	}
}

func (t *Telegram) forgetMessage(chatID int64, messageID int) {
	t.trackedMu.Lock()
	defer t.trackedMu.Unlock()
	for id, message := range t.tracked {
		if message.chatID == chatID && message.messageID == messageID {
			delete(t.tracked, id)
		}
	}
}

func (t *Telegram) post(ctx context.Context, method string, payload any, out any) error {
	req, err := t.newPostRequest(ctx, method, payload)
	if err != nil {
		return err
	}
	resp, err := t.client.Do(req)
	if err != nil {
		return fmt.Errorf("telegram %s request failed", method)
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	return decodePostResponse(resp, method, out)
}

func (t *Telegram) newPostRequest(ctx context.Context, method string, payload any) (*http.Request, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("encode telegram %s request: %w", method, err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.methodURL(method), bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build telegram %s request", method)
	}
	req.Header.Set("Content-Type", "application/json")
	return req, nil
}

func decodePostResponse(resp *http.Response, method string, out any) error {
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		_, _ = io.Copy(io.Discard, resp.Body)
		return fmt.Errorf("telegram %s returned HTTP %d", method, resp.StatusCode)
	}
	if out == nil {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil
	}
	decoder := json.NewDecoder(resp.Body)
	if err := decoder.Decode(out); err != nil {
		return fmt.Errorf("decode telegram %s response: %w", method, err)
	}
	return nil
}

func (t *Telegram) methodURL(method string) string {
	return t.baseURL + "/bot" + t.token + "/" + method
}

func callbackData(action DecisionAction, id, token string) string {
	return callbackPrefix + ":" + string(action) + ":" + id + ":" + token
}

func grantText(msg GrantMessage) string {
	return fmt.Sprintf("🔐 Approval needed for hf-broker\n\n%s is asking to %s.\n\n📍 Target: %s\n🌿 Ref: %s\n⏱️ Access: %d minutes\n🔁 Uses: %s\n⌛ Request expires: %s\n\n📝 Reason: %s\n\n⚠️ Approve only if this looks right.",
		msg.Client,
		operationText(msg.Operation),
		msg.Target,
		msg.Ref,
		msg.RequestedMinutes,
		usesText(msg.MaxUses),
		formatTelegramTime(msg.PendingExpiresAt),
		msg.Reason,
	)
}

func usesText(maxUses int) string {
	if maxUses <= 1 {
		return "1 push"
	}
	return fmt.Sprintf("up to %d pushes", maxUses)
}

func operationText(operation string) string {
	switch operation {
	case "git_receive_pack":
		return "push to a Git repo"
	default:
		return operation
	}
}

func formatTelegramTime(value time.Time) string {
	return value.UTC().Format("2006-01-02 15:04 UTC")
}

func decisionStatusText(answer string) string {
	if status, ok := decisionStatusTexts[answer]; ok {
		return status
	}
	return answer
}

func withDecisionStatus(text, status string) string {
	const marker = "\n\nStatus: "
	base, _, _ := strings.Cut(text, marker)
	return base + marker + status
}

func parseDecision(update telegramUpdate) (Decision, bool) {
	if update.CallbackQuery == nil {
		return Decision{}, false
	}
	callback := update.CallbackQuery
	action, id, token, err := parseCallbackData(callback.Data)
	if err != nil || callback.ID == "" || callback.Message == nil {
		return Decision{}, false
	}
	return Decision{
		Action:      action,
		ID:          id,
		Token:       token,
		CallbackID:  callback.ID,
		ChatID:      callback.Message.Chat.ID,
		MessageID:   callback.Message.MessageID,
		MessageText: callback.Message.Text,
		OperatorID:  callback.From.ID,
		OperatorTag: callback.From.Username,
	}, true
}

func parseCallbackData(data string) (DecisionAction, string, string, error) {
	parts := strings.Split(data, ":")
	if len(parts) != 4 || parts[0] != callbackPrefix {
		return "", "", "", errors.New("invalid callback data")
	}
	action := DecisionAction(parts[1])
	if action != DecisionApprove && action != DecisionDeny {
		return "", "", "", errors.New("unsupported callback action")
	}
	if parts[2] == "" || parts[3] == "" {
		return "", "", "", errors.New("missing callback id or token")
	}
	return action, parts[2], parts[3], nil
}

func wait(ctx context.Context, d time.Duration) {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
	case <-timer.C:
	}
}

type telegramUpdatesResponse struct {
	OK     bool             `json:"ok"`
	Result []telegramUpdate `json:"result"`
}

type telegramMessageResponse struct {
	OK     bool            `json:"ok"`
	Result telegramMessage `json:"result"`
}

type telegramUpdate struct {
	UpdateID      int64                  `json:"update_id"`
	CallbackQuery *telegramCallbackQuery `json:"callback_query"`
}

type telegramCallbackQuery struct {
	ID      string           `json:"id"`
	From    telegramUser     `json:"from"`
	Message *telegramMessage `json:"message"`
	Data    string           `json:"data"`
}

type telegramUser struct {
	ID       int64  `json:"id"`
	Username string `json:"username"`
}

type telegramMessage struct {
	MessageID int          `json:"message_id"`
	Chat      telegramChat `json:"chat"`
	Text      string       `json:"text"`
}

type telegramChat struct {
	ID int64 `json:"id"`
}
