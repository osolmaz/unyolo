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
	"time"
)

const (
	defaultTelegramBaseURL = "https://api.telegram.org"
	callbackPrefix         = "hfbg"
)

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
	OperatorID  int64
	OperatorTag string
}

// DecisionHandler applies one approved-chat decision and returns the text
// sent back to Telegram's callback answer.
type DecisionHandler func(context.Context, Decision) string

// Telegram long-polls the Bot API for grant decisions.
type Telegram struct {
	token              string
	chatID             int64
	baseURL            string
	client             *http.Client
	pollTimeoutSeconds int
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
	}
}

// SendGrantRequest sends one pending grant request with Approve and Deny buttons.
func (t *Telegram) SendGrantRequest(ctx context.Context, msg GrantMessage) error {
	payload := map[string]any{
		"chat_id": t.chatID,
		"text":    grantText(msg),
		"reply_markup": map[string]any{
			"inline_keyboard": [][]map[string]string{{
				{"text": "Approve", "callback_data": callbackData(DecisionApprove, msg.ID, msg.DecisionToken)},
				{"text": "Deny", "callback_data": callbackData(DecisionDeny, msg.ID, msg.DecisionToken)},
			}},
		},
	}
	return t.post(ctx, "sendMessage", payload, nil)
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
		answer := "Grant decision ignored"
		if decision.ChatID == t.chatID {
			answer = handler(ctx, decision)
		}
		_ = t.answerCallback(ctx, decision.CallbackID, answer)
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
	return fmt.Sprintf("hf-broker grant request\nClient: %s\nOperation: %s\nTarget: %s\nRef: %s\nMinutes: %d\nPending until: %s\nReason: %s",
		msg.Client,
		msg.Operation,
		msg.Target,
		msg.Ref,
		msg.RequestedMinutes,
		msg.PendingExpiresAt.UTC().Format(time.RFC3339),
		msg.Reason,
	)
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
	Chat telegramChat `json:"chat"`
}

type telegramChat struct {
	ID int64 `json:"id"`
}
