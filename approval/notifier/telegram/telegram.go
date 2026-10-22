// Package telegram is unYOLO's single Telegram owner. It sends the approval
// cards of every broker, reads the button clicks, and decides through each
// broker's Operator V1 API.
package telegram

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/osolmaz/unyolo/approval/notifier"
	"github.com/osolmaz/unyolo/transport/http"
)

const (
	defaultBaseURL     = "https://api.telegram.org"
	callbackPrefix     = "bk"
	pollTimeoutSeconds = 30
)

const (
	// RouteHuggingFace routes callbacks to hf-broker.
	RouteHuggingFace = "h"
	// RouteGitHub routes callbacks to gh-broker.
	RouteGitHub = "g"
	// RouteSudo routes callbacks to sudo-broker.
	RouteSudo = "s"
)

// Button labels. A click is accepted only when Telegram reports the label
// that belongs to the clicked action.
const (
	approveButtonText = "✅ Approve"
	denyButtonText    = "❌ Deny"
)

var errMessageNotModified = errors.New("telegram message is not modified")

func buttonText(action notify.Action) string {
	switch action {
	case notify.ActionApprove:
		return approveButtonText
	case notify.ActionDeny:
		return denyButtonText
	default:
		return ""
	}
}

// Client talks to the Telegram Bot API for one operator chat.
type Client struct {
	token   string
	chatID  int64
	baseURL string
	client  *http.Client
}

// New returns a Telegram client.
func New(token string, chatID int64, httpClient *http.Client, baseURL string) (*Client, error) {
	if strings.TrimSpace(token) == "" {
		return nil, errors.New("telegram bot token is required")
	}
	if chatID == 0 {
		return nil, errors.New("telegram chat id is required")
	}
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}
	if baseURL == "" {
		baseURL = defaultBaseURL
	}
	return &Client{token: token, chatID: chatID, baseURL: strings.TrimRight(baseURL, "/"), client: httpClient}, nil
}

// sendCard sends one rendered approval card with approve and deny buttons and
// returns the chat and message that Telegram assigned to it.
func (c *Client) sendCard(ctx context.Context, route, requestID, token, text string) (int64, int, error) {
	if strings.TrimSpace(requestID) == "" || strings.TrimSpace(token) == "" {
		return 0, 0, errors.New("approval card request id and token are required")
	}
	payload := map[string]any{
		"chat_id":    c.chatID,
		"text":       text,
		"parse_mode": "HTML",
		"reply_markup": map[string]any{
			"inline_keyboard": [][]map[string]string{{
				{"text": approveButtonText, "callback_data": callbackData(route, notify.ActionApprove, requestID, token)},
				{"text": denyButtonText, "callback_data": callbackData(route, notify.ActionDeny, requestID, token)},
			}},
		},
	}
	var response messageResponse
	if err := c.post(ctx, "sendMessage", payload, &response); err != nil {
		return 0, 0, err
	}
	if response.Result.MessageID <= 0 {
		return 0, 0, errors.New("telegram returned no message id for the approval card")
	}
	chatID := response.Result.Chat.ID
	if chatID == 0 {
		chatID = c.chatID
	}
	return chatID, response.Result.MessageID, nil
}

// updateCard shows a request status on its card and removes the buttons.
func (c *Client) updateCard(ctx context.Context, chatID int64, messageID int, text string, status notify.Status) error {
	err := c.editMessageStatus(ctx, chatID, messageID, text, status)
	if errors.Is(err, errMessageNotModified) {
		return nil
	}
	return err
}

func (c *Client) getUpdates(ctx context.Context, offset int64) ([]telegramUpdate, error) {
	payload := map[string]any{
		"offset":          offset,
		"timeout":         pollTimeoutSeconds,
		"allowed_updates": []string{"callback_query"},
	}
	var response updatesResponse
	if err := c.post(ctx, "getUpdates", payload, &response); err != nil {
		return nil, err
	}
	return response.Result, nil
}

func (c *Client) answerCallback(ctx context.Context, callbackID string, text string) error {
	payload := map[string]any{
		"callback_query_id": callbackID,
		"text":              text,
	}
	var response okResponse
	return c.post(ctx, "answerCallbackQuery", payload, &response)
}

func (c *Client) normalizeDecisionResult(result notify.DecisionResult) notify.DecisionResult {
	if result.Answer == "" {
		result.Answer = notify.AnswerIgnored
	}
	return result
}

func (c *Client) editMessageStatus(ctx context.Context, chatID int64, messageID int, text string, status notify.Status) error {
	payload := map[string]any{
		"chat_id":    chatID,
		"message_id": messageID,
		"text":       withDecisionStatus(text, status),
		"parse_mode": "HTML",
		"reply_markup": map[string]any{
			"inline_keyboard": []any{},
		},
	}
	var response okResponse
	return c.post(ctx, "editMessageText", payload, &response)
}

func callbackData(route string, action notify.Action, grantID string, token string) string {
	var actionCode string
	switch action {
	case notify.ActionApprove:
		actionCode = "a"
	case notify.ActionDeny:
		actionCode = "d"
	default:
		actionCode = string(action)
	}
	return strings.Join([]string{
		callbackPrefix,
		route,
		actionCode,
		encodeCallbackPart(grantID),
		encodeCallbackPart(token),
	}, ":")
}

func parseCallbackData(data string) (string, notify.Action, string, string, bool) {
	parts := strings.Split(data, ":")
	if len(parts) != 5 || parts[0] != callbackPrefix || !validRoute(parts[1]) {
		return "", "", "", "", false
	}
	var action notify.Action
	switch parts[2] {
	case "a":
		action = notify.ActionApprove
	case "d":
		action = notify.ActionDeny
	default:
		return "", "", "", "", false
	}
	grantID, ok := decodeCallbackPart(parts[3])
	if !ok {
		return "", "", "", "", false
	}
	token, ok := decodeCallbackPart(parts[4])
	if !ok {
		return "", "", "", "", false
	}
	return parts[1], action, grantID, token, true
}

func validRoute(route string) bool {
	return len(route) == 1 && route[0] >= 'a' && route[0] <= 'z'
}

func encodeCallbackPart(value string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(value))
}

func decodeCallbackPart(value string) (string, bool) {
	if value == "" {
		return "", false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(decoded) == 0 {
		return "", false
	}
	return string(decoded), true
}

func (c *Client) post(ctx context.Context, method string, payload any, out any) error {
	req, err := c.newRequest(ctx, method, payload)
	if err != nil {
		return err
	}
	resp, err := c.do(req)
	if err != nil {
		return err
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	return decodeTelegramResponse(resp, out)
}

func (c *Client) newRequest(ctx context.Context, method string, payload any) (*http.Request, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("encode telegram request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/bot"+c.token+"/"+method, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build telegram request: %w", c.redactedError(err))
	}
	req.Header.Set("Content-Type", "application/json")
	return req, nil
}

func (c *Client) do(req *http.Request) (*http.Response, error) {
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("telegram request failed: %w", c.redactedError(err))
	}
	return resp, nil
}

func decodeTelegramResponse(resp *http.Response, out any) error {
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return decodeTelegramError(resp)
	}
	if out == nil {
		_, err := httpx.ReadLimited(resp.Body, 64*1024)
		return err
	}
	if err := httpx.DecodeJSON(resp.Body, 64*1024, out, false); err != nil {
		return fmt.Errorf("decode telegram response: %w", err)
	}
	if err := checkTelegramResponse(out); err != nil {
		return err
	}
	return nil
}

func decodeTelegramError(resp *http.Response) error {
	var apiError telegramErrorResponse
	if err := httpx.DecodeJSON(resp.Body, 64*1024, &apiError, false); err != nil || apiError.Description == "" {
		return fmt.Errorf("telegram request returned status %d", resp.StatusCode)
	}
	if strings.Contains(strings.ToLower(apiError.Description), "message is not modified") {
		return errMessageNotModified
	}
	return fmt.Errorf("telegram request returned status %d", resp.StatusCode)
}

func (c *Client) redactedError(err error) error {
	return errors.New(strings.ReplaceAll(err.Error(), c.token, "[redacted]"))
}

func checkTelegramResponse(out any) error {
	switch response := out.(type) {
	case *okResponse:
		if !response.OK {
			return errors.New("telegram response returned ok=false")
		}
	case *messageResponse:
		if !response.OK {
			return errors.New("telegram response returned ok=false")
		}
	case *updatesResponse:
		if !response.OK {
			return errors.New("telegram response returned ok=false")
		}
	}
	return nil
}

func withDecisionStatus(text string, status notify.Status) string {
	const marker = "\n\n<b>Status</b>\n"
	base, _, _ := strings.Cut(text, marker)
	return base + marker + renderStatus(status)
}

func wait(ctx context.Context, d time.Duration) {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
	case <-timer.C:
	}
}

type okResponse struct {
	OK bool `json:"ok"`
}

type telegramErrorResponse struct {
	OK          bool   `json:"ok"`
	ErrorCode   int    `json:"error_code"`
	Description string `json:"description"`
}

type updatesResponse struct {
	OK     bool             `json:"ok"`
	Result []telegramUpdate `json:"result"`
}

type messageResponse struct {
	OK     bool `json:"ok"`
	Result struct {
		MessageID int `json:"message_id"`
		Chat      struct {
			ID int64 `json:"id"`
		} `json:"chat"`
	} `json:"result"`
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
	MessageID   int                   `json:"message_id"`
	Chat        telegramChat          `json:"chat"`
	Text        string                `json:"text"`
	ReplyMarkup *telegramInlineMarkup `json:"reply_markup"`
}

type telegramInlineMarkup struct {
	InlineKeyboard [][]telegramInlineButton `json:"inline_keyboard"`
}

type telegramInlineButton struct {
	Text         string `json:"text"`
	CallbackData string `json:"callback_data"`
}

// pressedButtonText returns the label of the button that carries data, as the
// message currently shows it.
func (m *telegramMessage) pressedButtonText(data string) string {
	if m.ReplyMarkup == nil {
		return ""
	}
	for _, row := range m.ReplyMarkup.InlineKeyboard {
		for _, button := range row {
			if button.CallbackData == data {
				return button.Text
			}
		}
	}
	return ""
}

type telegramChat struct {
	ID int64 `json:"id"`
}
