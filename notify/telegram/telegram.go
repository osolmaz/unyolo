// Package telegram implements a reusable Telegram approval notifier.
package telegram

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/osolmaz/brokerkit/httpx"
	"github.com/osolmaz/brokerkit/notify"
)

const (
	defaultBaseURL            = "https://api.telegram.org"
	callbackPrefix            = "bk"
	defaultPollTimeoutSeconds = 30
	defaultIgnoredAnswer      = "Decision ignored"
)

var errMessageNotModified = errors.New("telegram message is not modified")

// Options configures Telegram approval behavior.
type Options struct {
	PollTimeoutSeconds int
	IgnoredAnswer      string
	ApproveText        string
	DenyText           string
}

// Client sends approval messages through Telegram Bot API.
type Client struct {
	token              string
	chatID             int64
	baseURL            string
	client             *http.Client
	pollTimeoutSeconds int
	retryDelay         time.Duration
	ignoredAnswer      string
	approveText        string
	denyText           string
}

// New returns a Telegram client.
func New(token string, chatID int64, httpClient *http.Client, baseURL string) (*Client, error) {
	return NewWithOptions(token, chatID, httpClient, baseURL, Options{})
}

// NewWithOptions returns a Telegram client with custom status behavior.
func NewWithOptions(token string, chatID int64, httpClient *http.Client, baseURL string, opts Options) (*Client, error) {
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
	opts = normalizeOptions(opts)
	return &Client{
		token:              token,
		chatID:             chatID,
		baseURL:            strings.TrimRight(baseURL, "/"),
		client:             httpClient,
		pollTimeoutSeconds: opts.PollTimeoutSeconds,
		retryDelay:         time.Second,
		ignoredAnswer:      opts.IgnoredAnswer,
		approveText:        opts.ApproveText,
		denyText:           opts.DenyText,
	}, nil
}

func normalizeOptions(opts Options) Options {
	if opts.PollTimeoutSeconds < 0 {
		opts.PollTimeoutSeconds = 0
	}
	if opts.PollTimeoutSeconds == 0 {
		opts.PollTimeoutSeconds = defaultPollTimeoutSeconds
	}
	if opts.IgnoredAnswer == "" {
		opts.IgnoredAnswer = defaultIgnoredAnswer
	}
	if opts.ApproveText == "" {
		opts.ApproveText = "Approve"
	}
	if opts.DenyText == "" {
		opts.DenyText = "Deny"
	}
	return opts
}

// SendApproval sends one approval message with approve/deny buttons.
func (c *Client) SendApproval(ctx context.Context, msg notify.ApprovalMessage) (notify.MessageRef, error) {
	text := RenderApproval(msg)
	payload := map[string]any{
		"chat_id": c.chatID,
		"text":    text,
		"reply_markup": map[string]any{
			"inline_keyboard": [][]map[string]string{{
				{"text": c.approveText, "callback_data": CallbackData(notify.ActionApprove, msg.GrantID, msg.DecisionToken)},
				{"text": c.denyText, "callback_data": CallbackData(notify.ActionDeny, msg.GrantID, msg.DecisionToken)},
			}},
		},
	}
	var response messageResponse
	if err := c.post(ctx, "sendMessage", payload, &response); err != nil {
		return notify.MessageRef{}, err
	}
	chatID := response.Result.Chat.ID
	if chatID == 0 {
		chatID = c.chatID
	}
	return notify.MessageRef{Kind: "telegram", ChatID: chatID, MessageID: response.Result.MessageID, Text: text}, nil
}

// UpdateStatus edits an existing approval message status.
func (c *Client) UpdateStatus(ctx context.Context, ref notify.MessageRef, status string) error {
	err := c.editMessageStatus(ctx, ref.ChatID, ref.MessageID, ref.Text, status)
	if errors.Is(err, errMessageNotModified) {
		return nil
	}
	return err
}

// Poll runs Telegram long polling until ctx is canceled.
func (c *Client) Poll(ctx context.Context, handler func(context.Context, notify.Decision) notify.DecisionResult) {
	var offset int64
	for ctx.Err() == nil {
		var err error
		offset, err = c.PollOnce(ctx, offset, handler)
		if err != nil {
			wait(ctx, c.retryDelay)
		}
	}
}

func (c *Client) getUpdates(ctx context.Context, offset int64) ([]telegramUpdate, error) {
	payload := map[string]any{
		"offset":          offset,
		"timeout":         c.pollTimeoutSeconds,
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
		result.Answer = c.ignoredAnswer
	}
	return result
}

func (c *Client) editMessageStatus(ctx context.Context, chatID int64, messageID int, text string, status string) error {
	payload := map[string]any{
		"chat_id":    chatID,
		"message_id": messageID,
		"text":       withDecisionStatus(text, status),
		"reply_markup": map[string]any{
			"inline_keyboard": []any{},
		},
	}
	var response okResponse
	return c.post(ctx, "editMessageText", payload, &response)
}

// RenderApproval returns generic approval message text.
func RenderApproval(msg notify.ApprovalMessage) string {
	if strings.TrimSpace(msg.Text) != "" {
		return strings.TrimSpace(msg.Text)
	}
	var builder strings.Builder
	builder.WriteString("Approval requested\n")
	builder.WriteString("Client: " + msg.Client + "\n")
	builder.WriteString("Operation: " + msg.Operation + "\n")
	builder.WriteString("Target: " + msg.Target + "\n")
	for _, field := range msg.Fields {
		builder.WriteString(field.Name + ": " + field.Value + "\n")
	}
	builder.WriteString("Reason: " + msg.Reason + "\n")
	if msg.RequestedMinutes > 0 {
		builder.WriteString("Minutes: " + strconv.Itoa(msg.RequestedMinutes) + "\n")
	}
	if msg.MaxUses > 0 {
		builder.WriteString("Max uses: " + strconv.Itoa(msg.MaxUses) + "\n")
	}
	return strings.TrimSpace(builder.String())
}

// CallbackData encodes one button callback.
func CallbackData(action notify.Action, grantID string, token string) string {
	return strings.Join([]string{
		callbackPrefix,
		string(action),
		encodeCallbackPart(grantID),
		encodeCallbackPart(token),
	}, ":")
}

// ParseCallbackData decodes one callback_data value.
func ParseCallbackData(data string) (notify.Action, string, string, bool) {
	parts := strings.Split(data, ":")
	if len(parts) != 4 || parts[0] != callbackPrefix {
		return "", "", "", false
	}
	action := notify.Action(parts[1])
	if action != notify.ActionApprove && action != notify.ActionDeny {
		return "", "", "", false
	}
	grantID, ok := decodeCallbackPart(parts[2])
	if !ok {
		return "", "", "", false
	}
	token, ok := decodeCallbackPart(parts[3])
	if !ok {
		return "", "", "", false
	}
	return action, grantID, token, true
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

func withDecisionStatus(text string, status string) string {
	const marker = "\n\nStatus: "
	base, _, _ := strings.Cut(text, marker)
	return base + marker + status
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
	MessageID int          `json:"message_id"`
	Chat      telegramChat `json:"chat"`
	Text      string       `json:"text"`
}

type telegramChat struct {
	ID int64 `json:"id"`
}
