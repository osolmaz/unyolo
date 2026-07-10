// Package telegram implements a reusable Telegram approval notifier.
package telegram

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/osolmaz/brokerkit/internal/copyx"
	"github.com/osolmaz/brokerkit/notify"
)

const (
	defaultBaseURL            = "https://api.telegram.org"
	callbackPrefix            = "bk"
	defaultPollTimeoutSeconds = 30
	defaultIgnoredAnswer      = "Decision ignored"
	defaultPendingExpired     = "Expired. Request was not approved in time."
	defaultActiveExpired      = "Expired. Access window ended."
)

var errMessageNotModified = errors.New("telegram message is not modified")

// Options configures Telegram approval behavior.
type Options struct {
	PollTimeoutSeconds  int
	IgnoredAnswer       string
	PendingExpired      string
	ActiveExpired       string
	ApproveText         string
	DenyText            string
	StatusByAnswer      map[string]string
	TerminalStatuses    []string
	TerminalStatusStart []string
}

type trackedMessage struct {
	id             string
	chatID         int64
	messageID      int
	text           string
	expiresAt      time.Time
	statusOnExpire string
}

// Client sends approval messages through Telegram Bot API.
type Client struct {
	token              string
	chatID             int64
	baseURL            string
	client             *http.Client
	pollTimeoutSeconds int
	ignoredAnswer      string
	pendingExpired     string
	activeExpired      string
	approveText        string
	denyText           string
	statusByAnswer     map[string]string
	terminalStatuses   []string
	terminalStarts     []string
	trackedMu          sync.Mutex
	tracked            map[string]trackedMessage
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
		ignoredAnswer:      opts.IgnoredAnswer,
		pendingExpired:     opts.PendingExpired,
		activeExpired:      opts.ActiveExpired,
		approveText:        opts.ApproveText,
		denyText:           opts.DenyText,
		statusByAnswer:     copyx.StringMap(opts.StatusByAnswer),
		terminalStatuses:   append([]string(nil), opts.TerminalStatuses...),
		terminalStarts:     append([]string(nil), opts.TerminalStatusStart...),
		tracked:            map[string]trackedMessage{},
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
	if opts.PendingExpired == "" {
		opts.PendingExpired = defaultPendingExpired
	}
	if opts.ActiveExpired == "" {
		opts.ActiveExpired = defaultActiveExpired
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
	ref := notify.MessageRef{Kind: "telegram", ChatID: chatID, MessageID: response.Result.MessageID, Text: text}
	c.track(trackedMessage{
		id:             msg.GrantID,
		chatID:         chatID,
		messageID:      response.Result.MessageID,
		text:           text,
		expiresAt:      msg.PendingExpiresAt,
		statusOnExpire: c.pendingExpired,
	})
	return ref, nil
}

// UpdateStatus edits an existing approval message status.
func (c *Client) UpdateStatus(ctx context.Context, ref notify.MessageRef, status string) error {
	err := c.editMessageStatus(ctx, trackedMessage{chatID: ref.ChatID, messageID: ref.MessageID, text: ref.Text}, status)
	if errors.Is(err, errMessageNotModified) {
		err = nil
	}
	if err == nil && c.terminalStatus(status) {
		c.forgetMessage(ref.ChatID, ref.MessageID)
	}
	return err
}

// Poll runs Telegram long polling until ctx is canceled.
func (c *Client) Poll(ctx context.Context, handler func(context.Context, notify.Decision) notify.DecisionResult) {
	var offset int64
	for ctx.Err() == nil {
		nextOffset, err := c.PollOnce(ctx, offset, handler)
		if err != nil {
			wait(ctx, time.Second)
			continue
		}
		offset = nextOffset
	}
}

// PollOnce fetches and handles one Telegram update batch.
func (c *Client) PollOnce(ctx context.Context, offset int64, handler func(context.Context, notify.Decision) notify.DecisionResult) (int64, error) {
	updates, err := c.getUpdates(ctx, offset)
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
		result := notify.DecisionResult{Answer: c.ignoredAnswer}
		if decision.ChatID == c.chatID {
			result = c.normalizeDecisionResult(handler(ctx, decision))
		}
		_ = c.answerCallback(ctx, decision.CallbackID, result.Answer)
		if decision.ChatID == c.chatID {
			_ = c.markDecision(ctx, decision, result)
			c.trackAfterDecision(decision, result)
		}
	}
	return nextOffset, nil
}

// ExpireTracked edits tracked approval messages whose pending or active window expired.
func (c *Client) ExpireTracked(ctx context.Context, now time.Time) {
	for _, message := range c.dueMessages(now.UTC()) {
		_ = c.editMessageStatus(ctx, message, message.statusOnExpire)
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

func (c *Client) markDecision(ctx context.Context, decision notify.Decision, result notify.DecisionResult) error {
	if decision.MessageID == 0 || decision.MessageText == "" {
		return nil
	}
	status := result.Status
	if status == "" {
		status = c.statusForAnswer(result.Answer)
	}
	return c.editMessageStatus(ctx, trackedMessage{
		chatID:    decision.ChatID,
		messageID: decision.MessageID,
		text:      decision.MessageText,
	}, status)
}

func (c *Client) trackAfterDecision(decision notify.Decision, result notify.DecisionResult) {
	if result.ActiveExpiresAt.IsZero() {
		c.forget(decision.GrantID)
		return
	}
	c.track(trackedMessage{
		id:             decision.GrantID,
		chatID:         decision.ChatID,
		messageID:      decision.MessageID,
		text:           decision.MessageText,
		expiresAt:      result.ActiveExpiresAt,
		statusOnExpire: c.activeExpired,
	})
}

func (c *Client) normalizeDecisionResult(result notify.DecisionResult) notify.DecisionResult {
	if result.Answer == "" {
		result.Answer = c.ignoredAnswer
	}
	return result
}

func (c *Client) statusForAnswer(answer string) string {
	if value, ok := c.statusByAnswer[answer]; ok {
		return value
	}
	return answer
}

func (c *Client) track(message trackedMessage) {
	if message.id == "" || message.chatID == 0 || message.messageID == 0 || message.text == "" || message.expiresAt.IsZero() {
		return
	}
	c.trackedMu.Lock()
	defer c.trackedMu.Unlock()
	c.tracked[message.id] = message
}

func (c *Client) forget(id string) {
	c.trackedMu.Lock()
	defer c.trackedMu.Unlock()
	delete(c.tracked, id)
}

func (c *Client) forgetMessage(chatID int64, messageID int) {
	c.trackedMu.Lock()
	defer c.trackedMu.Unlock()
	for id, message := range c.tracked {
		if message.chatID == chatID && message.messageID == messageID {
			delete(c.tracked, id)
		}
	}
}

func (c *Client) dueMessages(now time.Time) []trackedMessage {
	c.trackedMu.Lock()
	defer c.trackedMu.Unlock()
	var due []trackedMessage
	for id, message := range c.tracked {
		if now.Before(message.expiresAt) {
			continue
		}
		due = append(due, message)
		delete(c.tracked, id)
	}
	return due
}

func (c *Client) editMessageStatus(ctx context.Context, message trackedMessage, status string) error {
	payload := map[string]any{
		"chat_id":    message.chatID,
		"message_id": message.messageID,
		"text":       withDecisionStatus(message.text, status),
		"reply_markup": map[string]any{
			"inline_keyboard": []any{},
		},
	}
	var response okResponse
	return c.post(ctx, "editMessageText", payload, &response)
}

func (c *Client) terminalStatus(status string) bool {
	if status == c.pendingExpired || status == c.activeExpired {
		return true
	}
	return slices.Contains(c.terminalStatuses, status) || hasAnyPrefix(status, c.terminalStarts)
}

func hasAnyPrefix(value string, prefixes []string) bool {
	for _, prefix := range prefixes {
		if strings.HasPrefix(value, prefix) {
			return true
		}
	}
	return false
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
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("decode telegram response: %w", err)
	}
	if err := checkTelegramResponse(out); err != nil {
		return err
	}
	return nil
}

func decodeTelegramError(resp *http.Response) error {
	var apiError telegramErrorResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64*1024)).Decode(&apiError); err != nil || apiError.Description == "" {
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

func parseDecision(update telegramUpdate) (notify.Decision, bool) {
	if update.CallbackQuery == nil {
		return notify.Decision{}, false
	}
	callback := update.CallbackQuery
	action, grantID, token, ok := ParseCallbackData(callback.Data)
	if !ok || callback.ID == "" || callback.Message == nil {
		return notify.Decision{}, false
	}
	return notify.Decision{
		Action:        action,
		GrantID:       grantID,
		DecisionToken: token,
		CallbackID:    callback.ID,
		ChatID:        callback.Message.Chat.ID,
		MessageID:     callback.Message.MessageID,
		MessageText:   callback.Message.Text,
		OperatorID:    callback.From.ID,
		OperatorTag:   callback.From.Username,
		Approver:      callback.From.Username,
	}, true
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
