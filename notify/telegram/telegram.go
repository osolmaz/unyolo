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

	"github.com/osolmaz/brokerkit/notify"
)

const (
	defaultBaseURL = "https://api.telegram.org"
	callbackPrefix = "bk"
)

// Client sends approval messages through Telegram Bot API.
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
	return &Client{
		token:   token,
		chatID:  chatID,
		baseURL: strings.TrimRight(baseURL, "/"),
		client:  httpClient,
	}, nil
}

// SendApproval sends one approval message with approve/deny buttons.
func (c *Client) SendApproval(ctx context.Context, msg notify.ApprovalMessage) (notify.MessageRef, error) {
	text := RenderApproval(msg)
	payload := map[string]any{
		"chat_id": c.chatID,
		"text":    text,
		"reply_markup": map[string]any{
			"inline_keyboard": [][]map[string]string{{
				{"text": "Approve", "callback_data": CallbackData(notify.ActionApprove, msg.GrantID, msg.DecisionToken)},
				{"text": "Deny", "callback_data": CallbackData(notify.ActionDeny, msg.GrantID, msg.DecisionToken)},
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
	text := ref.Text
	if text != "" {
		text += "\n\n" + status
	} else {
		text = status
	}
	payload := map[string]any{"chat_id": ref.ChatID, "message_id": ref.MessageID, "text": text}
	var response okResponse
	return c.post(ctx, "editMessageText", payload, &response)
}

// RenderApproval returns generic approval message text.
func RenderApproval(msg notify.ApprovalMessage) string {
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
		return fmt.Errorf("telegram request returned status %d", resp.StatusCode)
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("decode telegram response: %w", err)
	}
	if err := checkTelegramResponse(out); err != nil {
		return err
	}
	return nil
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
	}
	return nil
}

type okResponse struct {
	OK bool `json:"ok"`
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
