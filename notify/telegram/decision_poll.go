package telegram

import (
	"context"
	"errors"

	"github.com/osolmaz/brokerkit/notify"
)

// ErrDecisionRetry reports that a decision handler asked Telegram polling to
// leave the current update pending for a later durable retry.
var ErrDecisionRetry = errors.New("telegram decision requires retry")

// PollOnce fetches and handles one Telegram update batch.
func (c *Client) PollOnce(ctx context.Context, offset int64, handler func(context.Context, notify.Decision) notify.DecisionResult) (int64, error) {
	updates, err := c.getUpdates(ctx, offset)
	if err != nil {
		return offset, err
	}
	nextOffset := offset
	for _, update := range updates {
		decision, ok := parseDecision(update)
		if !ok {
			nextOffset = offsetAfterUpdate(nextOffset, update.UpdateID)
			continue
		}
		if c.handleDecision(ctx, decision, handler) {
			return nextOffset, ErrDecisionRetry
		}
		nextOffset = offsetAfterUpdate(nextOffset, update.UpdateID)
	}
	return nextOffset, nil
}

func offsetAfterUpdate(offset, updateID int64) int64 {
	if updateID >= offset {
		return updateID + 1
	}
	return offset
}

func (c *Client) handleDecision(ctx context.Context, decision notify.Decision, handler func(context.Context, notify.Decision) notify.DecisionResult) bool {
	if decision.Route != c.route {
		return c.retryForeignDecision(ctx, decision)
	}
	result := notify.DecisionResult{Answer: c.ignoredAnswer}
	if decision.ChatID == c.chatID {
		delete(c.foreignAttempts, decision.CallbackID)
		result = c.normalizeDecisionResult(handler(ctx, decision))
		if result.Retry {
			return true
		}
		if result.MessageStatus != "" {
			_ = c.answerCallback(ctx, decision.CallbackID, result.Answer)
			_ = c.editImmediateStatus(ctx, decision, result.MessageStatus)
			return false
		}
	}
	_ = c.answerCallback(ctx, decision.CallbackID, result.Answer)
	return false
}

func (c *Client) retryForeignDecision(ctx context.Context, decision notify.Decision) bool {
	if _, exists := c.foreignAttempts[decision.CallbackID]; !exists && len(c.foreignAttempts) >= maxForeignCallbacks {
		clear(c.foreignAttempts)
	}
	attempts := c.foreignAttempts[decision.CallbackID] + 1
	if attempts <= c.foreignRetries {
		c.foreignAttempts[decision.CallbackID] = attempts
		return true
	}
	delete(c.foreignAttempts, decision.CallbackID)
	answer := "Approval broker is unavailable"
	_ = c.answerCallback(ctx, decision.CallbackID, answer)
	_ = c.editMessageStatus(ctx, decision.ChatID, decision.MessageID, decision.MessageText, "Unavailable. Approval broker did not respond.")
	return false
}

func parseDecision(update telegramUpdate) (notify.Decision, bool) {
	if update.CallbackQuery == nil {
		return notify.Decision{}, false
	}
	callback := update.CallbackQuery
	route, action, grantID, token, ok := parseCallbackData(callback.Data)
	if !ok {
		return notify.Decision{}, false
	}
	if callback.ID == "" {
		return notify.Decision{}, false
	}
	if callback.Message == nil {
		return notify.Decision{}, false
	}
	if callback.Message.Chat.ID == 0 {
		return notify.Decision{}, false
	}
	if callback.Message.MessageID <= 0 {
		return notify.Decision{}, false
	}
	if callback.Message.Text == "" {
		return notify.Decision{}, false
	}
	return notify.Decision{
		Route:         route,
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
