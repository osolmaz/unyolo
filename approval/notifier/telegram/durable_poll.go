package telegram

import (
	"context"
	"errors"
	"html"
	"sync"
	"time"

	"github.com/osolmaz/unyolo/approval/notifier"
)

const durablePollDelay = time.Second

// PollDurable consumes callbacks through a crash-safe inbox until ctx ends.
func (c *Client) PollDurable(ctx context.Context, inbox *Inbox, handler func(context.Context, notify.Decision) notify.DecisionResult) error {
	return c.PollDurableReady(ctx, inbox, handler, nil)
}

// PollDurableReady verifies all broker routes before consuming each update batch.
func (c *Client) PollDurableReady(ctx context.Context, inbox *Inbox,
	handler func(context.Context, notify.Decision) notify.DecisionResult, ready func(context.Context) error) error {
	if inbox == nil || handler == nil {
		return errors.New("telegram durable poll requires an inbox and handler")
	}
	for ctx.Err() == nil {
		if err := verifyDurableRoutes(ctx, ready); err != nil {
			return err
		}
		retry, err := c.pollDurableOnce(ctx, inbox, handler)
		if err != nil {
			return err
		}
		if retry {
			wait(ctx, durablePollDelay)
		}
	}
	return ctx.Err()
}

func verifyDurableRoutes(ctx context.Context, ready func(context.Context) error) error {
	if ready == nil {
		return nil
	}
	readyCtx, cancel := context.WithTimeout(ctx, operatorDecisionTimeout)
	defer cancel()
	return ready(readyCtx)
}

func (c *Client) pollDurableOnce(ctx context.Context, inbox *Inbox,
	handler func(context.Context, notify.Decision) notify.DecisionResult) (bool, error) {
	if err := c.dispatchPending(ctx, inbox, handler); err != nil {
		return retryDurablePoll()
	}
	offset, err := inbox.nextOffset(ctx)
	if err != nil {
		return retryDurablePoll()
	}
	updates, err := c.getUpdates(ctx, offset)
	if err != nil {
		return retryDurablePoll()
	}
	return false, c.persistUpdates(ctx, inbox, updates)
}

func retryDurablePoll() (bool, error) { return true, nil }

func (c *Client) persistUpdates(ctx context.Context, inbox *Inbox, updates []telegramUpdate) error {
	for _, update := range updates {
		decision := c.acceptedDecision(update)
		result, err := inbox.persistUpdate(ctx, update.UpdateID, decision)
		if err != nil {
			return err
		}
		if decision != nil {
			answer := "Approval received"
			if result.Duplicate {
				answer = "Approval is already being processed"
				if result.Answer != "" {
					answer = answerText(result.Answer)
				}
			}
			_ = c.answerCallback(ctx, decision.CallbackID, answer)
		}
	}
	return nil
}

func (c *Client) acceptedDecision(update telegramUpdate) *notify.Decision {
	decision, ok := parseDecision(update)
	if !ok || decision.ChatID != c.chatID {
		return nil
	}
	return &decision
}

func (c *Client) dispatchPending(ctx context.Context, inbox *Inbox,
	handler func(context.Context, notify.Decision) notify.DecisionResult) error {
	items, err := inbox.pending(ctx)
	if err != nil {
		return err
	}
	groups := make(map[string][]queuedDecision)
	for _, item := range items {
		groups[item.Decision.Route] = append(groups[item.Decision.Route], item)
	}
	var wait sync.WaitGroup
	errorsByRoute := make(chan error, len(groups))
	for _, routeItems := range groups {
		routeItems := routeItems
		wait.Add(1)
		go func() {
			defer wait.Done()
			for _, item := range routeItems {
				if err := c.dispatchDurableItem(ctx, inbox, handler, item); err != nil {
					errorsByRoute <- err
					return
				}
			}
		}()
	}
	wait.Wait()
	close(errorsByRoute)
	var result error
	for err := range errorsByRoute {
		result = errors.Join(result, err)
	}
	return result
}

func (c *Client) dispatchDurableItem(ctx context.Context, inbox *Inbox,
	handler func(context.Context, notify.Decision) notify.DecisionResult, item queuedDecision) error {
	result := notify.DecisionResult{Answer: notify.AnswerClosed, MessageStatus: notify.Status{Kind: notify.StatusClosed}}
	if !item.Expired {
		result = c.normalizeDecisionResult(handler(ctx, item.Decision))
		if result.Retry || result.Answer == notify.AnswerUnavailable {
			return inbox.retry(ctx, item)
		}
		return c.finishAndClose(ctx, inbox, item, result)
	}
	return c.finishAndClose(ctx, inbox, item, result)
}

func (c *Client) finishAndClose(ctx context.Context, inbox *Inbox, item queuedDecision, result notify.DecisionResult) error {
	if err := c.finishDurableDecision(ctx, item.Decision, result); err != nil {
		return inbox.retry(ctx, item)
	}
	return inbox.terminal(ctx, item, result.Answer)
}

func (c *Client) finishDurableDecision(ctx context.Context, decision notify.Decision, result notify.DecisionResult) error {
	if result.MessageStatus.Kind != "" {
		return c.editMessageStatus(ctx, decision.ChatID, decision.MessageID, html.EscapeString(decision.MessageText), result.MessageStatus)
	}
	if result.ClearButtons {
		return c.clearDecisionButtons(ctx, decision)
	}
	return nil
}
