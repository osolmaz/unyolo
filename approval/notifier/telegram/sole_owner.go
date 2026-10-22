package telegram

import (
	"context"
	"errors"
)

// ErrAnotherOwner reports that another process receives this bot's updates,
// through its own getUpdates calls or through a webhook. Telegram answers
// such conflicts with HTTP 409. One bot needs exactly one owner, so the
// owner stops instead of competing for updates.
var ErrAnotherOwner = errors.New("another process receives this bot's updates")

// SoleOwnerProbeSeconds is how long the startup probe waits for a competing
// getUpdates call.
const SoleOwnerProbeSeconds = 5

type webhookInfoResponse struct {
	OK     bool `json:"ok"`
	Result struct {
		URL string `json:"url"`
	} `json:"result"`
}

// HasWebhook reports whether the bot delivers its updates to a webhook.
func (c *Client) HasWebhook(ctx context.Context) (bool, error) {
	var response webhookInfoResponse
	if err := c.post(ctx, "getWebhookInfo", map[string]any{}, &response); err != nil {
		return false, err
	}
	if !response.OK {
		return false, errors.New("telegram response returned ok=false")
	}
	return response.Result.URL != "", nil
}

// ProbeSoleOwner checks that no other process receives this bot's updates.
// It fails when the bot has a webhook, or when another getUpdates call
// arrives while its own long poll waits. The probe confirms no update, so a
// later poll still receives every pending update.
func (c *Client) ProbeSoleOwner(ctx context.Context, seconds int) error {
	webhook, err := c.HasWebhook(ctx)
	if err != nil {
		return err
	}
	if webhook {
		return errors.Join(ErrAnotherOwner, errors.New("the bot has a webhook"))
	}
	var response updatesResponse
	return c.post(ctx, "getUpdates", map[string]any{
		"timeout": seconds, "limit": 1, "allowed_updates": []string{"callback_query"},
	}, &response)
}
