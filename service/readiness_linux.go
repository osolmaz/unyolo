//go:build linux

package service

import (
	"context"
	"errors"
	"fmt"
	"net/http"
)

// HTTPReadyCheck returns a readiness check that accepts any successful HTTP
// status. The request body is never read or included in errors.
func HTTPReadyCheck(rawURL string, client *http.Client) ReadinessCheck {
	if client == nil {
		client = http.DefaultClient
	}
	return func(ctx context.Context) error {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
		if err != nil {
			return fmt.Errorf("create readiness request: %w", err)
		}
		response, err := client.Do(request)
		if err != nil {
			return errors.New("readiness request failed")
		}
		_ = response.Body.Close()
		if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
			return fmt.Errorf("readiness endpoint returned HTTP %d", response.StatusCode)
		}
		return nil
	}
}
