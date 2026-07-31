//go:build !linux

package deployment

import (
	"context"
	"errors"
)

func staleClientHandle(resource ResourceReceipt) string {
	return resourceReceiptKey(resource)[7:]
}

func (engine *Engine) quarantineStaleClient(context.Context, ResourceReceipt) (string, error) {
	return "", errors.New("stale client cleanup is not supported on this host")
}

func (engine *Engine) restoreStaleClient(context.Context, string) error {
	return errors.New("stale client cleanup is not supported on this host")
}

func (engine *Engine) discardStaleClientBackup(string) error {
	return errors.New("stale client cleanup is not supported on this host")
}
