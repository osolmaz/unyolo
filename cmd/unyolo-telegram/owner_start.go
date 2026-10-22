package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/osolmaz/unyolo/approval/notifier/telegram"
)

// ownerConflictPath records when this owner last found another process that
// receives the bot's updates. The doctor reads the record, because the doctor
// must not poll the bot and so take updates away from the running owner.
func ownerConflictPath(cfg ingressConfig) string {
	return filepath.Join(filepath.Dir(cfg.InboxPath), "owner-conflict")
}

// startOwner checks that this process is the bot's only owner and that every
// route speaks the current Operator V1 contract. It then tells systemd that
// the service is ready, so setup fails when a second owner exists.
func startOwner(ctx context.Context, cfg ingressConfig, built ingress) error {
	if err := built.client.ProbeSoleOwner(ctx, telegram.SoleOwnerProbeSeconds); err != nil {
		return recordOwnerConflict(ownerConflictPath(cfg), err)
	}
	if err := built.dispatcher.Compatible(ctx); err != nil {
		return err
	}
	if err := os.Remove(ownerConflictPath(cfg)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("clear owner conflict record: %w", err)
	}
	return notifyReady()
}

// recordOwnerConflict writes the conflict time for the doctor and explains the
// conflict. Other errors pass through unchanged.
func recordOwnerConflict(path string, err error) error {
	if !errors.Is(err, telegram.ErrAnotherOwner) {
		return err
	}
	record := []byte(time.Now().UTC().Format(time.RFC3339) + "\n")
	if writeErr := os.WriteFile(path, record, 0o600); writeErr != nil {
		return errors.Join(err, fmt.Errorf("record owner conflict: %w", writeErr))
	}
	return fmt.Errorf("%w: run exactly one unyolo-telegram for each bot, and stop every other program that uses this bot token", err)
}

// notifyReady tells systemd that the service finished its startup checks. It
// does nothing when the service does not run with Type=notify.
func notifyReady() error {
	socket := os.Getenv("NOTIFY_SOCKET")
	if socket == "" {
		return nil
	}
	connection, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: socket, Net: "unixgram"})
	if err != nil {
		return fmt.Errorf("notify systemd: %w", err)
	}
	_, writeErr := connection.Write([]byte("READY=1"))
	closeErr := connection.Close()
	if writeErr != nil {
		return fmt.Errorf("notify systemd: %w", writeErr)
	}
	return closeErr
}
