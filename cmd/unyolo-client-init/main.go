// unyolo-client-init runs once inside a Docker agent Compose project. It
// reads the pairing invitation from /run/secrets/unyolo-invitation, claims
// the connection, and writes client configs into a shared volume. The
// container exits with a non-zero code when any step fails so the Compose
// depends_on condition prevents the agent service from starting.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/osolmaz/unyolo/setup/pairingclient"
)

var version = "dev"

const (
	defaultInvitationPath = "/run/secrets/unyolo-invitation"
	defaultHome           = "/etc/unyolo"
	maxInvitationSize     = 4096
)

func main() {
	invitationPath := flag.String("invitation", defaultInvitationPath, "path to the pairing invitation secret file")
	home := flag.String("home", defaultHome, "root directory for the written client configuration")
	timeout := flag.Duration("timeout", 90*time.Second, "how long the claim step may take")
	waitForActive := flag.Bool("wait-for-active", true, "block until the server activates the pending pairing")
	showVersion := flag.Bool("version", false, "print the version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Println(version)
		return
	}
	if err := run(*invitationPath, *home, *timeout, *waitForActive); err != nil {
		fmt.Fprintln(os.Stderr, "unyolo-client-init:", err)
		os.Exit(1)
	}
}

func run(invitationPath, home string, timeout time.Duration, waitForActive bool) error {
	if !filepath.IsAbs(invitationPath) || filepath.Clean(invitationPath) != invitationPath {
		return errors.New("invitation path must be absolute and clean")
	}
	if !filepath.IsAbs(home) || filepath.Clean(home) != home {
		return errors.New("home path must be absolute and clean")
	}
	info, err := os.Stat(invitationPath)
	if err != nil {
		return fmt.Errorf("inspect invitation: %w", err)
	}
	if info.Size() > maxInvitationSize {
		return errors.New("invitation secret is too large")
	}
	data, err := os.ReadFile(invitationPath) // #nosec G304 -- validated invitation path.
	if err != nil {
		return fmt.Errorf("read invitation: %w", err)
	}
	invitation := string(data)
	if invitation == "" {
		return errors.New("invitation secret is empty")
	}
	if err := os.MkdirAll(home, 0o700); err != nil {
		return fmt.Errorf("prepare home: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-signals
		cancel()
	}()
	result, err := pairingclient.Claim(ctx, invitation, home)
	if err != nil {
		return fmt.Errorf("claim invitation: %w", err)
	}
	if !waitForActive {
		return nil
	}
	if err := pairingclient.WaitForActive(ctx, result); err != nil {
		return fmt.Errorf("wait for activation: %w", err)
	}
	if err := pairingclient.VerifyConnections(ctx, result); err != nil {
		return fmt.Errorf("verify connections: %w", err)
	}
	if err := pairingclient.MarkVerified(ctx, result); err != nil {
		return fmt.Errorf("record verification: %w", err)
	}
	return nil
}
