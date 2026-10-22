package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/osolmaz/unyolo/deployment/component"
)

var version = "dev"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:], os.Stdout, os.Stderr); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

//nolint:cyclop // The small CLI keeps its closed command dispatch and usage errors together.
func run(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	if len(args) == 1 && (args[0] == "version" || args[0] == "--version") {
		_, err := fmt.Fprintln(stdout, version)
		return err
	}
	if len(args) == 0 {
		return errors.New("usage: unyolo-telegram [--version|version|serve|setup|doctor]")
	}
	switch args[0] {
	case "serve":
		return runServe(ctx, args[1:], stderr)
	case "setup":
		return runSetup(ctx, args[1:], stdout, stderr)
	case "doctor":
		return runDoctor(ctx, args[1:], stdout, stderr)
	case "setup-component-probe":
		if err := component.Probe(ctx, args[1:]); err != nil {
			return err
		}
		_, err := fmt.Fprintln(stdout, "ok")
		return err
	case "setup-component":
		if len(args) != 1 {
			return errors.New("setup-component does not accept arguments")
		}
		return component.Serve(ctx, os.Stdin, stdout, componentConfig())
	case "setup-component-render":
		if len(args) != 1 {
			return errors.New("setup-component-render does not accept arguments")
		}
		return component.ServeRender(os.Stdin, stdout, componentRenderer{})
	default:
		return errors.New("usage: unyolo-telegram [--version|version|serve|setup|doctor]")
	}
}

// componentConfig is the ownership of the Telegram deployment component. The
// deployment engine creates the unyolo-telegram account as a managed
// approver, so the component owns no account or group.
func componentConfig() component.Config {
	return component.Config{
		ComponentID: componentID, ProfileAPI: "unyolo.io/telegram-deployment/v1",
		AllowedPaths: []string{
			componentConfigDir, componentStateDir, "/var/lib/unyolo-telegram/deployment-backups",
			"/etc/systemd/system/unyolo-telegram.service",
		},
		AllowedServices: []string{"unyolo-telegram.service"},
		BackupDirectory: "/var/lib/unyolo-telegram/deployment-backups",
	}
}

func runServe(ctx context.Context, args []string, stderr io.Writer) error {
	if ctx.Err() != nil {
		return nil
	}
	flags := flag.NewFlagSet("unyolo-telegram serve", flag.ContinueOnError)
	flags.SetOutput(stderr)
	configPath := flags.String("config", "/etc/unyolo-telegram/config.json", "absolute ingress config path")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("serve does not accept positional arguments")
	}
	cfg, err := loadIngressConfig(*configPath)
	if err != nil {
		return err
	}
	built, err := buildIngress(ctx, cfg)
	if err != nil {
		return err
	}
	defer func() { _ = built.inbox.Close() }()
	if err := startOwner(ctx, cfg, built); err != nil {
		return err
	}
	return recordOwnerConflict(ownerConflictPath(cfg), serveIngress(ctx, built))
}

// serveIngress runs the card owner and the click poller together. The poller
// stops on a contract mismatch or when another process polls the bot, and then
// the owner stops too.
func serveIngress(ctx context.Context, built ingress) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	owned := make(chan error, 1)
	go func() { owned <- built.owner.Run(ctx) }()
	err := built.client.PollDurableReady(ctx, built.inbox, built.dispatcher.Handle, built.dispatcher.Compatible)
	cancel()
	<-owned
	if errors.Is(err, context.Canceled) {
		return nil
	}
	return err
}
