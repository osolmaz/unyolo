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
		return errors.New("usage: unyolo-telegram [--version|version|serve|setup]")
	}
	switch args[0] {
	case "serve":
		return runServe(ctx, args[1:], stderr)
	case "setup":
		return runSetup(ctx, args[1:], stdout, stderr)
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
		return component.Serve(ctx, os.Stdin, stdout, component.Config{
			ComponentID: "telegram", ProfileAPI: "unyolo.io/telegram-deployment/v1",
			AllowedPaths:    []string{"/etc/unyolo-telegram", "/var/lib/unyolo-telegram", "/etc/systemd/system/unyolo-telegram.service"},
			AllowedServices: []string{"unyolo-telegram.service"}, AllowedAccounts: []string{"unyolo-telegram"},
			AllowedGroups: []string{"unyolo-telegram"}, BackupDirectory: "/var/lib/unyolo-telegram/deployment-backups",
		})
	default:
		return errors.New("usage: unyolo-telegram [--version|version|serve|setup]")
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
	client, dispatcher, inbox, err := buildIngress(ctx, cfg)
	if err != nil {
		return err
	}
	defer func() { _ = inbox.Close() }()
	err = client.PollDurableReady(ctx, inbox, dispatcher.Handle, dispatcher.Compatible)
	if errors.Is(err, context.Canceled) {
		return nil
	}
	return err
}
