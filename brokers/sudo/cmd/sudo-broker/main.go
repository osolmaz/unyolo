package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/osolmaz/brokerkit/deployment/component"
	"github.com/osolmaz/brokerkit/internal/storage/command"
)

var version = "dev"

func main() { os.Exit(mainCode(os.Args[1:], os.Stdout, os.Stderr)) }

func mainCode(args []string, stdout io.Writer, stderr io.Writer) int {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, args, stdout, stderr); err != nil {
		return reportMainError(err, stderr)
	}
	return 0
}

func reportMainError(err error, stderr io.Writer) int {
	var exitErr exitError
	if errors.As(err, &exitErr) {
		if exitErr.message != "" {
			_, _ = fmt.Fprintln(stderr, "sudo-broker:", exitErr.message)
		}
		return exitErr.code
	}
	_, _ = fmt.Fprintln(stderr, "sudo-broker:", err)
	return 1
}

func run(ctx context.Context, args []string, stdout io.Writer, stderr io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: sudo-broker <serve|run|setup|state|version>")
	}
	return runSubcommand(ctx, args[0], args[1:], stdout, stderr)
}

func runSubcommand(ctx context.Context, name string, args []string, stdout io.Writer, stderr io.Writer) error {
	switch name {
	case "doctor":
		return runDoctor(ctx, args, stdout, stderr)
	case "serve":
		return runServe(ctx, args, stdout, stderr)
	case "run":
		return runCommand(ctx, args, stdout, stderr)
	case "setup":
		return runSetup(ctx, args, stdout, stderr)
	case "state":
		return statecmd.Run(ctx, args, stdout, stderr)
	case "setup-component-probe":
		if err := component.Probe(ctx, args); err != nil {
			return err
		}
		_, err := fmt.Fprintln(stdout, "ok")
		return err
	case "setup-component":
		if len(args) != 0 {
			return errors.New("setup-component does not accept arguments")
		}
		return component.Serve(ctx, os.Stdin, stdout, component.Config{
			ComponentID: "sudo", ProfileAPI: "brokerkit.io/sudo-deployment/v1",
			AllowedPaths:    []string{"/etc/sudo-broker", "/var/lib/sudo-broker", "/etc/systemd/system/sudo-broker.service", "/etc/systemd/system/sudo-broker-exec.service"},
			AllowedServices: []string{"sudo-broker.service", "sudo-broker-exec.service"}, AllowedAccounts: []string{"sudo-broker"},
			AllowedGroups: []string{"sudo-broker", "sudo-broker-agent", "sudo-broker-operator"}, BackupDirectory: "/var/lib/sudo-broker/deployment-backups",
		})
	case "version", "--version":
		_, err := fmt.Fprintln(stdout, version)
		return err
	default:
		return fmt.Errorf("unknown command %q", name)
	}
}

type exitError struct {
	code    int
	message string
}

func (e exitError) Error() string { return e.message }
