package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
)

var version = "dev"

func main() { os.Exit(mainCode(os.Args[1:], os.Stdout, os.Stderr)) }

func mainCode(args []string, stdout io.Writer, stderr io.Writer) int {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, args, stdout, stderr); err != nil {
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
	return 0
}

func run(ctx context.Context, args []string, stdout io.Writer, stderr io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: sudo-broker <serve|run|setup|version>")
	}
	switch args[0] {
	case "doctor":
		return runDoctor(ctx, args[1:], stdout, stderr)
	case "serve":
		return runServe(ctx, args[1:], stdout, stderr)
	case "run":
		return runCommand(ctx, args[1:], stdout, stderr)
	case "setup":
		return runSetup(ctx, args[1:], stdout, stderr)
	case "version", "--version":
		_, err := fmt.Fprintln(stdout, version)
		return err
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

type exitError struct {
	code    int
	message string
}

func (e exitError) Error() string { return e.message }
