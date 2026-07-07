package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/osolmaz/hf-broker/internal/audit"
	"github.com/osolmaz/hf-broker/internal/config"
	"github.com/osolmaz/hf-broker/internal/httpapi"
	"github.com/osolmaz/hf-broker/internal/policy"
)

var version = "dev"

func main() {
	os.Exit(exitCodeForRun(run(), os.Stderr))
}

func exitCodeForRun(err error, stderr io.Writer) int {
	if err == nil {
		return 0
	}
	var exitErr exitError
	if errors.As(err, &exitErr) {
		if exitErr.message != "" {
			_, _ = fmt.Fprintln(stderr, exitErr.message)
		}
		return exitErr.code
	}
	_, _ = fmt.Fprintln(stderr, err)
	return 1
}

func run() error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	return runWithArgs(ctx, os.Getenv, os.Stdout, os.Stderr, os.Args[1:])
}

func runWithContext(ctx context.Context, getenv func(string) string, stdout, stderr io.Writer) error {
	return runServer(ctx, getenv, stdout, stderr)
}

func runWithArgs(ctx context.Context, getenv func(string) string, stdout, stderr io.Writer, args []string) error {
	if len(args) == 0 {
		return runServer(ctx, getenv, stdout, stderr)
	}
	switch args[0] {
	case "--version", "version":
		_, err := fmt.Fprintln(stdout, version)
		return err
	case "doctor":
		return runDoctor(ctx, stdout, stderr, args[1:])
	case "setup":
		return runSetup(ctx, stdout, stderr, args[1:])
	case "__doctor-isolation-probe":
		return runDoctorIsolationProbe(stdout, stderr, args[1:])
	default:
		return exitError{code: 64, message: "usage: hf-broker [--version|version|doctor|setup]"}
	}
}

func runServer(ctx context.Context, getenv func(string) string, stdout, stderr io.Writer) error {
	cfg, err := config.Load(getenv)
	if err != nil {
		return err
	}
	pol, err := policy.LoadFile(cfg.ScopeFile)
	if err != nil {
		return err
	}
	handler, err := httpapi.New(httpapi.Options{
		Config:  cfg,
		Scope:   pol,
		Audit:   audit.New(stdout),
		Context: ctx,
	})
	if err != nil {
		return err
	}
	server := &http.Server{
		Addr:              net.JoinHostPort(cfg.BindAddr, strconv.Itoa(cfg.Port)),
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
	}
	return serveWithContext(ctx, server, stderr)
}

func serveWithContext(ctx context.Context, server *http.Server, stderr io.Writer) error {
	errs := make(chan error, 1)
	go func() {
		errs <- server.ListenAndServe()
	}()
	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			return err
		}
		_, _ = fmt.Fprintln(stderr, "hf-broker stopped")
		return nil
	case err := <-errs:
		if err == http.ErrServerClosed {
			return nil
		}
		return err
	}
}

type exitError struct {
	code    int
	message string
}

func (e exitError) Error() string {
	return e.message
}
