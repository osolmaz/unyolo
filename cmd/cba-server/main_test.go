package main

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestRunReturnsConfigError(t *testing.T) {
	t.Setenv("CBA_ADMIN_TOKEN", "short")
	err := run(t.Context())
	if err == nil {
		t.Fatal("run() error = nil, want config error")
	}
}

func TestRunStopsWhenContextIsCancelled(t *testing.T) {
	t.Setenv("CBA_PORT", "0")
	t.Setenv("CBA_API_PREFIX", "/v1")
	t.Setenv("CBA_ADMIN_TOKEN", strings.Repeat("a", 32))
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := run(ctx); err != nil {
		t.Fatalf("run() error = %v", err)
	}
}

func TestServeReturnsListenError(t *testing.T) {
	t.Parallel()
	server := &http.Server{
		Addr:              "bad address",
		Handler:           http.NotFoundHandler(),
		ReadHeaderTimeout: time.Second,
	}
	err := serve(t.Context(), server, "bad")
	if err == nil {
		t.Fatal("serve() error = nil, want listen error")
	}
}

func TestShutdownClosesServer(t *testing.T) {
	t.Parallel()
	server := &http.Server{
		Addr:              "127.0.0.1:0",
		Handler:           http.NotFoundHandler(),
		ReadHeaderTimeout: time.Second,
	}
	if err := shutdown(server); err != nil {
		t.Fatalf("shutdown() error = %v", err)
	}
}
