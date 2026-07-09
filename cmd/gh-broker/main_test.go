package main

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/osolmaz/gh-broker/internal/config"
)

func TestRunReturnsConfigError(t *testing.T) {
	t.Setenv("GH_BROKER_SHARED_SECRET", "short")
	err := run(t.Context())
	if err == nil {
		t.Fatal("run() error = nil, want config error")
	}
}

func TestRunStopsWhenContextIsCancelled(t *testing.T) {
	t.Setenv("GH_BROKER_BIND_ADDR", "127.0.0.1")
	t.Setenv("GH_BROKER_PORT", "0")
	t.Setenv("GH_BROKER_CLIENT_ID", "bob")
	t.Setenv("GH_BROKER_SHARED_SECRET", strings.Repeat("a", 32))
	t.Setenv("GH_BROKER_GITHUB_TOKEN", "github-token")
	t.Setenv("GH_BROKER_SCOPE_FILE", writeScopeFile(t))
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := run(ctx); err != nil {
		t.Fatalf("run() error = %v", err)
	}
}

func TestRunReturnsScopeFileError(t *testing.T) {
	t.Setenv("GH_BROKER_BIND_ADDR", "127.0.0.1")
	t.Setenv("GH_BROKER_PORT", "0")
	t.Setenv("GH_BROKER_CLIENT_ID", "bob")
	t.Setenv("GH_BROKER_SHARED_SECRET", strings.Repeat("a", 32))
	t.Setenv("GH_BROKER_GITHUB_TOKEN", "github-token")
	t.Setenv("GH_BROKER_SCOPE_FILE", filepath.Join(t.TempDir(), "missing.json"))
	err := run(t.Context())
	if err == nil {
		t.Fatal("run() error = nil, want scope file error")
	}
}

func TestBuildServerUsesConfiguredBindAddress(t *testing.T) {
	t.Parallel()
	server, err := buildServer(configForBuildTest(t))
	if err != nil {
		t.Fatalf("buildServer() error = %v", err)
	}
	if server.Addr != "127.0.0.2:9090" {
		t.Fatalf("Addr = %q, want configured bind address", server.Addr)
	}
}

func TestServeReturnsListenError(t *testing.T) {
	t.Parallel()
	server := &http.Server{
		Addr:              "bad address",
		Handler:           http.NotFoundHandler(),
		ReadHeaderTimeout: time.Second,
	}
	err := serve(t.Context(), server, "127.0.0.1", "bad")
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

func configForBuildTest(t *testing.T) config.Config {
	t.Helper()
	return config.Config{
		BindAddr:            "127.0.0.2",
		Port:                "9090",
		ClientID:            "bob",
		SharedSecret:        strings.Repeat("a", 32),
		GitHubToken:         "github-token",
		ScopeFile:           writeScopeFile(t),
		GitHubHTTPTimeout:   time.Second,
		MaxReceivePackBytes: 1,
		ReadHeaderTimeout:   time.Second,
	}
}

func writeScopeFile(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "scope.json")
	body := []byte(`{"rules":[{"id":"bob-read","effect":"allow","clients":["bob"],"operations":["git.fetch","repo.metadata.read","contents.read","installation.repos.list"],"targets":[{"kind":"repo","owner":"dutifuldev","name":"*"},{"kind":"installation"}]}]}`)
	if err := os.WriteFile(path, body, 0600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	return path
}
