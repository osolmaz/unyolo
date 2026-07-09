package main

import (
	"bytes"
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/osolmaz/gh-broker/internal/config"
)

func TestRunWithArgsVersion(t *testing.T) {
	oldVersion := version
	version = "v1.2.3-test"
	t.Cleanup(func() { version = oldVersion })
	var stdout bytes.Buffer
	if err := runWithArgs(t.Context(), []string{"--version"}, &stdout, ioDiscard{}); err != nil {
		t.Fatalf("runWithArgs(version) error = %v", err)
	}
	if strings.TrimSpace(stdout.String()) != "v1.2.3-test" {
		t.Fatalf("version output = %q", stdout.String())
	}
}

func TestRunSetupClientWritesClientEnv(t *testing.T) {
	dir := t.TempDir()
	secretFile := filepath.Join(dir, "secrets")
	secret := strings.Repeat("s", 32)
	if err := os.WriteFile(secretFile, []byte("bob = "+secret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout bytes.Buffer
	err := runWithArgs(t.Context(), []string{
		"setup", "client",
		"--client", "bob",
		"--url", "http://127.0.0.1:8081",
		"--secret-file", secretFile,
		"--home-dir", dir,
	}, &stdout, ioDiscard{})
	if err != nil {
		t.Fatalf("runWithArgs(setup client) error = %v", err)
	}
	path := filepath.Join(dir, ".config", "gh-broker", "client.env")
	data, err := os.ReadFile(path) // #nosec G304 -- path is in a test temp directory.
	if err != nil {
		t.Fatalf("read client env: %v", err)
	}
	text := string(data)
	if !strings.Contains(text, "GH_BROKER_URL='http://127.0.0.1:8081'") {
		t.Fatalf("client env missing URL: %q", text)
	}
	if !strings.Contains(text, "GH_BROKER_SHARED_SECRET='"+secret+"'") {
		t.Fatalf("client env missing secret: %q", text)
	}
	if strings.Contains(stdout.String(), secret) {
		t.Fatalf("setup client stdout leaked secret: %q", stdout.String())
	}
}

func TestSetupClientParsingAndValidation(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	opts, err := parseSetupClient(ioDiscard{}, []string{
		"--client", "bob",
		"--url", "http://127.0.0.1:8081",
		"--secret-file", filepath.Join(t.TempDir(), "secrets"),
	})
	if err != nil {
		t.Fatalf("parseSetupClient() error = %v", err)
	}
	if opts.HomeDir != home {
		t.Fatalf("HomeDir = %q, want HOME", opts.HomeDir)
	}
	explicit := setupClientOptions{HomeDir: "/tmp/custom"}
	if err := defaultSetupClientHome(&explicit); err != nil {
		t.Fatalf("defaultSetupClientHome(explicit) error = %v", err)
	}
	if explicit.HomeDir != "/tmp/custom" {
		t.Fatalf("explicit HomeDir = %q, want unchanged", explicit.HomeDir)
	}
	if err := validateSetupClientOptions(setupClientOptions{}); err == nil {
		t.Fatal("validateSetupClientOptions(empty) error = nil, want validation error")
	}
	if err := runSetup(ioDiscard{}, ioDiscard{}, []string{"bad"}); err == nil {
		t.Fatal("runSetup(bad) error = nil, want usage error")
	}
}

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
	server, err := buildServer(t.Context(), configForBuildTest(t))
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

type ioDiscard struct{}

func (ioDiscard) Write(p []byte) (int, error) {
	return len(p), nil
}
