package main

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/osolmaz/brokerkit/brokers/github/internal/config"
	"github.com/osolmaz/brokerkit/transport/endpoint"
	"github.com/osolmaz/brokerkit/transport/http/server"
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

func TestDoctorCommandHelp(t *testing.T) {
	var help bytes.Buffer
	command, err := parseDoctorGitHub(&help, []string{"--help"})
	if err != nil || !command.help || help.Len() == 0 {
		t.Fatalf("parseDoctorGitHub(help) = %+v, %v, output %q", command, err, help.String())
	}
}

func TestDoctorCommandParsing(t *testing.T) {
	command, err := parseDoctorGitHub(ioDiscard{}, []string{
		"--repo", "osolmaz/gh-broker",
		"--agent-user", "alice",
		"--service-user", "broker",
		"--require-protection=false",
		"--json",
		"--env-file", "/tmp/gh-broker-env",
	})
	if err != nil {
		t.Fatalf("parseDoctorGitHub() error = %v", err)
	}
	if command.options.Repo != "osolmaz/gh-broker" || command.options.AgentUser != "alice" || command.options.ServiceUser != "broker" || command.options.RequireProtection || command.envFile != "/tmp/gh-broker-env" || !command.jsonOutput {
		t.Fatalf("parseDoctorGitHub() = %+v", command)
	}
}

func TestDoctorCommandRejectsInvalidFlags(t *testing.T) {
	for _, args := range [][]string{{"--bad"}, {}, {"--repo", "owner/repo", "extra"}} {
		if _, parseErr := parseDoctorGitHub(ioDiscard{}, args); parseErr == nil {
			t.Fatalf("parseDoctorGitHub(%v) error = nil", args)
		}
	}
}

func TestRunDoctorRejectsInvalidInvocation(t *testing.T) {
	if err := runDoctor(t.Context(), ioDiscard{}, ioDiscard{}, nil); err == nil {
		t.Fatal("runDoctor(empty) error = nil")
	}
	if err := runDoctor(t.Context(), ioDiscard{}, ioDiscard{}, []string{"github", "--help"}); err != nil {
		t.Fatalf("runDoctor(help) error = %v", err)
	}
	t.Setenv("GH_BROKER_SHARED_SECRET", "short")
	if err := runDoctor(t.Context(), ioDiscard{}, ioDiscard{}, []string{"github", "--repo", "owner/repo", "--env-file", ""}); err == nil {
		t.Fatal("runDoctor(invalid config) error = nil")
	}
}

func TestLoadGitHubDoctorConfigReadsInstalledEnvironment(t *testing.T) {
	dir := t.TempDir()
	secret := strings.Repeat("s", 32)
	secretsFile := filepath.Join(dir, "secrets")
	tokenFile := filepath.Join(dir, "github-token")
	envFile := filepath.Join(dir, "env")
	if err := os.WriteFile(secretsFile, []byte("bob = "+secret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tokenFile, []byte("github-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	env := "GH_BROKER_CLIENT_ID=bob\n" +
		"GH_BROKER_AGENT_ENDPOINT=unix:///run/gh-broker/agent.sock\n" +
		"GH_BROKER_SECRETS_FILE=" + secretsFile + "\n" +
		"GH_BROKER_GITHUB_TOKEN_FILE=" + tokenFile + "\n" +
		"GH_BROKER_SCOPE_FILE=" + filepath.Join(dir, "scope.json") + "\n" +
		"GH_BROKER_STATE_DIR=" + filepath.Join(dir, "state") + "\n"
	if err := os.WriteFile(envFile, []byte(env), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GH_BROKER_SHARED_SECRET", strings.Repeat("p", 32))
	t.Setenv("GH_BROKER_GITHUB_TOKEN", "process-token")
	cfg, err := loadGitHubDoctorConfig(envFile)
	if err != nil {
		t.Fatalf("loadGitHubDoctorConfig() error = %v", err)
	}
	if cfg.SharedSecret != secret || cfg.GitHubToken != "github-token" || cfg.SecretsFile != secretsFile {
		t.Fatalf("loaded doctor config = %+v", cfg)
	}
}

func TestExitCodeForRun(t *testing.T) {
	var stderr bytes.Buffer
	if code := exitCodeForRun(nil, &stderr); code != 0 {
		t.Fatalf("nil exit code = %d", code)
	}
	if code := exitCodeForRun(exitError{code: 2, message: "unsafe"}, &stderr); code != 2 || !strings.Contains(stderr.String(), "unsafe") {
		t.Fatalf("status exit = %d, stderr = %q", code, stderr.String())
	}
	stderr.Reset()
	if code := exitCodeForRun(errors.New("failed"), &stderr); code != 1 || !strings.Contains(stderr.String(), "failed") {
		t.Fatalf("error exit = %d, stderr = %q", code, stderr.String())
	}
}

func TestRunSetupClientWritesClientEnv(t *testing.T) {
	dir := t.TempDir()
	dir, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatalf("resolve temp home: %v", err)
	}
	secretFile := filepath.Join(dir, "secrets")
	secret := strings.Repeat("s", 32)
	if err := os.WriteFile(secretFile, []byte("bob = "+secret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout bytes.Buffer
	err = runWithArgs(t.Context(), []string{
		"setup", "client",
		"--client", "bob",
		"--endpoint", "unix:///run/gh-broker/agent.sock",
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
	if !strings.Contains(text, "GH_BROKER_AGENT_ENDPOINT='unix:///run/gh-broker/agent.sock'") {
		t.Fatalf("client env missing endpoint: %q", text)
	}
	if strings.Contains(text, "GH_BROKER_ENDPOINT=") {
		t.Fatalf("client env contains legacy endpoint: %q", text)
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
		"--endpoint", "unix:///run/gh-broker/agent.sock",
		"--secret-file", filepath.Join(t.TempDir(), "secrets"),
	})
	if err != nil {
		t.Fatalf("parseSetupClient() error = %v", err)
	}
	if opts.HomeDir != home {
		t.Fatalf("HomeDir = %q, want HOME", opts.HomeDir)
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
	t.Setenv("GH_BROKER_DEVELOPMENT", "true")
	t.Setenv("GH_BROKER_AGENT_ENDPOINT", "tcp://127.0.0.1:0")
	t.Setenv("GH_BROKER_CLIENT_ID", "bob")
	t.Setenv("GH_BROKER_SHARED_SECRET", strings.Repeat("a", 32))
	t.Setenv("GH_BROKER_GITHUB_TOKEN", "github-token")
	t.Setenv("GH_BROKER_GITHUB_TOKEN_FILE", "/protected/github-token")
	t.Setenv("GH_BROKER_SCOPE_FILE", writeScopeFile(t))
	t.Setenv("GH_BROKER_STATE_DIR", t.TempDir())
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := run(ctx); err != nil {
		t.Fatalf("run() error = %v", err)
	}
}

func TestRunReturnsScopeFileError(t *testing.T) {
	t.Setenv("GH_BROKER_DEVELOPMENT", "true")
	t.Setenv("GH_BROKER_AGENT_ENDPOINT", "tcp://127.0.0.1:0")
	t.Setenv("GH_BROKER_CLIENT_ID", "bob")
	t.Setenv("GH_BROKER_SHARED_SECRET", strings.Repeat("a", 32))
	t.Setenv("GH_BROKER_GITHUB_TOKEN", "github-token")
	t.Setenv("GH_BROKER_GITHUB_TOKEN_FILE", "/protected/github-token")
	t.Setenv("GH_BROKER_SCOPE_FILE", filepath.Join(t.TempDir(), "missing.json"))
	t.Setenv("GH_BROKER_STATE_DIR", t.TempDir())
	err := run(t.Context())
	if err == nil {
		t.Fatal("run() error = nil, want scope file error")
	}
}

func TestBuildServersUseConfiguredEndpoints(t *testing.T) {
	cfg := configForBuildTest(t)
	servers, err := buildServers(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = serverhttp.Shutdown(servers) })
	if len(servers) != 1 || servers[0].Listener.Addr().Network() != "unix" || servers[0].Server.ReadHeaderTimeout != 5*time.Second {
		t.Fatalf("servers = %+v", servers)
	}
}

func TestBuildServersAddsDedicatedOperatorEndpoint(t *testing.T) {
	cfg := configForBuildTest(t)
	cfg.OperatorID = "operator-a"
	cfg.OperatorSecret = strings.Repeat("o", 32)
	operatorDir := t.TempDir()
	if err := os.Chmod(operatorDir, 0o700); err != nil {
		t.Fatal(err)
	}
	operator, err := endpoint.Parse("unix://"+filepath.Join(operatorDir, "operator.sock"), endpoint.ParseOptions{})
	if err != nil {
		t.Fatal(err)
	}
	cfg.OperatorEndpoint = &operator
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	gitAddress := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	gitEndpoint, err := endpoint.Parse("tcp://"+gitAddress, endpoint.ParseOptions{})
	if err != nil {
		t.Fatal(err)
	}
	cfg.GitEndpoint = &gitEndpoint
	servers, err := buildServers(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = serverhttp.Shutdown(servers) })
	if len(servers) != 3 || servers[1].Listener.Addr().Network() != "unix" || servers[1].Server.WriteTimeout != 0 || servers[1].Server.ReadTimeout != 15*time.Second || servers[2].Listener.Addr().Network() != "tcp" {
		t.Fatalf("servers = %+v", servers)
	}
}

func configForBuildTest(t *testing.T) config.Config {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	agentEndpoint, err := endpoint.Parse("unix://"+filepath.Join(dir, "agent.sock"), endpoint.ParseOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return config.Config{
		Development:         true,
		AgentEndpoint:       agentEndpoint,
		ClientID:            "bob",
		SharedSecret:        strings.Repeat("a", 32),
		GitHubToken:         "github-token",
		GitHubTokenFile:     "/protected/github-token",
		ScopeFile:           writeScopeFile(t),
		StateDir:            t.TempDir(),
		GitHubHTTPTimeout:   time.Second,
		MaxReceivePackBytes: 1,
	}
}

func writeScopeFile(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "scope.json")
	body := []byte(`{"rules":[{"id":"bob-read","effect":"allow","clients":["bob"],"operations":["git.fetch","repo.metadata.read","repo.contents.read","installation.repo.list"],"targets":[{"kind":"repo","owner":"dutifuldev","name":"*"},{"kind":"installation"}]}]}`)
	if err := os.WriteFile(path, body, 0600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	return path
}

type ioDiscard struct{}

func (ioDiscard) Write(p []byte) (int, error) {
	return len(p), nil
}
