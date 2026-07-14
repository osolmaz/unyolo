//go:build linux

package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	bkservice "github.com/osolmaz/brokerkit/service"
	bksetup "github.com/osolmaz/brokerkit/setup"
)

func TestSetupSystemdDryRunBuildsSeparatedUnits(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	catalogPath := filepath.Join(directory, "catalog.json")
	policyPath := filepath.Join(directory, "policy.json")
	catalogDocument := `{"version":1,"commands":[{"id":"true","executable":"/usr/bin/true","arguments":[],"target_users":["root"],"working_directory":"/","timeout_seconds":5,"max_output_bytes":100}]}`
	policyDocument := `{"rules":[{"id":"request-true","effect":"request","clients":["bob"],"operations":["exec.command"],"targets":[{"kind":"user","name":"root"}],"attrs":{"command_id":["true"]},"grant_policy":{"mode":"execution","default_minutes":2,"max_minutes":5,"request_ttl_minutes":2,"default_max_uses":1,"max_uses":1}}]}`
	if err := os.WriteFile(catalogPath, []byte(catalogDocument), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(policyPath, []byte(policyDocument), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	err := runSetupSystemd(context.Background(), []string{
		"--dry-run", "--binary", "/usr/bin/true", "--helper-binary", "/usr/bin/true",
		"--client", "agent-a", "--operator", "operator-a", "--agent-user", "agent-user", "--operator-user", "operator-user",
		"--policy-file", policyPath, "--catalog-file", catalogPath,
	}, &stdout, &stderr)
	if err != nil {
		t.Fatal(err)
	}
	output := stdout.String()
	for _, want := range []string{"User=root", "User=sudo-broker", "RuntimeDirectory=sudo-broker", "Requires=sudo-broker-exec.service", "NoNewPrivileges=false"} {
		if !strings.Contains(output, want) {
			t.Fatalf("dry-run missing %q:\n%s", want, output)
		}
	}
	if strings.Contains(output, " = ") {
		t.Fatalf("dry-run leaked a generated secret: %s", output)
	}
}

func TestSetupClientUsesSharedClientFormat(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	secretPath := filepath.Join(t.TempDir(), "secrets")
	secret := strings.Repeat("s", 32)
	if err := os.WriteFile(secretPath, []byte("bob = "+secret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout bytes.Buffer
	if err := runSetup(context.Background(), []string{"client", "--client", "bob", "--endpoint", "unix:///run/sudo-broker/agent.sock", "--secret-file", secretPath, "--home-dir", home}, &stdout, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(home, ".config", "sudo-broker", "client.env"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "SUDO_BROKER_SHARED_SECRET='") || strings.Contains(stdout.String(), secret) {
		t.Fatalf("client config/output invalid: %q / %q", data, stdout.String())
	}
}

func TestSetupRejectsIncompleteSystemdAndUnknownMode(t *testing.T) {
	t.Parallel()
	if err := runSetup(context.Background(), []string{"unknown"}, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
		t.Fatal("unknown setup mode was accepted")
	}
	if err := runSetupSystemd(context.Background(), []string{"--dry-run", "--binary", "/usr/bin/true", "--helper-binary", "/usr/bin/true"}, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
		t.Fatal("incomplete systemd setup was accepted")
	}
}

func TestSetupPathAndOptionHelpers(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	frontend := filepath.Join(directory, "sudo-broker")
	helper := filepath.Join(directory, "sudo-broker-exec")
	if err := os.WriteFile(frontend, []byte("binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(helper, []byte("helper"), 0o755); err != nil {
		t.Fatal(err)
	}
	if got := defaultHelperBinary(frontend); got != helper {
		t.Fatalf("default helper = %q", got)
	}
	opts := sudoSystemdOptions{SystemdOptions: bksetup.DefaultSystemdOptions(bksetup.SystemdDefaults{
		BrokerName: "sudo-broker", User: "sudo-broker", Group: "sudo-broker", ClientName: "agent-a", Endpoint: "unix:///run/sudo-broker/agent.sock",
	}), HelperBinary: helper, HelperStateDir: "/var/lib/sudo/helper", HelperSocket: "/run/sudo/helper.sock",
		PolicyFile: "/policy", CatalogFile: "/catalog", SharedSecret: strings.Repeat("s", 32), OperatorID: "operator-a",
		OperatorSecret: strings.Repeat("o", 32), OperatorEndpoint: "unix:///run/sudo-broker/operator.sock"}
	opts.AgentUser, opts.OperatorUser = "agent-user", "operator-user"
	opts.DryRun = true
	if err := validateSudoSystemdOptions(opts); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*sudoSystemdOptions){
		func(value *sudoSystemdOptions) { value.HelperSocket = "relative" },
		func(value *sudoSystemdOptions) { value.HelperStateDir = value.StateDir },
		func(value *sudoSystemdOptions) { value.OperatorEndpoint = value.Endpoint },
		func(value *sudoSystemdOptions) { value.OperatorID = "bad=name" },
		func(value *sudoSystemdOptions) { value.OperatorSecret = value.SharedSecret },
		func(value *sudoSystemdOptions) { value.TelegramBotTokenFile = "/token" },
	} {
		changed := opts
		mutate(&changed)
		if err := validateSudoSystemdOptions(changed); err == nil {
			t.Fatalf("invalid options accepted: %+v", changed)
		}
	}
}

func TestSetupFileAndTelegramBranches(t *testing.T) {
	directory := t.TempDir()
	empty := filepath.Join(directory, "empty")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readSetupFile(empty); err == nil {
		t.Fatal("empty setup file was accepted")
	}
	if _, err := readSetupFile(filepath.Join(directory, "missing")); err == nil {
		t.Fatal("missing setup file was accepted")
	}
	frontend := filepath.Join(directory, "frontend")
	if err := os.WriteFile(frontend, []byte("binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	if got := defaultHelperBinary(frontend); got != "/usr/local/libexec/sudo-broker-exec" {
		t.Fatalf("missing adjacent helper fallback = %q", got)
	}
	catalogPath := filepath.Join(directory, "catalog.json")
	policyPath := filepath.Join(directory, "policy.json")
	tokenPath := filepath.Join(directory, "telegram-token")
	_ = os.WriteFile(catalogPath, []byte(`{"version":1,"commands":[{"id":"true","executable":"/usr/bin/true","arguments":[],"target_users":["root"],"working_directory":"/","timeout_seconds":5,"max_output_bytes":100}]}`), 0o600)
	_ = os.WriteFile(policyPath, []byte(`{"rules":[{"id":"request","effect":"request","clients":["bob"],"operations":["exec.command"],"targets":[{"kind":"user","name":"root"}],"attrs":{"command_id":["true"]},"grant_policy":{"mode":"execution","default_minutes":1,"max_minutes":1,"request_ttl_minutes":1,"default_max_uses":1,"max_uses":1}}]}`), 0o600)
	_ = os.WriteFile(tokenPath, []byte("token"), 0o600)
	var output bytes.Buffer
	if err := runSetupSystemd(context.Background(), []string{"--dry-run", "--binary", "/usr/bin/true", "--helper-binary", "/usr/bin/true",
		"--client", "agent-a", "--operator", "operator-a", "--agent-user", "agent-user", "--operator-user", "operator-user",
		"--catalog-file", catalogPath, "--policy-file", policyPath, "--telegram-bot-token-file", tokenPath, "--telegram-chat-id", "1"}, &output, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "--telegram-token-file") {
		t.Fatalf("Telegram dry-run = %s", output.String())
	}
}

func TestFrontendSecretsRemainRootOwned(t *testing.T) {
	t.Parallel()
	file := frontendSecretFile("secrets", []byte("secret"))
	if file.Owner != bkservice.ManagedFileOwnerRoot || file.Mode != 0o640 {
		t.Fatalf("frontend secret ownership = owner %q mode %04o", file.Owner, file.Mode)
	}
}

func TestSharedStateDirectoryRequiresOneDeepCommonParent(t *testing.T) {
	t.Parallel()
	if got := sharedStateDirectory("/var/lib/sudo-broker/frontend", "/var/lib/sudo-broker/helper"); got != "/var/lib/sudo-broker" {
		t.Fatalf("sharedStateDirectory() = %q", got)
	}
	if got := sharedStateDirectory("/var/lib/frontend", "/var/lib/helper"); got != "" {
		t.Fatalf("sharedStateDirectory(shallow) = %q", got)
	}
	if got := sharedStateDirectory("/srv/a/frontend", "/srv/b/helper"); got != "" {
		t.Fatalf("sharedStateDirectory(different) = %q", got)
	}
}
