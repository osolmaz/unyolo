package setup

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseAndConfigureClient(t *testing.T) {
	home := t.TempDir()
	secretFile := filepath.Join(t.TempDir(), "secrets")
	secret := strings.Repeat("s", 32)
	if err := os.WriteFile(secretFile, []byte("bob = "+secret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	opts, help, err := ParseClient(&bytes.Buffer{}, []string{
		"--client", "bob", "--endpoint", "unix:///run/brokerkit/test/agent.sock", "--secret-file", secretFile, "--home-dir", home,
	}, ClientDefaults{BrokerName: "test-broker", EnvPrefix: "TEST_BROKER", ClientName: "agent"})
	if err != nil || help {
		t.Fatalf("ParseClient() opts=%+v help=%v err=%v", opts, help, err)
	}
	var output bytes.Buffer
	path, err := ConfigureClient(&output, opts)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path) // #nosec G304 -- test reads its private fixture.
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "TEST_BROKER_AGENT_ENDPOINT='unix:///run/brokerkit/test/agent.sock'") ||
		!strings.Contains(string(data), "TEST_BROKER_SHARED_SECRET='"+secret+"'") ||
		strings.Contains(string(data), "TEST_BROKER_ENDPOINT=") {
		t.Fatalf("client config = %s", data)
	}
	if strings.Contains(output.String(), secret) || !strings.Contains(output.String(), "test-broker client config written") {
		t.Fatalf("setup output = %q", output.String())
	}
}

func TestParseClientHelpAndValidation(t *testing.T) {
	var helpOutput bytes.Buffer
	_, help, err := ParseClient(&helpOutput, []string{"--help"}, ClientDefaults{BrokerName: "test-broker", EnvPrefix: "TEST", ClientName: "bob"})
	if err != nil || !help || !strings.Contains(helpOutput.String(), "-secret-file") {
		t.Fatalf("help=%v err=%v output=%q", help, err, helpOutput.String())
	}
	invalid := [][]string{
		{"extra"},
		{"--endpoint", "unix:///run/brokerkit/test/agent.sock", "--secret-file", "/tmp/s", "--home-dir", "/tmp", "--client", ""},
		{"--client", "bob", "--secret-file", "/tmp/s", "--home-dir", "/tmp"},
		{"--client", "bob", "--endpoint", "activation://agent", "--secret-file", "/tmp/s", "--home-dir", "/tmp"},
		{"--client", "bob", "--endpoint", "unix:///run/brokerkit/test/agent.sock", "--home-dir", "/tmp"},
	}
	for _, args := range invalid {
		if _, _, err := ParseClient(&bytes.Buffer{}, args, ClientDefaults{BrokerName: "test-broker", EnvPrefix: "TEST", ClientName: "bob"}); err == nil {
			t.Fatalf("ParseClient(%v) error = nil", args)
		}
	}
}

func TestConfigureClientRejectsWeakSecret(t *testing.T) {
	secretFile := filepath.Join(t.TempDir(), "secrets")
	if err := os.WriteFile(secretFile, []byte("bob = short\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := ConfigureClient(&bytes.Buffer{}, ClientOptions{
		BrokerName: "test-broker", EnvPrefix: "TEST", ClientName: "bob",
		Endpoint: "unix:///run/brokerkit/test/agent.sock", SecretFile: secretFile, HomeDir: t.TempDir(),
	})
	if err == nil {
		t.Fatal("ConfigureClient(weak secret) error = nil")
	}
}

func TestResolveSecretSources(t *testing.T) {
	generated, err := ResolveSecret(SecretInput{}, strings.NewReader(""))
	if err != nil || len(generated) != 64 {
		t.Fatalf("GenerateSecret() len=%d err=%v", len(generated), err)
	}
	assertFileAndStdinSecrets(t)
	assertInvalidSecretSources(t)
}

func assertFileAndStdinSecrets(t *testing.T) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(path, []byte(strings.Repeat("f", 32)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	fromFile, err := ResolveSecret(SecretInput{File: path}, strings.NewReader(""))
	if err != nil || len(fromFile) != 32 {
		t.Fatalf("ResolveSecret(file) len=%d err=%v", len(fromFile), err)
	}
	fromStdin, err := ResolveSecret(SecretInput{Stdin: true}, strings.NewReader(strings.Repeat("i", 32)+"\n"))
	if err != nil || len(fromStdin) != 32 {
		t.Fatalf("ResolveSecret(stdin) len=%d err=%v", len(fromStdin), err)
	}
}

func assertInvalidSecretSources(t *testing.T) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(path, []byte(strings.Repeat("f", 32)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ResolveSecret(SecretInput{File: path, Stdin: true}, strings.NewReader("")); err == nil {
		t.Fatal("ResolveSecret(conflicting) error = nil")
	}
	if _, err := ResolveSecret(SecretInput{Stdin: true}, strings.NewReader("short")); err == nil {
		t.Fatal("ResolveSecret(short) error = nil")
	}
	if _, err := ResolveSecret(SecretInput{Stdin: true}, strings.NewReader(strings.Repeat("x", maxSecretInputBytes+1))); err == nil {
		t.Fatal("ResolveSecret(oversized) error = nil")
	}
	largeFile := filepath.Join(t.TempDir(), "large-secret")
	if err := os.WriteFile(largeFile, []byte(strings.Repeat("x", maxSecretInputBytes+1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ResolveSecret(SecretInput{File: largeFile}, strings.NewReader("")); err == nil {
		t.Fatal("ResolveSecret(oversized file) error = nil")
	}
	if _, err := ResolveSecret(SecretInput{Stdin: true}, strings.NewReader(strings.Repeat("x", 32)+"\nsecond")); err == nil {
		t.Fatal("ResolveSecret(multiline) error = nil")
	}
	if _, err := ResolveSecret(SecretInput{File: filepath.Join(t.TempDir(), "missing")}, strings.NewReader("")); err == nil {
		t.Fatal("ResolveSecret(missing) error = nil")
	}
}

func TestSystemdOptions(t *testing.T) {
	opts := DefaultSystemdOptions(SystemdDefaults{
		BrokerName: "test-broker", User: "test-broker", Group: "test-broker", ClientName: "agent-a", Endpoint: "activation://agent",
	})
	opts.AgentUser, opts.OperatorUser = "agent-user", "operator-user"
	opts.BinaryPath = "/usr/local/bin/test-broker"
	if err := opts.Validate(); err != nil {
		t.Fatal(err)
	}
	if opts.Endpoint != "activation://agent" {
		t.Fatalf("Endpoint = %q", opts.Endpoint)
	}
	for _, client := range []string{"ci@host", "123"} {
		valid := opts
		valid.ClientName = client
		if err := valid.Validate(); err != nil {
			t.Fatalf("Validate(client=%q): %v", client, err)
		}
	}
	for _, mutate := range []func(*SystemdOptions){
		func(value *SystemdOptions) { value.User = "bad=name" },
		func(value *SystemdOptions) { value.ClientName = "bad=name" },
		func(value *SystemdOptions) { value.ConfigDir = "relative" },
		func(value *SystemdOptions) { value.Endpoint = "tcp://0.0.0.0:1" },
		func(value *SystemdOptions) { value.Endpoint = "fd://3" },
		func(value *SystemdOptions) { value.OperatorAccessGroup = value.AgentAccessGroup },
	} {
		invalid := opts
		mutate(&invalid)
		if err := invalid.Validate(); err == nil {
			t.Fatalf("Validate(%+v) error = nil", invalid)
		}
	}
}

func TestFinalizeSystemdRejectsInvalidBinary(t *testing.T) {
	opts := DefaultSystemdOptions(SystemdDefaults{BrokerName: "test", User: "test", Group: "test", ClientName: "agent-a", Endpoint: "activation://agent"})
	opts.AgentUser, opts.OperatorUser = "agent-user", "operator-user"
	for _, path := range []string{"relative", filepath.Join(t.TempDir(), "missing"), t.TempDir()} {
		opts.BinaryPath = path
		if _, err := FinalizeSystemd(opts); err == nil {
			t.Fatalf("FinalizeSystemd(%q) error = nil", path)
		}
	}
	nonExecutable := filepath.Join(t.TempDir(), "broker")
	if err := os.WriteFile(nonExecutable, []byte("binary"), 0o600); err != nil {
		t.Fatal(err)
	}
	opts.BinaryPath = nonExecutable
	if _, err := FinalizeSystemd(opts); err == nil {
		t.Fatal("FinalizeSystemd(non-executable) error = nil")
	}
}

func TestValidateTrustedExecutable(t *testing.T) {
	resolved, err := filepath.EvalSymlinks("/bin/sh")
	if err != nil {
		t.Fatal(err)
	}
	if err := validateTrustedExecutable(resolved); err != nil {
		t.Fatalf("validateTrustedExecutable(system binary): %v", err)
	}
	opts := DefaultSystemdOptions(SystemdDefaults{
		BrokerName: "test", User: "test", Group: "test", ClientName: "agent-a", Endpoint: "activation://agent",
	})
	opts.AgentUser, opts.OperatorUser = "agent-user", "operator-user"
	opts.BinaryPath = resolved
	if _, err := FinalizeSystemd(opts); err != nil {
		t.Fatalf("FinalizeSystemd(system binary): %v", err)
	}
	untrusted := filepath.Join(t.TempDir(), "broker")
	if err := os.WriteFile(untrusted, []byte("binary"), 0o755); err != nil { // #nosec G306 -- executable fixture requires execute bits.
		t.Fatal(err)
	}
	if err := validateTrustedExecutable(untrusted); err == nil {
		t.Fatal("validateTrustedExecutable(user-owned binary) error = nil")
	}
}

func TestRequiresTrustedExecutable(t *testing.T) {
	if got := requiresTrustedExecutable(SystemdOptions{}); got != (os.Geteuid() == 0) {
		t.Fatalf("requiresTrustedExecutable() = %t for euid %d", got, os.Geteuid())
	}
}
