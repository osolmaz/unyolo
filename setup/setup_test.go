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
		"--client", "bob", "--url", "http://127.0.0.1:8080", "--secret-file", secretFile, "--home-dir", home,
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
	if !strings.Contains(string(data), "TEST_BROKER_SHARED_SECRET='"+secret+"'") {
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
		{"--url", "http://127.0.0.1", "--secret-file", "/tmp/s", "--home-dir", "/tmp", "--client", ""},
		{"--client", "bob", "--secret-file", "/tmp/s", "--home-dir", "/tmp"},
		{"--client", "bob", "--url", "https://user:credential@broker.example", "--secret-file", "/tmp/s", "--home-dir", "/tmp"},
		{"--client", "bob", "--url", "http://127.0.0.1", "--home-dir", "/tmp"},
	}
	for _, args := range invalid {
		if _, _, err := ParseClient(&bytes.Buffer{}, args, ClientDefaults{BrokerName: "test-broker", EnvPrefix: "TEST", ClientName: "bob"}); err == nil {
			t.Fatalf("ParseClient(%v) error = nil", args)
		}
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
		BrokerName: "test-broker", User: "test-broker", Group: "test-broker", ClientName: "bob", BindAddr: "127.0.0.1", Port: 8080,
	})
	opts.BinaryPath = "/usr/local/bin/test-broker"
	if err := opts.Validate(); err != nil {
		t.Fatal(err)
	}
	if opts.ListenAddress() != "127.0.0.1:8080" {
		t.Fatalf("ListenAddress() = %q", opts.ListenAddress())
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
		func(value *SystemdOptions) { value.BindAddr = "all" },
		func(value *SystemdOptions) { value.Port = 0 },
	} {
		invalid := opts
		mutate(&invalid)
		if err := invalid.Validate(); err == nil {
			t.Fatalf("Validate(%+v) error = nil", invalid)
		}
	}
}

func TestFinalizeSystemdRejectsInvalidBinary(t *testing.T) {
	opts := DefaultSystemdOptions(SystemdDefaults{BrokerName: "test", User: "test", Group: "test", ClientName: "bob", BindAddr: "127.0.0.1", Port: 1})
	opts.BinaryPath = "relative"
	_, err := FinalizeSystemd(opts)
	if err == nil {
		t.Fatalf("FinalizeSystemd() error = %v", err)
	}
}
