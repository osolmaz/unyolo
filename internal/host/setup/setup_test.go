package setup

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVerifyRootOwnedExecutableRejectsTestBinary(t *testing.T) {
	if err := VerifyRootOwnedExecutable(); err == nil {
		t.Fatal("user-owned test executable was accepted for privileged deployment")
	}
}

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
	if !strings.Contains(string(data), `"agent_endpoint": "unix:///run/brokerkit/test/agent.sock"`) ||
		!strings.Contains(string(data), `"client_id": "bob"`) ||
		!strings.Contains(string(data), `"shared_secret": "`+secret+`"`) {
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

func TestResolveServiceExecutablePreservesManagedCurrentPath(t *testing.T) {
	root := t.TempDir()
	release := filepath.Join(root, "releases", "bundle-one")
	destination := filepath.Join("bin", "test-broker")
	if err := os.MkdirAll(filepath.Join(release, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(release, destination)
	if err := os.WriteFile(binary, []byte("binary"), 0o755); err != nil { // #nosec G306 -- executable fixture.
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join("releases", "bundle-one"), filepath.Join(root, "current")); err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(root, "current", destination)
	for _, input := range []string{want, binary} {
		got, managed, err := resolveServiceExecutable(input, root, destination, false)
		if err != nil || !managed || got != want {
			t.Fatalf("resolveServiceExecutable(%q) = %q, %t, %v", input, got, managed, err)
		}
	}
}

func TestResolveServiceExecutableAllowsManagedBootstrapOnly(t *testing.T) {
	root := t.TempDir()
	destination := filepath.Join("bin", "test-broker")
	managed := filepath.Join(root, "current", destination)
	got, selected, err := resolveServiceExecutable(managed, root, destination, false)
	if err != nil || !selected || got != managed {
		t.Fatalf("managed bootstrap = %q, %t, %v", got, selected, err)
	}
	wrong := filepath.Join(root, "current", "bin", "other")
	if _, _, err := resolveServiceExecutable(wrong, root, destination, false); err == nil {
		t.Fatal("wrong managed destination was accepted")
	}
}

func TestManagedDestinationMatchesOnlyExactCurrentPath(t *testing.T) {
	destination := filepath.Join("bin", "test-broker")
	if got := ManagedDestination(ManagedExecutablePath(destination), destination); got != destination {
		t.Fatalf("ManagedDestination() = %q", got)
	}
	if got := ManagedDestination("/usr/local/bin/test-broker", destination); got != "" {
		t.Fatalf("standalone ManagedDestination() = %q", got)
	}
}

func TestValidateTrustedAncestorWalksToExistingRoot(t *testing.T) {
	missing := filepath.Join(string(filepath.Separator), filepath.Base(t.TempDir()), "nested")
	if err := validateTrustedAncestor(missing); err != nil {
		t.Fatalf("validateTrustedAncestor() error = %v", err)
	}
}

func TestResolveServiceExecutableRejectsEscapedCurrentPointer(t *testing.T) {
	root := t.TempDir()
	if err := os.Symlink("../outside", filepath.Join(root, "current")); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join("bin", "test-broker")
	if _, _, err := resolveServiceExecutable(filepath.Join(root, "current", destination), root, destination, false); err == nil {
		t.Fatal("escaped managed pointer was accepted")
	}
}

func TestResolveServiceExecutableRejectsInvalidInputs(t *testing.T) {
	root := t.TempDir()
	destination := filepath.Join("bin", "test-broker")
	for _, test := range []struct {
		path        string
		destination string
	}{
		{path: "relative", destination: destination},
		{path: "/bin/sh", destination: "../test-broker"},
	} {
		if _, _, err := resolveServiceExecutable(test.path, root, test.destination, false); err == nil {
			t.Fatalf("resolveServiceExecutable(%q, %q) accepted invalid input", test.path, test.destination)
		}
	}
	current := filepath.Join(root, "current")
	if err := os.Mkdir(current, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, _, err := resolveServiceExecutable(filepath.Join(current, destination), root, destination, false); err == nil {
		t.Fatal("directory current pointer was accepted")
	}
}
