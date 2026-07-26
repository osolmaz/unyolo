package clientconfig

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSecretFiles(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secrets")
	if err := os.WriteFile(path, []byte("agent = "+strings.Repeat("s", 32)+"\nother = "+strings.Repeat("o", 32)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	secret, err := SecretFromFile(path, "agent")
	if err != nil || secret != strings.Repeat("s", 32) {
		t.Fatalf("SecretFromFile() = %q, %v", secret, err)
	}
	secrets, err := SecretsFromFile(path)
	if err != nil || len(secrets) != 2 {
		t.Fatalf("SecretsFromFile() = %#v, %v", secrets, err)
	}
	if _, err := SecretFromFile(filepath.Join(t.TempDir(), "missing"), "agent"); err == nil {
		t.Fatal("missing secret file was accepted")
	}
}

func TestRenderClientJSON(t *testing.T) {
	body, err := Render(Config{
		BrokerName: "gh-broker", EnvPrefix: "GH_BROKER", ClientID: "bob",
		Endpoint: "unix:///run/brokerkit/github/agent.sock", Secret: "secret-with-'quote'",
	})
	if err != nil {
		t.Fatalf("Render() error = %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatalf("Render() invalid JSON: %v", err)
	}
	if decoded["api_version"] != APIVersion || decoded["client_id"] != "bob" || decoded["shared_secret"] != "secret-with-'quote'" {
		t.Fatalf("Render() = %s", body)
	}
	if strings.Contains(string(body), "export ") {
		t.Fatalf("Render() returned shell content: %s", body)
	}
}

func TestWriteClientEnv(t *testing.T) {
	home := t.TempDir()
	path, err := Write(Config{
		BrokerName: "hf-broker",
		EnvPrefix:  "HF_BROKER",
		ClientID:   "agent-a",
		Endpoint:   "unix:///run/brokerkit/huggingface/agent.sock",
		Secret:     "client-secret",
		HomeDir:    home,
	})
	if err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	wantPath := filepath.Join(home, ".config", "hf-broker", "client.json")
	if path != wantPath {
		t.Fatalf("Write() path = %q, want %q", path, wantPath)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat client env: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("client env mode = %o, want 0600", info.Mode().Perm())
	}
	data, err := os.ReadFile(path) // #nosec G304 -- path is returned by Write in a test temp directory.
	if err != nil {
		t.Fatalf("read client env: %v", err)
	}
	text := string(data)
	if !strings.Contains(text, `"agent_endpoint": "unix:///run/brokerkit/huggingface/agent.sock"`) ||
		!strings.Contains(text, `"shared_secret": "client-secret"`) {
		t.Fatalf("client JSON is incomplete: %q", text)
	}
}

func TestWriteForHomeOwnerWritesClientEnv(t *testing.T) {
	home := t.TempDir()
	path, err := WriteForHomeOwner(Config{
		BrokerName: "gh-broker",
		EnvPrefix:  "GH_BROKER",
		ClientID:   "agent-a",
		Endpoint:   "unix:///run/brokerkit/github/agent.sock",
		Secret:     "client-secret",
		HomeDir:    home,
	})
	if err != nil {
		t.Fatalf("WriteForHomeOwner() error = %v", err)
	}
	if path != filepath.Join(home, ".config", "gh-broker", "client.json") {
		t.Fatalf("WriteForHomeOwner() path = %q", path)
	}
}

func TestWriteForHomeOwnerRejectsSymlinkedConfigPaths(t *testing.T) {
	for _, brokerLink := range []bool{false, true} {
		home := t.TempDir()
		outside := t.TempDir()
		if brokerLink {
			if err := os.Mkdir(filepath.Join(home, ".config"), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(outside, filepath.Join(home, ".config", "gh-broker")); err != nil {
				t.Fatal(err)
			}
		} else if err := os.Symlink(outside, filepath.Join(home, ".config")); err != nil {
			t.Fatal(err)
		}
		_, err := WriteForHomeOwner(Config{
			BrokerName: "gh-broker", EnvPrefix: "GH_BROKER", ClientID: "agent-a", Endpoint: "unix:///run/brokerkit/github/agent.sock",
			Secret: "client-secret", HomeDir: home,
		})
		if err == nil {
			t.Fatal("WriteForHomeOwner(symlink) error = nil")
		}
		if _, statErr := os.Stat(filepath.Join(outside, "client.json")); !os.IsNotExist(statErr) {
			t.Fatalf("outside client config stat error = %v", statErr)
		}
	}
}

func TestWriteForHomeOwnerRejectsSymlinkedHome(t *testing.T) {
	parent := t.TempDir()
	realHome := t.TempDir()
	linkedHome := filepath.Join(parent, "home")
	if err := os.Symlink(realHome, linkedHome); err != nil {
		t.Fatal(err)
	}
	_, err := WriteForHomeOwner(Config{
		BrokerName: "gh-broker", EnvPrefix: "GH_BROKER", ClientID: "agent-a", Endpoint: "unix:///run/brokerkit/github/agent.sock",
		Secret: "client-secret", HomeDir: linkedHome,
	})
	if err == nil {
		t.Fatal("WriteForHomeOwner(symlinked home) error = nil")
	}
}

func TestWriteForHomeOwnerReplacesClientFileSymlinkInsideHome(t *testing.T) {
	home := t.TempDir()
	outside := filepath.Join(home, "outside")
	if err := os.WriteFile(outside, []byte("unchanged"), 0o600); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(home, ".config", "gh-broker")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "client.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := WriteForHomeOwner(Config{
		BrokerName: "gh-broker", EnvPrefix: "GH_BROKER", ClientID: "agent-a", Endpoint: "unix:///run/brokerkit/github/agent.sock",
		Secret: "client-secret", HomeDir: home,
	}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(outside) // #nosec G304 -- test reads its private fixture path.
	if err != nil || string(data) != "unchanged" {
		t.Fatalf("outside file = %q, err=%v", data, err)
	}
}

func TestSecretFromData(t *testing.T) {
	secret, err := SecretFromData([]byte(`
# comment
alice = first-secret
bob = second-secret
`), "bob")
	if err != nil {
		t.Fatalf("SecretFromData() error = %v", err)
	}
	if secret != "second-secret" {
		t.Fatalf("SecretFromData() = %q, want second-secret", secret)
	}
}

func TestSecretsFromData(t *testing.T) {
	secrets, err := SecretsFromData([]byte(`
# comment
alice = first-secret
bob = second-secret
`))
	if err != nil {
		t.Fatalf("SecretsFromData() error = %v", err)
	}
	if secrets["alice"] != "first-secret" || secrets["bob"] != "second-secret" || len(secrets) != 2 {
		t.Fatalf("SecretsFromData() = %#v, want alice and bob", secrets)
	}
}

func TestSecretsFromDataValidation(t *testing.T) {
	cases := map[string]string{
		"bad line":         "bob secret\n",
		"empty secret":     "bob = \n",
		"duplicate client": "bob = first\nbob = second\n",
		"empty file":       "# comment only\n\n",
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := SecretsFromData([]byte(data)); err == nil {
				t.Fatal("SecretsFromData() error = nil, want validation error")
			}
		})
	}
}

func TestSecretFromDataValidation(t *testing.T) {
	cases := map[string]struct {
		data   string
		client string
	}{
		"missing client name": {data: "bob = secret\n"},
		"bad line":            {data: "bob secret\n", client: "bob"},
		"empty secret":        {data: "bob = \n", client: "bob"},
		"duplicate client":    {data: "bob = first\nbob = second\n", client: "bob"},
		"not found":           {data: "alice = secret\n", client: "bob"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := SecretFromData([]byte(tc.data), tc.client); err == nil {
				t.Fatal("SecretFromData() error = nil, want validation error")
			}
		})
	}
}

func TestSecretsFromFileRejectsOversizedInput(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secrets")
	if err := os.WriteFile(path, []byte(strings.Repeat("x", maxClientSecretsBytes+1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := SecretsFromFile(path); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("SecretsFromFile(oversized) error = %v", err)
	}
}

func TestValidation(t *testing.T) {
	cases := map[string]Config{
		"bad broker":      {BrokerName: "../bad", EnvPrefix: "GH_BROKER", Endpoint: "unix:///run/brokerkit/github/agent.sock", Secret: "s"},
		"bad prefix":      {BrokerName: "gh-broker", EnvPrefix: "gh-broker", Endpoint: "unix:///run/brokerkit/github/agent.sock", Secret: "s"},
		"bad endpoint":    {BrokerName: "gh-broker", EnvPrefix: "GH_BROKER", Endpoint: "http://127.0.0.1", Secret: "s"},
		"server endpoint": {BrokerName: "gh-broker", EnvPrefix: "GH_BROKER", Endpoint: "activation://agent", Secret: "s"},
		"no secret":       {BrokerName: "gh-broker", EnvPrefix: "GH_BROKER", Endpoint: "unix:///run/brokerkit/github/agent.sock"},
	}
	for name, cfg := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Render(cfg); err == nil {
				t.Fatal("Render() error = nil, want validation error")
			}
		})
	}
}

func TestValidateClientName(t *testing.T) {
	for _, value := range []string{"bob", "ci@host", "123"} {
		if err := ValidateClientName(value); err != nil {
			t.Fatalf("ValidateClientName(%q): %v", value, err)
		}
	}
	for _, value := range []string{"", "#comment", "a=b", "a\nb"} {
		if err := ValidateClientName(value); err == nil {
			t.Fatalf("ValidateClientName(%q) error = nil", value)
		}
	}
}

func TestPathValidation(t *testing.T) {
	if _, err := Path("", "gh-broker"); err == nil {
		t.Fatal("Path(empty home) error = nil")
	}
	if _, err := Path("/tmp", "GH-broker"); err == nil {
		t.Fatal("Path(bad broker) error = nil")
	}
}
