package clientconfig

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRenderClientEnv(t *testing.T) {
	body, err := Render(Config{
		BrokerName: "gh-broker",
		EnvPrefix:  "GH_BROKER_",
		URL:        "http://127.0.0.1:8081",
		Secret:     "secret-with-'quote'",
	})
	if err != nil {
		t.Fatalf("Render() error = %v", err)
	}
	want := "GH_BROKER_URL='http://127.0.0.1:8081'\nGH_BROKER_SHARED_SECRET='secret-with-'\\''quote'\\'''\n"
	if string(body) != want {
		t.Fatalf("Render() = %q, want %q", body, want)
	}
}

func TestWriteClientEnv(t *testing.T) {
	home := t.TempDir()
	path, err := Write(Config{
		BrokerName: "hf-broker",
		EnvPrefix:  "HF_BROKER",
		URL:        "https://broker.example.test",
		Secret:     "client-secret",
		HomeDir:    home,
	})
	if err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	wantPath := filepath.Join(home, ".config", "hf-broker", "client.env")
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
	if !strings.Contains(text, "HF_BROKER_URL='https://broker.example.test'\n") {
		t.Fatalf("client env missing URL: %q", text)
	}
	if !strings.Contains(text, "HF_BROKER_SHARED_SECRET='client-secret'\n") {
		t.Fatalf("client env missing secret: %q", text)
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

func TestSecretFromDataValidation(t *testing.T) {
	cases := map[string]struct {
		data   string
		client string
	}{
		"missing client name": {data: "bob = secret\n"},
		"bad line":            {data: "bob secret\n", client: "bob"},
		"empty secret":        {data: "bob = \n", client: "bob"},
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

func TestValidation(t *testing.T) {
	cases := map[string]Config{
		"bad broker": {BrokerName: "../bad", EnvPrefix: "GH_BROKER", URL: "http://127.0.0.1", Secret: "s"},
		"bad prefix": {BrokerName: "gh-broker", EnvPrefix: "gh-broker", URL: "http://127.0.0.1", Secret: "s"},
		"bad url":    {BrokerName: "gh-broker", EnvPrefix: "GH_BROKER", URL: "ftp://127.0.0.1", Secret: "s"},
		"no secret":  {BrokerName: "gh-broker", EnvPrefix: "GH_BROKER", URL: "http://127.0.0.1"},
	}
	for name, cfg := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Render(cfg); err == nil {
				t.Fatal("Render() error = nil, want validation error")
			}
		})
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
