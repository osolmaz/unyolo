package clientconfig

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadGeneratedClientConfiguration(t *testing.T) {
	home := t.TempDir()
	written, err := Write(Config{BrokerName: "gh-broker", EnvPrefix: "GH_BROKER", ClientID: "agent-a", Endpoint: "unix:///tmp/agent.sock",
		GitEndpoint: "tcp://127.0.0.1:32191", Secret: strings.Repeat("s", 32), HomeDir: home})
	if err != nil {
		t.Fatal(err)
	}
	client, err := Read(home, "gh-broker", "GH_BROKER")
	if err != nil {
		t.Fatal(err)
	}
	if client.ClientID != "agent-a" || client.GitEndpoint != "tcp://127.0.0.1:32191" || client.SharedSecret != strings.Repeat("s", 32) {
		t.Fatalf("client = %+v", client)
	}
	if err := os.Chmod(written, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(home, "gh-broker", "GH_BROKER"); err == nil {
		t.Fatal("Read accepted a group-readable client file")
	}
}

func TestReadRejectsUnknownAndDuplicateJSONFields(t *testing.T) {
	home := t.TempDir()
	dir := filepath.Join(home, ".config", "gh-broker")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, body := range []string{
		`{"api_version":"brokerkit.io/client/v1","client_id":"a","agent_endpoint":"unix:///tmp/a","shared_secret":"secret","run":"evil"}`,
		`{"api_version":"brokerkit.io/client/v1","client_id":"a","agent_endpoint":"unix:///tmp/a","agent_endpoint":"unix:///tmp/b","shared_secret":"secret"}`,
	} {
		if err := os.WriteFile(filepath.Join(dir, "client.json"), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Read(home, "gh-broker", "GH_BROKER"); err == nil {
			t.Fatalf("Read accepted %q", body)
		}
	}
}

func TestValidateClientFileRejectsUnsafePaths(t *testing.T) {
	home := t.TempDir()
	missing := filepath.Join(home, "missing")
	if err := validateClientFile(missing, home); err == nil {
		t.Fatal("validateClientFile accepted a missing file")
	}
	directory := filepath.Join(home, "client.json")
	if err := os.Mkdir(directory, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := validateClientFile(directory, home); err == nil {
		t.Fatal("validateClientFile accepted a directory")
	}
	file := filepath.Join(home, "regular.env")
	if err := os.WriteFile(file, []byte("test"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := validateClientFile(file, filepath.Join(home, "unknown-home")); err == nil {
		t.Fatal("validateClientFile accepted a missing home")
	}
}
