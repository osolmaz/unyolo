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

func TestResolveDevelopmentEnvironment(t *testing.T) {
	home := t.TempDir()
	values := map[string]string{
		"TEST_AGENT_ENDPOINT": "unix:///tmp/test.sock",
		"TEST_SHARED_SECRET":  strings.Repeat("s", 32),
	}
	getenv := func(key string) string { return values[key] }
	resolved, err := Resolve(home, "test-broker", "TEST", getenv)
	if err != nil || resolved.ClientID != "development" || resolved.AgentEndpoint != values["TEST_AGENT_ENDPOINT"] {
		t.Fatalf("Resolve() = %#v, %v", resolved, err)
	}
	secretFile := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(secretFile, []byte(strings.Repeat("f", 32)), 0o600); err != nil {
		t.Fatal(err)
	}
	delete(values, "TEST_SHARED_SECRET")
	values["TEST_SHARED_SECRET_FILE"] = secretFile
	resolved, err = Resolve(home, "test-broker", "TEST", getenv)
	if err != nil || resolved.SharedSecret != strings.Repeat("f", 32) {
		t.Fatalf("file Resolve() = %#v, %v", resolved, err)
	}
	values["TEST_SHARED_SECRET"] = strings.Repeat("s", 32)
	if _, err := Resolve(home, "test-broker", "TEST", getenv); err == nil {
		t.Fatal("conflicting environment credentials were accepted")
	}
	if _, err := Resolve(home, "test-broker", "EMPTY", getenv); err == nil {
		t.Fatal("missing configuration was accepted")
	}
}

func TestResolveRejectsFileEnvironmentConflict(t *testing.T) {
	home := t.TempDir()
	if _, err := Write(Config{BrokerName: "test-broker", EnvPrefix: "TEST", ClientID: "agent", Endpoint: "unix:///tmp/test.sock", Secret: strings.Repeat("s", 32), HomeDir: home}); err != nil {
		t.Fatal(err)
	}
	if _, err := Resolve(home, "test-broker", "TEST", func(key string) string {
		if key == "TEST_AGENT_ENDPOINT" {
			return "unix:///tmp/other.sock"
		}
		return ""
	}); err == nil {
		t.Fatal("file and environment conflict was accepted")
	}
	resolved, err := Resolve(home, "test-broker", "TEST", func(string) string { return "" })
	if err != nil || resolved.ClientID != "agent" {
		t.Fatalf("file Resolve() = %#v, %v", resolved, err)
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
