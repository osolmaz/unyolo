package gitclient

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/osolmaz/brokerkit/clientconfig"
)

func TestInstallCredentialAndUninstallWithRealGit(t *testing.T) {
	secret := strings.Repeat("s", 32)
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		_, password, ok := request.BasicAuth()
		if request.URL.Path != identityPath || !ok || password != secret {
			http.Error(response, "denied", http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(response).Encode(map[string]string{"provider": "github"})
	}))
	defer server.Close()
	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()
	if _, err := clientconfig.Write(clientconfig.Config{
		BrokerName: "gh-broker", EnvPrefix: "GH_BROKER", Endpoint: "unix:///tmp/agent.sock",
		GitEndpoint: "tcp://" + parsed.Host, Secret: secret, HomeDir: home,
	}); err != nil {
		t.Fatal(err)
	}
	provider := Provider{ID: "github", BrokerName: "gh-broker", EnvPrefix: "GH_BROKER", CanonicalPrefixes: []string{"https://github.com/", "git@github.com:"}}
	status, err := Install(t.Context(), provider, Options{HomeDir: home})
	if err != nil {
		t.Fatal(err)
	}
	if !status.Installed || status.Mode != ModeAll {
		t.Fatalf("status = %+v", status)
	}
	config, err := os.ReadFile(filepath.Join(home, ".gitconfig"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(config), "brokerkit --provider github") || !strings.Contains(string(config), "https://github.com/") {
		t.Fatalf("git config = %s", config)
	}
	if _, err := Install(t.Context(), provider, Options{HomeDir: home}); err != nil {
		t.Fatalf("idempotent Install() error = %v", err)
	}
	rewrites, err := commandRunner{home: home}.Run(t.Context(), "git", "config", "--global", "--get-all", "url."+server.URL+"/.insteadOf")
	if err != nil || strings.Count(strings.TrimSpace(string(rewrites)), "\n") != 1 {
		t.Fatalf("idempotent rewrites = %q, %v", rewrites, err)
	}
	var credential strings.Builder
	input := "protocol=http\nhost=" + parsed.Host + "\npath=owner/repo.git\n\n"
	if err := Credential(provider, home, "get", strings.NewReader(input), &credential); err != nil {
		t.Fatal(err)
	}
	if credential.String() != "username=brokerkit\npassword="+secret+"\n" {
		t.Fatalf("credential response = %q", credential.String())
	}
	if err := os.Remove(filepath.Join(home, ".config", "gh-broker", "client.env")); err != nil {
		t.Fatal(err)
	}
	if _, err := Uninstall(context.Background(), provider, Options{HomeDir: home}); err != nil {
		t.Fatal(err)
	}
	status, err = Inspect(t.Context(), provider, Options{HomeDir: home})
	if err != nil || status.Installed {
		t.Fatalf("uninstalled status = %+v, %v", status, err)
	}
}

func TestCredentialRefusesAnotherOrigin(t *testing.T) {
	home := t.TempDir()
	if _, err := clientconfig.Write(clientconfig.Config{
		BrokerName: "gh-broker", EnvPrefix: "GH_BROKER", Endpoint: "unix:///tmp/agent.sock",
		GitEndpoint: "tcp://127.0.0.1:32191", Secret: strings.Repeat("s", 32), HomeDir: home,
	}); err != nil {
		t.Fatal(err)
	}
	provider := Provider{ID: "github", BrokerName: "gh-broker", EnvPrefix: "GH_BROKER", CanonicalPrefixes: []string{"https://github.com/"}}
	var output strings.Builder
	err := Credential(provider, home, "get", strings.NewReader("protocol=https\nhost=github.com\npath=owner/repo\n\n"), &output)
	if err != nil || output.Len() != 0 {
		t.Fatalf("Credential() = %q, %v", output.String(), err)
	}
}

func TestCommandRunnerUsesConfiguredHomeAsWorkingDirectory(t *testing.T) {
	home := t.TempDir()
	output, err := (commandRunner{home: home}).Run(t.Context(), "sh", "-c", "printf '%s\\n%s' \"$HOME\" \"$PWD\"")
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(string(output), "\n")
	if len(lines) != 2 || lines[0] != home || lines[1] != home {
		t.Fatalf("HOME and PWD = %q, want %q", output, home)
	}
}

func TestRunCommandLifecycle(t *testing.T) {
	secret := strings.Repeat("s", 32)
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		_, password, ok := request.BasicAuth()
		if request.URL.Path != identityPath || !ok || password != secret {
			http.Error(response, "denied", http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(response).Encode(map[string]string{"provider": "github"})
	}))
	defer server.Close()
	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()
	if _, err := clientconfig.Write(clientconfig.Config{
		BrokerName: "gh-broker", EnvPrefix: "GH_BROKER", Endpoint: "unix:///tmp/agent.sock",
		GitEndpoint: "tcp://" + parsed.Host, Secret: secret, HomeDir: home,
	}); err != nil {
		t.Fatal(err)
	}
	provider := Provider{ID: "github", BrokerName: "gh-broker", EnvPrefix: "GH_BROKER", CanonicalPrefixes: []string{"https://github.com/"}}
	var stdout, stderr bytes.Buffer
	if err := RunCommand(t.Context(), provider, []string{"status", "--home-dir", home, "--json"}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), `"installed":false`) {
		t.Fatalf("initial status = %q", stdout.String())
	}
	for _, args := range [][]string{
		{"install", "--home-dir", home},
		{"doctor", "--home-dir", home, "--json"},
		{"uninstall", "--home-dir", home},
	} {
		stdout.Reset()
		stderr.Reset()
		if err := RunCommand(t.Context(), provider, args, &stdout, &stderr); err != nil {
			t.Fatalf("RunCommand(%v) error = %v, stderr = %q", args, err, stderr.String())
		}
	}
	for _, args := range [][]string{{}, {"unknown"}, {"status", "extra"}, {"status", "--mode", "invalid"}} {
		if err := RunCommand(t.Context(), provider, args, &stdout, &stderr); err == nil {
			t.Fatalf("RunCommand(%v) error = nil", args)
		}
	}
}

func TestParseCredentialArgs(t *testing.T) {
	provider, action, err := ParseCredentialArgs([]string{"--provider", "github", "get"})
	if err != nil || provider != "github" || action != "get" {
		t.Fatalf("ParseCredentialArgs() = %q, %q, %v", provider, action, err)
	}
	for _, args := range [][]string{
		{}, {"get"}, {"--provider"}, {"--provider", "github"},
		{"--provider", "github", "--provider", "huggingface", "get"},
		{"--provider", "github", "get", "store"}, {"--bad", "github", "get"},
	} {
		if _, _, err := ParseCredentialArgs(args); err == nil {
			t.Fatalf("ParseCredentialArgs(%v) error = nil", args)
		}
	}
}

func TestCredentialIgnoresPersistenceActions(t *testing.T) {
	provider := Provider{ID: "github", BrokerName: "gh-broker", EnvPrefix: "GH_BROKER", CanonicalPrefixes: []string{"https://github.com/"}}
	for _, action := range []string{"capability", "store", "erase"} {
		if err := Credential(provider, t.TempDir(), action, strings.NewReader(""), &strings.Builder{}); err != nil {
			t.Fatalf("Credential(%q) error = %v", action, err)
		}
	}
	if err := Credential(provider, t.TempDir(), "invalid", strings.NewReader(""), &strings.Builder{}); err == nil {
		t.Fatal("Credential(invalid) error = nil")
	}
}
