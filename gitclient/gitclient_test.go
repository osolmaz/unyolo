package gitclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/osolmaz/brokerkit/clientconfig"
)

func TestInstallCredentialAndUninstallWithRealGit(t *testing.T) {
	installTestCredentialHelper(t)
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
	runner := commandRunner{home: home}
	if _, err := runner.Run(t.Context(), "config", "--global", "http.proxy", "http://proxy.example"); err != nil {
		t.Fatal(err)
	}
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
	proxy, err := runner.Run(t.Context(), "config", "--get-urlmatch", "http.proxy", server.URL+"/owner/repo.git")
	if err != nil || strings.TrimSpace(string(proxy)) != "" {
		t.Fatalf("broker listener proxy = %q, %v", proxy, err)
	}
	if _, err := Install(t.Context(), provider, Options{HomeDir: home}); err != nil {
		t.Fatalf("idempotent Install() error = %v", err)
	}
	rewrites, err := commandRunner{home: home}.Run(t.Context(), "config", "--global", "--get-all", "url."+server.URL+"/.insteadOf")
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
	runner := commandRunner{home: home}
	if _, err := runner.Run(t.Context(), "init"); err != nil {
		t.Fatal(err)
	}
	output, err := runner.Run(t.Context(), "rev-parse", "--show-toplevel")
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(output)) != home {
		t.Fatalf("working directory = %q, want %q", output, home)
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
	for _, args := range [][]string{{}, {"unknown"}, {"status", "extra"}, {"status", "--mode", "push-only"}} {
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

func TestCredentialHandlesUnavailableAndIncompleteConfiguration(t *testing.T) {
	provider := testProvider()
	var missingOutput strings.Builder
	if err := Credential(provider, t.TempDir(), "get", strings.NewReader(""), &missingOutput); err == nil {
		t.Fatal("Credential accepted a missing client configuration")
	}
	if missingOutput.String() != "quit=true\n" {
		t.Fatalf("missing configuration output = %q", missingOutput.String())
	}
	home := t.TempDir()
	if _, err := clientconfig.Write(clientconfig.Config{
		BrokerName: provider.BrokerName, EnvPrefix: provider.EnvPrefix, Endpoint: "unix:///tmp/agent.sock",
		Secret: strings.Repeat("s", 32), HomeDir: home,
	}); err != nil {
		t.Fatal(err)
	}
	var output strings.Builder
	if err := Credential(provider, home, "get", strings.NewReader("protocol=http\nhost=127.0.0.1:1\npath=owner/repo\n\n"), &output); err != nil {
		t.Fatal(err)
	}
	if output.String() != "quit=true\n" {
		t.Fatalf("Credential output = %q", output.String())
	}
}

func TestPrepareHomeAndProviderValidation(t *testing.T) {
	valid := testProvider()
	for _, provider := range []Provider{
		{},
		{ID: "github", BrokerName: "gh-broker", EnvPrefix: "GH_BROKER", CanonicalPrefixes: []string{"relative"}},
		{ID: "github", BrokerName: "gh-broker", EnvPrefix: "GH_BROKER", CanonicalPrefixes: []string{"git@github.com:\n"}},
	} {
		if _, err := prepareHome(provider, &Options{HomeDir: t.TempDir()}); err == nil {
			t.Fatalf("prepareHome accepted provider %+v", provider)
		}
	}
	if _, err := prepareHome(valid, &Options{HomeDir: "relative"}); err == nil {
		t.Fatal("prepareHome accepted a relative home")
	}
	for _, repository := range []string{"relative", t.TempDir() + "/../repository"} {
		if _, err := prepareHome(valid, &Options{HomeDir: t.TempDir(), Repository: repository}); err == nil {
			t.Fatalf("prepareHome accepted repository %q", repository)
		}
	}
	if runner, err := prepareHome(valid, &Options{HomeDir: t.TempDir()}); err != nil || runner == nil {
		t.Fatalf("prepareHome valid options = %T, %v", runner, err)
	}
}

func TestInstallReplacementAndDoctorFailures(t *testing.T) {
	provider := testProvider()
	home, server := writeGitClientFixture(t, provider, "github")
	defer server.Close()
	if _, err := Install(t.Context(), provider, Options{HomeDir: home}); err != nil {
		t.Fatal(err)
	}
	replacement := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(response).Encode(map[string]string{"provider": "github"})
	}))
	parsedReplacement, err := url.Parse(replacement.URL)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := clientconfig.Write(clientconfig.Config{
		BrokerName: provider.BrokerName, EnvPrefix: provider.EnvPrefix, Endpoint: "unix:///tmp/agent.sock",
		GitEndpoint: "tcp://" + parsedReplacement.Host, Secret: strings.Repeat("s", 32), HomeDir: home,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := Install(t.Context(), provider, Options{HomeDir: home}); err == nil {
		t.Fatal("Install replaced different settings without --replace")
	}
	if _, err := Install(t.Context(), provider, Options{HomeDir: home, Replace: true}); err != nil {
		t.Fatal(err)
	}
	replacement.Close()
	if _, err := Doctor(t.Context(), provider, Options{HomeDir: home}); err == nil {
		t.Fatal("Doctor accepted an unavailable listener")
	}
	otherHome, otherServer := writeGitClientFixture(t, provider, "github")
	defer otherServer.Close()
	if _, err := Doctor(t.Context(), provider, Options{HomeDir: otherHome}); err == nil {
		t.Fatal("Doctor accepted an uninstalled client")
	}
}

func TestInstallRejectsHigherPriorityRewrite(t *testing.T) {
	provider := testProvider()
	home, server := writeGitClientFixture(t, provider, "github")
	defer server.Close()
	runner := commandRunner{home: home}
	if _, err := runner.Run(t.Context(), "config", "--global", "--add", "url.http://127.0.0.1:1/.insteadOf", "https://github.com/owner/"); err != nil {
		t.Fatal(err)
	}
	if _, err := Install(t.Context(), provider, Options{HomeDir: home}); err == nil {
		t.Fatal("Install accepted a higher-priority URL rewrite")
	}
}

func TestInstallRejectsUnownedTargetRewrite(t *testing.T) {
	provider := testProvider()
	home, server := writeGitClientFixture(t, provider, "github")
	defer server.Close()
	runner := commandRunner{home: home}
	key := "url." + server.URL + "/.insteadOf"
	if _, err := runner.Run(t.Context(), "config", "--global", "--add", key, "https://github.com/"); err != nil {
		t.Fatal(err)
	}
	if _, err := Install(t.Context(), provider, Options{HomeDir: home}); err == nil {
		t.Fatal("Install accepted an unowned rewrite for the target listener")
	}
	values, err := configValues(t.Context(), runner, key)
	if err != nil || !slices.Equal(values, []string{"https://github.com/"}) {
		t.Fatalf("unowned rewrite changed: %q, %v", values, err)
	}
}

func TestInstallPreservesUnownedTargetCredentialHelper(t *testing.T) {
	provider := testProvider()
	home, server := writeGitClientFixture(t, provider, "github")
	defer server.Close()
	runner := commandRunner{home: home}
	key := "credential." + server.URL + ".helper"
	if _, err := runner.Run(t.Context(), "config", "--global", "--add", key, "user-owned-helper"); err != nil {
		t.Fatal(err)
	}
	if _, err := Install(t.Context(), provider, Options{HomeDir: home}); err == nil {
		t.Fatal("Install accepted an unowned credential helper for the target listener")
	}
	values, err := configValues(t.Context(), runner, key)
	if err != nil || !slices.Equal(values, []string{"user-owned-helper"}) {
		t.Fatalf("unowned credential helper changed: %q, %v", values, err)
	}
}

func TestInstallRejectsUnavailableCredentialHelperWithoutMutation(t *testing.T) {
	provider := testProvider()
	home, server := writeGitClientFixture(t, provider, "github")
	defer server.Close()
	removeTestCredentialHelper(t)
	if _, err := Install(t.Context(), provider, Options{HomeDir: home}); err == nil || !strings.Contains(err.Error(), "credential helper is unavailable") {
		t.Fatalf("Install error = %v", err)
	}
	status, err := Inspect(t.Context(), provider, Options{HomeDir: home})
	if err != nil || status.Installed {
		t.Fatalf("status after rejected install = %+v, %v", status, err)
	}
}

func TestInstallAndDoctorRejectSystemRewrite(t *testing.T) {
	provider := testProvider()
	systemConfig := filepath.Join(t.TempDir(), "system.gitconfig")
	t.Setenv("GIT_CONFIG_SYSTEM", systemConfig)
	if err := os.WriteFile(systemConfig, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	home, server := writeGitClientFixture(t, provider, "github")
	defer server.Close()
	if _, err := Install(t.Context(), provider, Options{HomeDir: home}); err != nil {
		t.Fatal(err)
	}
	conflict := "[url \"http://127.0.0.1:1/\"]\n\tinsteadOf = https://github.com/owner/\n"
	if err := os.WriteFile(systemConfig, []byte(conflict), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Doctor(t.Context(), provider, Options{HomeDir: home}); err == nil {
		t.Fatal("Doctor accepted a higher-priority system URL rewrite")
	}
	otherHome, otherServer := writeGitClientFixture(t, provider, "github")
	defer otherServer.Close()
	if _, err := Install(t.Context(), provider, Options{HomeDir: otherHome}); err == nil {
		t.Fatal("Install accepted a higher-priority system URL rewrite")
	}
}

func TestInstallRejectsProxyAndProviderWideLFSOverrides(t *testing.T) {
	provider := testProvider()
	for _, test := range []struct {
		name      string
		configure func(*testing.T, commandRunner, string)
	}{
		{name: "scoped proxy", configure: func(t *testing.T, runner commandRunner, origin string) {
			if _, err := runner.Run(t.Context(), "config", "--global", "http."+origin+"/owner.proxy", "http://proxy.example"); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "global LFS URL", configure: func(t *testing.T, runner commandRunner, _ string) {
			if _, err := runner.Run(t.Context(), "config", "--global", "lfs.url", "https://direct.example/lfs"); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "global push URL", configure: func(t *testing.T, runner commandRunner, _ string) {
			if _, err := runner.Run(t.Context(), "config", "--global", "remote.origin.pushurl", "https://direct.example/repo.git"); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "system LFS push URL", configure: func(t *testing.T, _ commandRunner, _ string) {
			systemConfig := filepath.Join(t.TempDir(), "system.gitconfig")
			if err := os.WriteFile(systemConfig, []byte("[lfs]\n\tpushurl = https://direct.example/lfs\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			t.Setenv("GIT_CONFIG_SYSTEM", systemConfig)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			home, server := writeGitClientFixture(t, provider, "github")
			defer server.Close()
			runner := commandRunner{home: home}
			test.configure(t, runner, server.URL)
			if _, err := Install(t.Context(), provider, Options{HomeDir: home}); err == nil {
				t.Fatal("Install accepted a Git transport bypass")
			}
		})
	}
}

func TestInstallRejectsOverridesFromIncludedGlobalConfig(t *testing.T) {
	provider := testProvider()
	home, server := writeGitClientFixture(t, provider, "github")
	defer server.Close()
	included := filepath.Join(home, "included.gitconfig")
	if err := os.WriteFile(included, []byte("[url \"https://direct.example/\"]\n\tinsteadOf = https://github.com/owner/\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runner := commandRunner{home: home}
	if _, err := runner.Run(t.Context(), "config", "--global", "include.path", included); err != nil {
		t.Fatal(err)
	}
	if _, err := Install(t.Context(), provider, Options{HomeDir: home}); err == nil {
		t.Fatal("Install accepted a URL rewrite from an included global config")
	}
}

func TestDoctorRejectsModifiedEffectiveConfiguration(t *testing.T) {
	provider := testProvider()
	home, server := writeGitClientFixture(t, provider, "github")
	defer server.Close()
	status, err := Install(t.Context(), provider, Options{HomeDir: home})
	if err != nil {
		t.Fatal(err)
	}
	runner := commandRunner{home: home}
	if _, err := runner.Run(t.Context(), "config", "--global", "--unset", "credential."+status.Origin+".useHttpPath"); err != nil {
		t.Fatal(err)
	}
	if _, err := Doctor(t.Context(), provider, Options{HomeDir: home}); err == nil {
		t.Fatal("Doctor accepted modified credential isolation")
	}
}

func TestDoctorRejectsUnavailableCredentialHelper(t *testing.T) {
	provider := testProvider()
	home, server := writeGitClientFixture(t, provider, "github")
	defer server.Close()
	if _, err := Install(t.Context(), provider, Options{HomeDir: home}); err != nil {
		t.Fatal(err)
	}
	removeTestCredentialHelper(t)
	if _, err := Doctor(t.Context(), provider, Options{HomeDir: home}); err == nil || !strings.Contains(err.Error(), "credential helper is unavailable") {
		t.Fatalf("Doctor error = %v", err)
	}
}

func TestInstallRestoresPreviousConfigurationAfterWriteFailure(t *testing.T) {
	provider := testProvider()
	home, server := writeGitClientFixture(t, provider, "github")
	defer server.Close()
	previous, err := Install(t.Context(), provider, Options{HomeDir: home})
	if err != nil {
		t.Fatal(err)
	}
	replacement := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(response).Encode(map[string]string{"provider": "github"})
	}))
	defer replacement.Close()
	parsed, err := url.Parse(replacement.URL)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := clientconfig.Write(clientconfig.Config{
		BrokerName: provider.BrokerName, EnvPrefix: provider.EnvPrefix, Endpoint: "unix:///tmp/agent.sock",
		GitEndpoint: "tcp://" + parsed.Host, Secret: strings.Repeat("s", 32), HomeDir: home,
	}); err != nil {
		t.Fatal(err)
	}
	runner := &failOnceRunner{
		Runner: commandRunner{home: home},
		match: func(args []string) bool {
			return slices.Contains(args, statusKey(provider, "origin")) && slices.Contains(args, replacement.URL)
		},
	}
	if _, err := Install(t.Context(), provider, Options{HomeDir: home, Replace: true, Runner: runner}); err == nil || !strings.Contains(err.Error(), "injected write failure") {
		t.Fatalf("Install error = %v", err)
	}
	status, err := Inspect(t.Context(), provider, Options{HomeDir: home})
	if err != nil || status != previous {
		t.Fatalf("restored status = %+v, %v; want %+v", status, err, previous)
	}
	if err := verifyInstallation(t.Context(), provider, previous, commandRunner{home: home}); err != nil {
		t.Fatalf("restored installation is invalid: %v", err)
	}
}

func TestDoctorRejectsRepositoryTransportOverrides(t *testing.T) {
	provider := testProvider()
	home, server := writeGitClientFixture(t, provider, "github")
	defer server.Close()
	if _, err := Install(t.Context(), provider, Options{HomeDir: home}); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name      string
		configure func(string)
	}{
		{name: "local LFS URL", configure: func(repo string) {
			runner := commandRunner{home: home}
			if _, err := runner.Run(t.Context(), "-C", repo, "config", "--local", "lfs.url", "https://direct.example/lfs"); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "local URL rewrite", configure: func(repo string) {
			runner := commandRunner{home: home}
			if _, err := runner.Run(t.Context(), "-C", repo, "config", "--local", "url.https://direct.example/.insteadOf", "https://github.com/owner/"); err != nil {
				t.Fatal(err)
			}
		}},
		{name: ".lfsconfig", configure: func(repo string) {
			if err := os.WriteFile(filepath.Join(repo, ".lfsconfig"), []byte("[lfs]\n\turl = https://direct.example/lfs\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "listener proxy", configure: func(repo string) {
			runner := commandRunner{home: home}
			if _, err := runner.Run(t.Context(), "-C", repo, "config", "--local", "http."+server.URL+"/owner.proxy", "http://proxy.example"); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			repo := t.TempDir()
			runner := commandRunner{home: home}
			if _, err := runner.Run(t.Context(), "-C", repo, "init"); err != nil {
				t.Fatal(err)
			}
			test.configure(repo)
			if _, err := Doctor(t.Context(), provider, Options{HomeDir: home, Repository: repo}); err == nil {
				t.Fatal("Doctor accepted a repository transport override")
			}
		})
	}
}

func TestDoctorRejectsIncludedAndWorktreeTransportOverrides(t *testing.T) {
	provider := testProvider()
	for _, test := range []struct {
		name      string
		configure func(*testing.T, commandRunner, string, string)
	}{
		{name: "included local push URL", configure: func(t *testing.T, runner commandRunner, repo, home string) {
			included := filepath.Join(home, "repo-include.gitconfig")
			if err := os.WriteFile(included, []byte("[remote \"origin\"]\n\tpushurl = https://github.com/bypass/repo.git\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := runner.Run(t.Context(), "-C", repo, "config", "--local", "include.path", included); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "worktree URL rewrite", configure: func(t *testing.T, runner commandRunner, repo, _ string) {
			if _, err := runner.Run(t.Context(), "-C", repo, "config", "--local", "extensions.worktreeConfig", "true"); err != nil {
				t.Fatal(err)
			}
			if _, err := runner.Run(t.Context(), "-C", repo, "config", "--worktree", "url.https://direct.example/.insteadOf", "https://github.com/owner/"); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "conditional global rewrite", configure: func(t *testing.T, runner commandRunner, repo, home string) {
			included := filepath.Join(home, "conditional.gitconfig")
			if err := os.WriteFile(included, []byte("[url \"https://direct.example/\"]\n\tinsteadOf = https://github.com/owner/\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			key := "includeIf.gitdir:" + repo + "/.path"
			if _, err := runner.Run(t.Context(), "config", "--global", key, included); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "inherited global push URL", configure: func(t *testing.T, runner commandRunner, _, _ string) {
			if _, err := runner.Run(t.Context(), "config", "--global", "remote.origin.pushurl", "https://direct.example/repo.git"); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			home, server := writeGitClientFixture(t, provider, "github")
			defer server.Close()
			if _, err := Install(t.Context(), provider, Options{HomeDir: home}); err != nil {
				t.Fatal(err)
			}
			repo := t.TempDir()
			runner := commandRunner{home: home}
			if _, err := runner.Run(t.Context(), "-C", repo, "init"); err != nil {
				t.Fatal(err)
			}
			test.configure(t, runner, repo, home)
			if _, err := Doctor(t.Context(), provider, Options{HomeDir: home, Repository: repo}); err == nil {
				t.Fatal("Doctor accepted a repository transport bypass")
			}
		})
	}
}

func TestDoctorAcceptsCleanRepositoryAndOptionalNonRepository(t *testing.T) {
	provider := testProvider()
	home, server := writeGitClientFixture(t, provider, "github")
	defer server.Close()
	if _, err := Install(t.Context(), provider, Options{HomeDir: home}); err != nil {
		t.Fatal(err)
	}
	repo := t.TempDir()
	runner := commandRunner{home: home}
	if _, err := runner.Run(t.Context(), "-C", repo, "init"); err != nil {
		t.Fatal(err)
	}
	if _, err := Doctor(t.Context(), provider, Options{HomeDir: home, Repository: repo}); err != nil {
		t.Fatalf("Doctor rejected a clean repository: %v", err)
	}
	nonRepository := t.TempDir()
	if _, err := Doctor(t.Context(), provider, Options{
		HomeDir: home, Repository: nonRepository, repositoryOptional: true,
	}); err != nil {
		t.Fatalf("Doctor rejected an optional non-repository: %v", err)
	}
	if _, err := Doctor(t.Context(), provider, Options{HomeDir: home, Repository: nonRepository}); err == nil {
		t.Fatal("Doctor accepted a required non-repository")
	}
}

func TestCheckIdentityRejectsInvalidResponses(t *testing.T) {
	for _, response := range []struct {
		status int
		body   string
	}{
		{status: http.StatusForbidden, body: `{}`},
		{status: http.StatusOK, body: `{`},
		{status: http.StatusOK, body: `{"provider":"huggingface"}`},
		{status: http.StatusOK, body: `{"provider":"github"}{}`},
	} {
		server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
			writer.WriteHeader(response.status)
			_, _ = writer.Write([]byte(response.body))
		}))
		err := checkIdentity(t.Context(), server.Client(), server.URL, strings.Repeat("s", 32), "github")
		server.Close()
		if err == nil {
			t.Fatalf("checkIdentity accepted HTTP %d body %q", response.status, response.body)
		}
	}
}

func testProvider() Provider {
	return Provider{ID: "github", BrokerName: "gh-broker", EnvPrefix: "GH_BROKER", CanonicalPrefixes: []string{"https://github.com/", "git@github.com:"}}
}

func writeGitClientFixture(t *testing.T, provider Provider, identity string) (string, *httptest.Server) {
	t.Helper()
	installTestCredentialHelper(t)
	secret := strings.Repeat("s", 32)
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(response).Encode(map[string]string{"provider": identity})
	}))
	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()
	if _, err := clientconfig.Write(clientconfig.Config{
		BrokerName: provider.BrokerName, EnvPrefix: provider.EnvPrefix, Endpoint: "unix:///tmp/agent.sock",
		GitEndpoint: "tcp://" + parsed.Host, Secret: secret, HomeDir: home,
	}); err != nil {
		t.Fatal(err)
	}
	return home, server
}

type failOnceRunner struct {
	Runner
	match  func([]string) bool
	failed bool
}

func (r *failOnceRunner) Run(ctx context.Context, args ...string) ([]byte, error) {
	if !r.failed && r.match(args) {
		r.failed = true
		return nil, errors.New("injected write failure")
	}
	return r.Runner.Run(ctx, args...)
}

func installTestCredentialHelper(t *testing.T) {
	t.Helper()
	bin := t.TempDir()
	helper := filepath.Join(bin, "git-credential-brokerkit")
	if err := os.WriteFile(helper, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func removeTestCredentialHelper(t *testing.T) {
	t.Helper()
	git, err := exec.LookPath("git")
	if err != nil {
		t.Fatal(err)
	}
	bin := t.TempDir()
	if err := os.Symlink(git, filepath.Join(bin, "git")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)
}
