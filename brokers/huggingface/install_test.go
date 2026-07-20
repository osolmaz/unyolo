package hfbroker

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/policy"
)

func TestInstallWrapperDelegatesToBrokerkit(t *testing.T) {
	dir := t.TempDir()
	delegate := filepath.Join(dir, "delegate.sh")
	if err := os.WriteFile(delegate, []byte("#!/bin/sh\nprintf '%s|%s|%s|%s|%s\\n' \"$BROKER\" \"$REPO\" \"$TAG_PREFIX\" \"$VERSION\" \"$INSTALL_DIR\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	command := exec.CommandContext(context.Background(), "sh", "install.sh") // #nosec G204 -- test executes the repository-owned installer wrapper.
	command.Env = append(os.Environ(),
		"BROKERKIT_INSTALLER_FILE="+delegate,
		"VERSION=v1.2.3",
		"INSTALL_DIR=/tmp/broker-bin",
	)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("install wrapper: %v: %s", err, output)
	}
	if got := strings.TrimSpace(string(output)); got != "hf-broker|osolmaz/brokerkit|hf-broker/|v1.2.3|/tmp/broker-bin" {
		t.Fatalf("delegated environment = %q", got)
	}
}

func TestScopeExampleParses(t *testing.T) {
	data, err := os.ReadFile("scope.example.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := policy.Parse(data); err != nil {
		t.Fatalf("scope.example.json: %v", err)
	}
}

func TestInstallWrapperPropagatesDownloadFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}))
	t.Cleanup(server.Close)
	command := exec.CommandContext(context.Background(), "sh", "install.sh") // #nosec G204 -- test executes the repository-owned installer wrapper.
	command.Env = append(os.Environ(), "BROKERKIT_INSTALLER_URL="+server.URL)
	if output, err := command.CombinedOutput(); err == nil {
		t.Fatalf("install wrapper succeeded after failed download: %s", output)
	}
}

func TestInstallWrapperResolvesReleaseToImmutableCommit(t *testing.T) {
	const revision = "0123456789abcdef0123456789abcdef01234567"
	requested := make(chan string, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/releases":
			_, _ = w.Write([]byte(`[{"tag_name":"hf-broker/v1.2.3"}]`))
		case "/refs/hf-broker/v1.2.3":
			_, _ = w.Write([]byte(`{"object":{"sha":"` + revision + `","type":"commit"}}`))
		case "/raw/" + revision + "/install/install.sh":
			requested <- r.URL.Path
			_, _ = w.Write([]byte("#!/bin/sh\nprintf '%s' \"$VERSION\"\n"))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	command := exec.CommandContext(t.Context(), "sh", "install.sh") // #nosec G204 -- test executes the repository-owned installer wrapper.
	command.Env = append(os.Environ(), "BROKERKIT_RELEASES_URL="+server.URL+"/releases",
		"BROKERKIT_REF_URL_BASE="+server.URL+"/refs", "BROKERKIT_RAW_URL_BASE="+server.URL+"/raw")
	output, err := command.CombinedOutput()
	if err != nil || strings.TrimSpace(string(output)) != "hf-broker/v1.2.3" {
		t.Fatalf("immutable wrapper err=%v output=%s", err, output)
	}
	if path := <-requested; !strings.Contains(path, revision) {
		t.Fatalf("installer path = %q", path)
	}
}

func TestInstallWrapperPeelsAnnotatedTagToImmutableCommit(t *testing.T) {
	const tagRevision = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	const commitRevision = "0123456789abcdef0123456789abcdef01234567"
	requested := make(chan string, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/refs/hf-broker/v1.2.3":
			_, _ = w.Write([]byte("{\n  \"object\": {\n    \"sha\": \"" + tagRevision + "\",\n    \"type\": \"tag\"\n  }\n}"))
		case "/tags/" + tagRevision:
			_, _ = w.Write([]byte("{\n  \"sha\": \"" + tagRevision + "\",\n  \"object\": {\n    \"sha\": \"" + commitRevision + "\",\n    \"type\": \"commit\"\n  }\n}"))
		case "/raw/" + commitRevision + "/install/install.sh":
			requested <- r.URL.Path
			_, _ = w.Write([]byte("#!/bin/sh\nprintf '%s' \"$VERSION\"\n"))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	command := exec.CommandContext(t.Context(), "sh", "install.sh") // #nosec G204 -- test executes the repository-owned installer wrapper.
	command.Env = append(os.Environ(),
		"VERSION=v1.2.3",
		"BROKERKIT_REF_URL_BASE="+server.URL+"/refs",
		"BROKERKIT_TAG_URL_BASE="+server.URL+"/tags",
		"BROKERKIT_RAW_URL_BASE="+server.URL+"/raw",
	)
	output, err := command.CombinedOutput()
	if err != nil || strings.TrimSpace(string(output)) != "hf-broker/v1.2.3" {
		t.Fatalf("annotated wrapper err=%v output=%s", err, output)
	}
	if path := <-requested; !strings.Contains(path, commitRevision) {
		t.Fatalf("installer path = %q", path)
	}
}

func TestInstallWrapperRejectsMutableRevision(t *testing.T) {
	command := exec.CommandContext(t.Context(), "sh", "install.sh") // #nosec G204 -- test executes the repository-owned installer wrapper.
	command.Env = append(os.Environ(), "BROKERKIT_INSTALLER_REV=main")
	output, err := command.CombinedOutput()
	if err == nil || !strings.Contains(string(output), "exact 40-character commit SHA") {
		t.Fatalf("mutable revision err=%v output=%s", err, output)
	}
}
