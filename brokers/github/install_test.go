package ghbroker

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestInstallWrapperDelegatesToBrokerkit(t *testing.T) {
	dir := t.TempDir()
	delegate := filepath.Join(dir, "delegate.sh")
	if err := os.WriteFile(delegate, []byte("#!/bin/sh\nprintf '%s|%s|%s|%s\\n' \"$BROKER\" \"$REPO\" \"$VERSION\" \"$INSTALL_DIR\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	command := exec.CommandContext(context.Background(), "sh", "install.sh") // #nosec G204 -- test executes the repository-owned installer wrapper.
	command.Env = append(os.Environ(),
		"BROKERKIT_INSTALLER_FILE="+delegate,
		"REPO=example/gh-broker",
		"VERSION=v1.2.3",
		"INSTALL_DIR=/tmp/broker-bin",
	)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("install wrapper: %v: %s", err, output)
	}
	if got := strings.TrimSpace(string(output)); got != "gh-broker|example/gh-broker|v1.2.3|/tmp/broker-bin" {
		t.Fatalf("delegated environment = %q", got)
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
