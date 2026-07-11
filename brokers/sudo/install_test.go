package sudobroker

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestInstallWrapperDelegatesCompanionBinary(t *testing.T) {
	t.Parallel()
	delegate := filepath.Join(t.TempDir(), "delegate.sh")
	if err := os.WriteFile(delegate, []byte("#!/bin/sh\nprintf '%s|%s|%s|%s\\n' \"$BROKER\" \"$REPO\" \"$TAG_PREFIX\" \"$COMPANION_BINARIES\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	command := exec.CommandContext(context.Background(), "sh", "install.sh") // #nosec G204 -- repository-owned wrapper.
	command.Env = append(os.Environ(), "BROKERKIT_INSTALLER_FILE="+delegate)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("install wrapper: %v: %s", err, output)
	}
	if got := strings.TrimSpace(string(output)); got != "sudo-broker|osolmaz/brokerkit|sudo-broker/|sudo-broker-exec" {
		t.Fatalf("delegated environment = %q", got)
	}
}
