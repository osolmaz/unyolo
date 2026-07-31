package installer

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestRootBootstrapBindsReleaseToSourceCommit(t *testing.T) {
	data, err := os.ReadFile("bootstrap-root.sh")
	if err != nil {
		t.Fatal(err)
	}
	body := string(data)
	for _, expected := range []string{`[ "$#" -eq 2 ]`, `--source-digest "$source_commit"`, `--bundle "$bundle"`} {
		if !strings.Contains(body, expected) {
			t.Fatalf("root bootstrap is missing %q", expected)
		}
	}
}

func TestRootBootstrapKeepsProviderAdaptersExecutable(t *testing.T) {
	data, err := os.ReadFile("bootstrap-root.sh")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `find "$verified_new/source-set/artifacts" -type f -exec chmod 0555 {} +`) {
		t.Fatal("root bootstrap does not restore executable permissions on signed provider adapters")
	}
}

func TestBootstrapStagesOnceAndRemovesStageAfterSetup(t *testing.T) {
	requireLinuxBootstrap(t)
	script, err := exec.LookPath("script")
	if err != nil {
		t.Skip("script command is required for PTY coverage")
	}
	root := t.TempDir()
	installer := writeBootstrapFixtureInstaller(t, root, false)
	command := bootstrapPTYCommand(t.Context(), script)
	command.Dir = ".."
	command.Env = append(os.Environ(),
		"UNYOLO_INSTALLER_FILE="+installer,
		"UNYOLO_SOURCE_COMMIT="+strings.Repeat("a", 40),
		"BOOTSTRAP_FIXTURE_ROOT="+root,
	)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("bootstrap failed: %v\n%s", err, output)
	}
	count, err := os.ReadFile(filepath.Join(root, "install-count"))
	if err != nil || string(count) != "1\n" {
		t.Fatalf("install count = %q, %v", count, err)
	}
	args, err := os.ReadFile(filepath.Join(root, "setup-args"))
	if err != nil || !strings.Contains(string(args), "setup --accessible --bootstrap-stage") {
		t.Fatalf("setup args = %q, %v", args, err)
	}
	fields := strings.Fields(string(args))
	stage := fields[len(fields)-1]
	if _, err := os.Stat(stage); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("bootstrap stage remains: %v", err)
	}
}

func TestBootstrapCtrlCCleansStageAndReturns130(t *testing.T) {
	requireLinuxBootstrap(t)
	script, err := exec.LookPath("script")
	if err != nil {
		t.Skip("script command is required for PTY coverage")
	}
	root := t.TempDir()
	installer := writeBootstrapFixtureInstaller(t, root, true)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	command := bootstrapPTYCommand(ctx, script)
	command.Dir = ".."
	command.Env = append(os.Environ(),
		"UNYOLO_INSTALLER_FILE="+installer,
		"UNYOLO_SOURCE_COMMIT="+strings.Repeat("a", 40),
		"BOOTSTRAP_FIXTURE_ROOT="+root,
	)
	input, err := command.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	ready := filepath.Join(root, "ready")
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(ready); err == nil {
			break
		}
		if time.Now().After(deadline) {
			_ = command.Process.Kill()
			t.Fatal("staged setup did not become ready")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if _, err := input.Write([]byte{3}); err != nil {
		t.Fatal(err)
	}
	_ = input.Close()
	err = command.Wait()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 130 {
		t.Fatalf("Ctrl-C exit = %v", err)
	}
	args, readErr := os.ReadFile(filepath.Join(root, "setup-args"))
	if readErr != nil {
		t.Fatal(readErr)
	}
	fields := strings.Fields(string(args))
	stage := fields[len(fields)-1]
	if _, err := os.Stat(stage); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("bootstrap stage remains after Ctrl-C: %v", err)
	}
}

func requireLinuxBootstrap(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("guided host provisioning currently requires Linux")
	}
}

func bootstrapPTYCommand(ctx context.Context, script string) *exec.Cmd {
	return exec.CommandContext(ctx, script, "-qefc", "sh install/bootstrap.sh --release unyolo/v1.2.3 --accessible", "/dev/null") // #nosec G204 -- fixed repository command through the discovered PTY utility.
}

func writeBootstrapFixtureInstaller(t *testing.T, root string, wait bool) string {
	t.Helper()
	installer := filepath.Join(root, "fixture-installer.sh")
	waitBody := "exit 0"
	if wait {
		waitBody = "touch \"$BOOTSTRAP_FIXTURE_ROOT/ready\"\ntrap 'exit 130' INT\nwhile :; do sleep 1; done"
	}
	body := fmt.Sprintf(`#!/bin/sh
set -eu
count=0
[ ! -f "$BOOTSTRAP_FIXTURE_ROOT/install-count" ] || count=$(cat "$BOOTSTRAP_FIXTURE_ROOT/install-count")
count=$((count + 1))
printf '%%s\n' "$count" > "$BOOTSTRAP_FIXTURE_ROOT/install-count"
mkdir -p "$INSTALL_DIR" "$LIBEXEC_DIR" "$DATA_DIR/providers"
cat > "$INSTALL_DIR/unyolo" <<'CLI'
#!/bin/sh
printf '%%s\n' "$*" > "$BOOTSTRAP_FIXTURE_ROOT/setup-args"
%s
CLI
chmod 0755 "$INSTALL_DIR/unyolo"
printf '#!/bin/sh\nexit 0\n' > "$LIBEXEC_DIR/openclaw-unyolo-setup"
printf '#!/bin/sh\nexit 0\n' > "$LIBEXEC_DIR/gh-attestation-verifier"
chmod 0755 "$LIBEXEC_DIR/openclaw-unyolo-setup" "$LIBEXEC_DIR/gh-attestation-verifier"
for name in github huggingface sudo; do printf '{"api_version":"unyolo.io/setup-provider/v1","id":"%%s","label":"%%s","selected":true}\n' "$name" "$name" > "$DATA_DIR/providers/$name.json"; done
printf '{"api_version":"unyolo.io/bootstrap-stage/v1","release":"unyolo/v1.2.3","source_commit":"%%s","archive_sha256":"sha256:%%064d","attestation":{"repository":"osolmaz/unyolo","workflow":"osolmaz/unyolo/.github/workflows/release.yml","source_ref":"refs/tags/unyolo/v1.2.3"}}\n' "$UNYOLO_SOURCE_COMMIT" 0 > "$UNYOLO_INSTALL_RECORD"
`, waitBody)
	if err := os.WriteFile(installer, []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
	return installer
}
