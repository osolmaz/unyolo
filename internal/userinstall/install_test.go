package userinstall

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestActivatePublishesOneVerifiedRelease(t *testing.T) {
	stage := writeStage(t, "v1.2.3")
	dataHome, binHome := t.TempDir(), t.TempDir()
	for _, path := range []string{dataHome, binHome} {
		if err := os.Chmod(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Date(2026, 7, 30, 8, 0, 0, 0, time.UTC)
	options := Options{StageRoot: stage, DataHome: dataHome, BinHome: binHome, Now: func() time.Time { return now }}
	if err := Activate(t.Context(), options); err != nil {
		t.Fatal(err)
	}
	output, err := exec.CommandContext(context.Background(), filepath.Join(binHome, "unyolo"), "--version").CombinedOutput()
	if err != nil || strings.TrimSpace(string(output)) != "v1.2.3" {
		t.Fatalf("active CLI = %q, %v", output, err)
	}
	current, err := os.Readlink(filepath.Join(dataHome, "unyolo", "current"))
	if err != nil || current != filepath.Join("releases", "v1.2.3") {
		t.Fatalf("current = %q, %v", current, err)
	}
	manifestData, err := os.ReadFile(filepath.Join(dataHome, "unyolo", "releases", "v1.2.3", "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest Manifest
	if err := json.Unmarshal(manifestData, &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.Release != "unyolo/v1.2.3" || manifest.InstalledAt != now || len(manifest.Files) != 3 {
		t.Fatalf("manifest = %+v", manifest)
	}
	if _, err := os.Stat(filepath.Join(dataHome, "unyolo", "releases", "v1.2.3", "providers", "github.json")); err != nil {
		t.Fatalf("installed provider catalog: %v", err)
	}
	if err := Activate(t.Context(), options); err != nil {
		t.Fatalf("idempotent activation: %v", err)
	}
}

func TestActivateFailurePreservesExistingCLI(t *testing.T) {
	stage := writeStage(t, "v1.2.3")
	if err := os.Remove(filepath.Join(stage, "libexec", "openclaw-unyolo-setup")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(stage, "bin", "unyolo"), filepath.Join(stage, "libexec", "openclaw-unyolo-setup")); err != nil {
		t.Fatal(err)
	}
	dataHome, binHome := t.TempDir(), t.TempDir()
	for _, path := range []string{dataHome, binHome} {
		if err := os.Chmod(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	oldCLI := filepath.Join(binHome, "unyolo")
	if err := os.WriteFile(oldCLI, []byte("#!/bin/sh\necho old\n"), 0o755); err != nil { // #nosec G306 -- executable test fixture.
		t.Fatal(err)
	}
	err := Activate(t.Context(), Options{StageRoot: stage, DataHome: dataHome, BinHome: binHome})
	if err == nil || !strings.Contains(err.Error(), "invalid file") {
		t.Fatalf("activation error = %v", err)
	}
	data, readErr := os.ReadFile(oldCLI)
	if readErr != nil || !strings.Contains(string(data), "echo old") {
		t.Fatalf("old CLI changed: %q, %v", data, readErr)
	}
	if _, statErr := os.Lstat(filepath.Join(dataHome, "unyolo", "current")); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("current exists after failed preparation: %v", statErr)
	}
}

func TestActivateRollsBackCurrentWhenBinaryLinkFails(t *testing.T) {
	stage := writeStage(t, "v1.2.3")
	dataHome, binHome := t.TempDir(), t.TempDir()
	for _, path := range []string{dataHome, binHome} {
		if err := os.Chmod(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(filepath.Join(binHome, "unyolo"), 0o700); err != nil {
		t.Fatal(err)
	}
	err := Activate(t.Context(), Options{StageRoot: stage, DataHome: dataHome, BinHome: binHome})
	if err == nil {
		t.Fatal("activation unexpectedly replaced a directory on PATH")
	}
	if _, statErr := os.Lstat(filepath.Join(dataHome, "unyolo", "current")); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("current exists after link failure: %v", statErr)
	}
	if info, statErr := os.Stat(filepath.Join(binHome, "unyolo")); statErr != nil || !info.IsDir() {
		t.Fatalf("existing binary path changed: %+v, %v", info, statErr)
	}
}

func TestActivateRejectsVersionMismatch(t *testing.T) {
	stage := writeStage(t, "v1.2.3")
	data, err := os.ReadFile(filepath.Join(stage, "stage.json"))
	if err != nil {
		t.Fatal(err)
	}
	var record StageRecord
	if err := json.Unmarshal(data, &record); err != nil {
		t.Fatal(err)
	}
	record.Release = "unyolo/v2.0.0"
	record.Attestation.SourceRef = "refs/tags/unyolo/v2.0.0"
	data, _ = json.Marshal(record)
	if err := os.WriteFile(filepath.Join(stage, "stage.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	dataHome, binHome := t.TempDir(), t.TempDir()
	for _, path := range []string{dataHome, binHome} {
		if chmodErr := os.Chmod(path, 0o700); chmodErr != nil {
			t.Fatal(chmodErr)
		}
	}
	err = Activate(t.Context(), Options{StageRoot: stage, DataHome: dataHome, BinHome: binHome})
	if err == nil || !strings.Contains(err.Error(), "version does not match") {
		t.Fatalf("version mismatch = %v", err)
	}
}

func writeStage(t *testing.T, version string) string {
	t.Helper()
	stage := t.TempDir()
	if err := os.Chmod(stage, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, directory := range []string{"bin", "libexec", filepath.Join("share", "providers")} {
		if err := os.MkdirAll(filepath.Join(stage, directory), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	cli := "#!/bin/sh\nif [ \"${1:-}\" = --version ]; then echo '" + version + "'; fi\n"
	for path, body := range map[string]string{
		filepath.Join("bin", "unyolo"):                    cli,
		filepath.Join("libexec", "openclaw-unyolo-setup"): "#!/bin/sh\necho companion\n",
	} {
		if err := os.WriteFile(filepath.Join(stage, path), []byte(body), 0o755); err != nil { // #nosec G306 -- executable test fixture.
			t.Fatal(err)
		}
	}
	providerData := `{"api_version":"unyolo.io/setup-provider/v1","id":"github","label":"GitHub","selected":true}` + "\n"
	if err := os.WriteFile(filepath.Join(stage, "share", "providers", "github.json"), []byte(providerData), 0o600); err != nil {
		t.Fatal(err)
	}
	record := StageRecord{
		APIVersion: StageAPIVersion, Release: "unyolo/" + version,
		SourceCommit: strings.Repeat("a", 40), ArchiveSHA256: "sha256:" + strings.Repeat("b", 64),
		Attestation: Attestation{Repository: "osolmaz/unyolo", Workflow: "osolmaz/unyolo/.github/workflows/release.yml", SourceRef: "refs/tags/unyolo/" + version},
	}
	data, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stage, "stage.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	return stage
}
