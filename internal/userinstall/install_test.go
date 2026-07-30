package userinstall

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
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
	if manifest.Release != "unyolo/v1.2.3" || manifest.InstalledAt != now || len(manifest.Files) != 5 {
		t.Fatalf("manifest = %+v", manifest)
	}
	if _, err := os.Stat(filepath.Join(dataHome, "unyolo", "releases", "v1.2.3", "providers", "github.json")); err != nil {
		t.Fatalf("installed provider catalog: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dataHome, "unyolo", "releases", "v1.2.3", "deployment-kits", "templates", "test", "deployment.json")); err != nil {
		t.Fatalf("installed deployment kits: %v", err)
	}
	artifactInfo, err := os.Stat(filepath.Join(dataHome, "unyolo", "releases", "v1.2.3", "deployment-kits", "artifacts", "test-broker"))
	if err != nil || artifactInfo.Mode().Perm() != 0o755 {
		t.Fatalf("installed deployment runtime artifact: %+v, %v", artifactInfo, err)
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

func TestActivateRestoresPriorCurrentWhenBinaryLinkFails(t *testing.T) {
	dataHome, binHome := t.TempDir(), t.TempDir()
	for _, path := range []string{dataHome, binHome} {
		if err := os.Chmod(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := Activate(t.Context(), Options{StageRoot: writeStage(t, "v1.2.3"), DataHome: dataHome, BinHome: binHome}); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(binHome, "unyolo")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(binHome, "unyolo"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := Activate(t.Context(), Options{StageRoot: writeStage(t, "v1.2.4"), DataHome: dataHome, BinHome: binHome}); err == nil {
		t.Fatal("activation unexpectedly replaced a directory on PATH")
	}
	current, err := os.Readlink(filepath.Join(dataHome, "unyolo", "current"))
	if err != nil || current != filepath.Join("releases", "v1.2.3") {
		t.Fatalf("prior current release was not restored: %q, %v", current, err)
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

func TestInstallationFilesystemHelpersRejectUnsafeInputs(t *testing.T) {
	root := t.TempDir()
	if _, err := verifySourceFile(filepath.Join(root, "missing")); err == nil {
		t.Fatal("missing staged file was accepted")
	}
	if _, err := verifySourceFile(root); err == nil {
		t.Fatal("directory was accepted as a staged file")
	}
	empty := filepath.Join(root, "empty")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := verifySourceFile(empty); err == nil {
		t.Fatal("empty staged file was accepted")
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(empty, link); err != nil {
		t.Fatal(err)
	}
	if _, err := verifySourceFile(link); err == nil {
		t.Fatal("symlink was accepted as a staged file")
	}
	if err := copyRegular(filepath.Join(root, "missing"), filepath.Join(root, "copy"), 0o600); err == nil {
		t.Fatal("missing copy source was accepted")
	}
	source := filepath.Join(root, "source")
	if err := os.WriteFile(source, []byte("source"), 0o600); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(root, "destination")
	if err := os.WriteFile(destination, []byte("existing"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := copyRegular(source, destination, 0o600); err == nil {
		t.Fatal("existing copy destination was replaced")
	}
	if err := verifyOwnedDirectory(source); err == nil {
		t.Fatal("file was accepted as an installation directory")
	}
	writable := filepath.Join(root, "writable")
	if err := os.Mkdir(writable, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(writable, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := verifyOwnedDirectory(writable); err == nil {
		t.Fatal("group-writable installation directory was accepted")
	}
}

func TestVerifyExistingReleaseRejectsCorruption(t *testing.T) {
	stage := writeStage(t, "v1.2.3")
	dataHome, binHome := t.TempDir(), t.TempDir()
	for _, path := range []string{dataHome, binHome} {
		if err := os.Chmod(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := Activate(t.Context(), Options{StageRoot: stage, DataHome: dataHome, BinHome: binHome}); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(dataHome, "unyolo", "releases", "v1.2.3")
	manifestData, err := os.ReadFile(filepath.Join(root, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var expected Manifest
	if err := json.Unmarshal(manifestData, &expected); err != nil {
		t.Fatal(err)
	}
	changed := expected
	changed.SourceCommit = strings.Repeat("c", 40)
	if err := verifyExistingRelease(root, changed); err == nil {
		t.Fatal("changed release identity was accepted")
	}
	changed = expected
	changed.Files = changed.Files[:len(changed.Files)-1]
	if err := verifyExistingRelease(root, changed); err == nil {
		t.Fatal("changed release file set was accepted")
	}
	changed = expected
	changed.Files = append([]File(nil), expected.Files...)
	changed.Files[0].SHA256 = "sha256:" + strings.Repeat("d", 64)
	if err := verifyExistingRelease(root, changed); err == nil {
		t.Fatal("changed release file record was accepted")
	}
	if err := os.WriteFile(filepath.Join(root, expected.Files[0].Path), []byte("corrupt"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := verifyExistingRelease(root, expected); err == nil {
		t.Fatal("corrupt installed release file was accepted")
	}
	if err := os.WriteFile(filepath.Join(root, "manifest.json"), []byte("{\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := verifyExistingRelease(root, expected); err == nil {
		t.Fatal("malformed installed release manifest was accepted")
	}
}

func TestCollectReleaseDataRejectsTooManyFiles(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	for index := 0; index < 1025; index++ {
		name := filepath.Join(root, fmt.Sprintf("file-%04d", index))
		if err := os.WriteFile(name, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := collectReleaseData(root, "deployment-kits"); err == nil {
		t.Fatal("oversized release data tree was accepted")
	}
}

func TestCollectReleaseDataRejectsUnsafeTrees(t *testing.T) {
	tests := []struct {
		name  string
		build func(*testing.T, string)
	}{
		{"symlink", func(t *testing.T, root string) {
			if err := os.Symlink("outside", filepath.Join(root, "link")); err != nil {
				t.Fatal(err)
			}
		}},
		{"writable directory", func(t *testing.T, root string) {
			path := filepath.Join(root, "unsafe")
			if err := os.Mkdir(path, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(path, 0o777); err != nil {
				t.Fatal(err)
			}
		}},
		{"empty file", func(t *testing.T, root string) {
			if err := os.WriteFile(filepath.Join(root, "empty"), nil, 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"oversized data", func(t *testing.T, root string) {
			file, err := os.Create(filepath.Join(root, "large"))
			if err != nil {
				t.Fatal(err)
			}
			if err := file.Truncate(maxDeploymentKitFile + 1); err != nil {
				_ = file.Close()
				t.Fatal(err)
			}
			if err := file.Close(); err != nil {
				t.Fatal(err)
			}
		}},
		{"nonexecutable artifact", func(t *testing.T, root string) {
			path := filepath.Join(root, "artifacts")
			if err := os.Mkdir(path, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(path, "broker"), []byte("binary"), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			if err := os.Chmod(root, 0o700); err != nil {
				t.Fatal(err)
			}
			test.build(t, root)
			if _, err := collectReleaseData(root, "deployment-kits"); err == nil {
				t.Fatal("unsafe release data tree was accepted")
			}
		})
	}
}

func TestInstallRootUsesEnvironmentAndHomeDefaults(t *testing.T) {
	t.Setenv("UNYOLO_TEST_ROOT", filepath.Join(t.TempDir(), "configured"))
	configured, err := installRoot("", "UNYOLO_TEST_ROOT", filepath.Join(".local", "share"))
	if err != nil || configured != os.Getenv("UNYOLO_TEST_ROOT") {
		t.Fatalf("configured install root: %q, %v", configured, err)
	}
	t.Setenv("UNYOLO_TEST_ROOT", "")
	fallback, err := installRoot("", "UNYOLO_TEST_ROOT", filepath.Join(".local", "share"))
	if err != nil || !filepath.IsAbs(fallback) {
		t.Fatalf("home install root: %q, %v", fallback, err)
	}
}

func TestValidateOptionsRejectsInvalidStageMetadata(t *testing.T) {
	tests := []struct {
		name   string
		option func(*Options)
		record func(*StageRecord)
		raw    []byte
	}{
		{"relative stage", func(value *Options) { value.StageRoot = "relative" }, nil, nil},
		{"relative data home", func(value *Options) { value.DataHome = "relative" }, nil, nil},
		{"relative bin home", func(value *Options) { value.BinHome = "relative" }, nil, nil},
		{"API", nil, func(value *StageRecord) { value.APIVersion = "bad" }, nil},
		{"release", nil, func(value *StageRecord) { value.Release = "other/v1.2.3" }, nil},
		{"source commit", nil, func(value *StageRecord) { value.SourceCommit = "bad" }, nil},
		{"archive digest", nil, func(value *StageRecord) { value.ArchiveSHA256 = "bad" }, nil},
		{"repository", nil, func(value *StageRecord) { value.Attestation.Repository = "bad" }, nil},
		{"workflow", nil, func(value *StageRecord) { value.Attestation.Workflow = "bad" }, nil},
		{"source ref", nil, func(value *StageRecord) { value.Attestation.SourceRef = "bad" }, nil},
		{"malformed", nil, nil, []byte("{\n")},
		{"oversized", nil, nil, bytes.Repeat([]byte("x"), 16*1024+1)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			stage := writeStage(t, "v1.2.3")
			options := Options{StageRoot: stage, DataHome: t.TempDir(), BinHome: t.TempDir()}
			if test.option != nil {
				test.option(&options)
			}
			if test.record != nil || test.raw != nil {
				data, err := os.ReadFile(filepath.Join(stage, "stage.json"))
				if err != nil {
					t.Fatal(err)
				}
				if test.record != nil {
					var record StageRecord
					if err := json.Unmarshal(data, &record); err != nil {
						t.Fatal(err)
					}
					test.record(&record)
					data, err = json.Marshal(record)
					if err != nil {
						t.Fatal(err)
					}
				} else {
					data = test.raw
				}
				if err := os.WriteFile(filepath.Join(stage, "stage.json"), data, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if _, _, _, err := validateOptions(options); err == nil {
				t.Fatal("invalid bootstrap stage metadata was accepted")
			}
		})
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
	for _, directory := range []string{"bin", "libexec", filepath.Join("share", "providers"), filepath.Join("share", "deployment-kits", "templates", "test"), filepath.Join("share", "deployment-kits", "artifacts")} {
		if err := os.MkdirAll(filepath.Join(stage, directory), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	cli := "#!/bin/sh\nif [ \"${1:-}\" = --version ]; then echo '" + version + "'; fi\n"
	companions := []string{"openclaw-unyolo-setup"}
	files := map[string]string{filepath.Join("bin", "unyolo"): cli}
	for _, name := range companions {
		files[filepath.Join("libexec", name)] = "#!/bin/sh\necho companion\n"
	}
	for path, body := range files {
		if err := os.WriteFile(filepath.Join(stage, path), []byte(body), 0o755); err != nil { // #nosec G306 -- executable test fixture.
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(stage, "share", "deployment-kits", "templates", "test", "deployment.json"), []byte("deployment-template\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stage, "share", "deployment-kits", "artifacts", "test-broker"), []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
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
