package state

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestStateCheckBackupRestoreAndOpenExisting(t *testing.T) {
	root := t.TempDir()
	sourceDirectory := filepath.Join(root, "source")
	database, err := Open(t.Context(), sourceDirectory, Options{})
	if err != nil {
		t.Fatal(err)
	}
	createdAt := time.Now().UTC()
	digest, err := database.PutPlan(t.Context(), "test.io/plan/v1", []byte(`{"secret":"source-value"}`), createdAt)
	if err != nil {
		t.Fatal(err)
	}
	if report, err := database.Check(t.Context(), true); err != nil || report.QuickCheck != "ok" || report.FullCheck != "ok" || report.DatabaseBytes < 1 {
		t.Fatalf("check = %+v, %v", report, err)
	}
	backupDirectory := filepath.Join(root, "backup")
	manifest, err := database.Backup(t.Context(), backupDirectory)
	if err != nil || manifest.Format != backupFormat || manifest.SchemaVersion != CurrentSchemaVersion || len(manifest.SHA256) != 64 {
		t.Fatalf("backup = %+v, %v", manifest, err)
	}
	if _, err := OpenExisting(t.Context(), sourceDirectory, Options{}); !errors.Is(err, ErrStateInUse) {
		t.Fatalf("concurrent OpenExisting() = %v", err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}

	targetDirectory := filepath.Join(root, "target")
	target, err := Open(t.Context(), targetDirectory, Options{})
	if err != nil {
		t.Fatal(err)
	}
	oldDigest, err := target.PutPlan(t.Context(), "test.io/plan/v1", []byte(`{"old":true}`), createdAt)
	if err != nil {
		t.Fatal(err)
	}
	if err := target.Close(); err != nil {
		t.Fatal(err)
	}
	if err := Restore(t.Context(), targetDirectory, backupDirectory); err != nil {
		t.Fatal(err)
	}
	restored, err := OpenExisting(t.Context(), targetDirectory, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = restored.Close() }()
	if _, err := restored.Plan(t.Context(), digest); err != nil {
		t.Fatalf("restored plan is missing: %v", err)
	}
	if _, err := restored.Plan(t.Context(), oldDigest); !errors.Is(err, ErrNotFound) {
		t.Fatalf("old plan survived restore: %v", err)
	}
}

func TestRestoreRejectsTamperingAndActiveState(t *testing.T) {
	root := t.TempDir()
	source, err := Open(t.Context(), filepath.Join(root, "source"), Options{})
	if err != nil {
		t.Fatal(err)
	}
	backupDirectory := filepath.Join(root, "backup")
	if _, err := source.Backup(t.Context(), backupDirectory); err != nil {
		t.Fatal(err)
	}
	if err := source.Close(); err != nil {
		t.Fatal(err)
	}
	targetDirectory := filepath.Join(root, "target")
	target, err := Open(t.Context(), targetDirectory, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err := Restore(t.Context(), targetDirectory, backupDirectory); !errors.Is(err, ErrStateInUse) {
		t.Fatalf("restore active state = %v", err)
	}
	if err := target.Close(); err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(backupDirectory, backupManifestFile)
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	var manifest BackupManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatal(err)
	}
	manifest.SHA256 = strings.Repeat("0", 64)
	data, _ = json.Marshal(manifest)
	if err := os.WriteFile(manifestPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	before, _, err := fileDigest(filepath.Join(targetDirectory, databaseFile), maxStateFileBytes)
	if err != nil {
		t.Fatal(err)
	}
	if err := Restore(t.Context(), targetDirectory, backupDirectory); err == nil {
		t.Fatal("restore accepted a tampered manifest")
	}
	after, _, err := fileDigest(filepath.Join(targetDirectory, databaseFile), maxStateFileBytes)
	if err != nil || before != after {
		t.Fatalf("failed restore changed live state: before=%s after=%s err=%v", before, after, err)
	}
}

func TestReadBackupManifestRejectsMalformedManifest(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, backupManifestFile)
	if err := os.WriteFile(path, []byte(`{"format":"wrong"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readBackupManifest(directory); err == nil {
		t.Fatal("malformed backup manifest accepted")
	}
}

func TestReadBackupManifestAcceptsCurrentManifest(t *testing.T) {
	root := t.TempDir()
	database, err := Open(t.Context(), filepath.Join(root, "state"), Options{})
	if err != nil {
		t.Fatal(err)
	}
	backupDirectory := filepath.Join(root, "backup")
	manifest, err := database.Backup(t.Context(), backupDirectory)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	read, err := readBackupManifest(backupDirectory)
	if err != nil {
		t.Fatal(err)
	}
	if read.SHA256 != manifest.SHA256 || read.DatabaseBytes != manifest.DatabaseBytes {
		t.Fatalf("manifest = %+v, want %+v", read, manifest)
	}
}

func TestBackupRejectsExistingDestination(t *testing.T) {
	root := t.TempDir()
	database, err := Open(t.Context(), filepath.Join(root, "state"), Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = database.Close() }()
	destination := filepath.Join(root, "backup")
	if err := os.Mkdir(destination, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Backup(t.Context(), destination); err == nil {
		t.Fatal("backup existing destination accepted")
	}
}

func TestRestoreInstallsIntoEmptyStateDirectory(t *testing.T) {
	root := t.TempDir()
	source, err := Open(t.Context(), filepath.Join(root, "source"), Options{})
	if err != nil {
		t.Fatal(err)
	}
	backupDirectory := filepath.Join(root, "backup")
	if _, err := source.Backup(t.Context(), backupDirectory); err != nil {
		t.Fatal(err)
	}
	if err := source.Close(); err != nil {
		t.Fatal(err)
	}
	targetDirectory := filepath.Join(root, "empty-target")
	if err := os.Mkdir(targetDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := Restore(t.Context(), targetDirectory, backupDirectory); err != nil {
		t.Fatal(err)
	}
	restored, err := OpenExisting(t.Context(), targetDirectory, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err := restored.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestStateExportIsDeterministicAndRedacted(t *testing.T) {
	root := t.TempDir()
	directory := filepath.Join(root, "state")
	database, err := Open(t.Context(), directory, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = database.Close() }()
	createdAt := time.Date(2026, time.July, 15, 1, 2, 3, 0, time.UTC)
	canonicalSecret := "canonical-plan-secret"
	digest, err := database.PutPlan(t.Context(), "test.io/plan/v1", []byte(`{"token":"`+canonicalSecret+`"}`), createdAt)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.InsertOperation(t.Context(), OperationRecord{ID: "op-1", APIVersion: "brokerkit.io/agent/v1", Broker: "test-broker",
		ClientID: "agent-a", IdempotencyKey: "request-1", Operation: "repo.create", TargetJSON: []byte(`{"token":"target-secret"}`),
		ArgumentsJSON: []byte(`{"token":"argument-secret"}`), Reason: "reason-secret", State: "pending", Revision: 1,
		CreatedAt: createdAt, UpdatedAt: createdAt, PresentationJSON: []byte(`{"title":"secret title"}`), PlanDigest: digest}); err != nil {
		t.Fatal(err)
	}
	first, second := filepath.Join(root, "first.json"), filepath.Join(root, "second.json")
	if err := database.Export(t.Context(), first); err != nil {
		t.Fatal(err)
	}
	if err := database.Export(t.Context(), second); err != nil {
		t.Fatal(err)
	}
	left, _ := os.ReadFile(first)
	right, _ := os.ReadFile(second)
	if string(left) != string(right) {
		t.Fatal("identical state produced nondeterministic exports")
	}
	for _, secret := range []string{canonicalSecret, "target-secret", "argument-secret", "reason-secret", "secret title"} {
		if strings.Contains(string(left), secret) {
			t.Fatalf("export leaked %q: %s", secret, left)
		}
	}
	if !strings.Contains(string(left), `"id":"op-1"`) || !strings.Contains(string(left), `"digest":"`+digest+`"`) {
		t.Fatalf("export omitted safe references: %s", left)
	}
}

func TestMaintenancePathsRejectRelativeAndNestedDestinations(t *testing.T) {
	database, err := Open(t.Context(), t.TempDir(), Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = database.Close() }()
	if _, err := database.Backup(t.Context(), "relative"); err == nil {
		t.Fatal("relative backup destination accepted")
	}
	if err := database.Export(t.Context(), filepath.Join(database.directory, "export.json")); err == nil {
		t.Fatal("nested export destination accepted")
	}
}
