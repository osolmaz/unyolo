package installation

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	files "github.com/osolmaz/unyolo/internal/storage/files"
)

func writeMarker(t *testing.T, root string, m marker) {
	t.Helper()
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := files.WriteJSONAtomic(filepath.Join(root, ".transaction.json"), m, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestRecoverRollsBackPublishingPhase(t *testing.T) {
	t.Parallel()
	root := filepath.Join(t.TempDir(), "installations")
	store := Store{Root: root}
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	currentDir := filepath.Join(root, DefaultName)
	if err := os.MkdirAll(currentDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(currentDir, "installation.json"), []byte(`{"partial":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	backup := currentDir + ".backup-recover"
	if err := os.MkdirAll(backup, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(backup, "installation.json"), []byte(`{"restored":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	writeMarker(t, root, marker{APIVersion: APIVersion, Name: DefaultName, Phase: phasePublishing, Backup: backup})

	if err := store.Recover(); err != nil {
		t.Fatalf("Recover() = %v", err)
	}
	data, err := os.ReadFile(filepath.Join(currentDir, "installation.json"))
	if err != nil || string(data) != `{"restored":true}` {
		t.Fatalf("restored data = %q, %v", data, err)
	}
	if _, err := os.Stat(filepath.Join(root, ".transaction.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("marker was not cleared: %v", err)
	}
}

func TestRecoverCommitsPhaseKeepsNewInstallation(t *testing.T) {
	t.Parallel()
	root := filepath.Join(t.TempDir(), "installations")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	currentDir := filepath.Join(root, DefaultName)
	if err := os.MkdirAll(currentDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(currentDir, "installation.json"), []byte(`{"new":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	backup := currentDir + ".backup-commits"
	if err := os.MkdirAll(backup, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(backup, "old.json"), []byte(`old`), 0o600); err != nil {
		t.Fatal(err)
	}
	writeMarker(t, root, marker{APIVersion: APIVersion, Name: DefaultName, Phase: phaseCommitted, Backup: backup})

	store := Store{Root: root}
	if err := store.Recover(); err != nil {
		t.Fatalf("Recover() = %v", err)
	}
	// New installation must survive committed-phase recovery.
	if _, err := os.Stat(filepath.Join(currentDir, "installation.json")); err != nil {
		t.Fatalf("new installation lost after committed recovery: %v", err)
	}
	if _, err := os.Stat(backup); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("backup was not cleaned: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, ".transaction.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("marker was not cleared: %v", err)
	}
}

func TestRecoverRejectsInvalidMarker(t *testing.T) {
	t.Parallel()
	root := filepath.Join(t.TempDir(), "installations")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	bad, err := json.Marshal(map[string]any{"api_version": "wrong", "name": "default", "phase": phasePublishing})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".transaction.json"), bad, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := (Store{Root: root}).Recover(); err == nil {
		t.Fatal("Recover() accepted a bad marker")
	}
}

func TestStoreDiscardRemovesInstallationSource(t *testing.T) {
	t.Parallel()
	root := filepath.Join(t.TempDir(), "installations")
	store := Store{Root: root}
	if err := os.MkdirAll(filepath.Join(root, DefaultName, "generated"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, DefaultName, "installation.json"), []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := store.Discard(DefaultName); err != nil {
		t.Fatalf("Discard() = %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, DefaultName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("installation directory still exists: %v", err)
	}
	// A second Discard on a missing installation is a no-op.
	if err := store.Discard(DefaultName); err != nil {
		t.Fatalf("Discard() on missing installation = %v", err)
	}
}
