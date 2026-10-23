package bundle

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStateFileReplacementKeepsCredentialState(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "gh-broker")
	if err := os.MkdirAll(filepath.Join(stateDir, "credential-slots"), 0o700); err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string]string{
		"state.db": "old grants", "state.db-wal": "old wal", "credential-slots.key": "key", "credential-slots/github": "slot",
	} {
		if err := os.WriteFile(filepath.Join(stateDir, name), []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	component := Component{StateDir: stateDir, ReplaceState: true, StateFiles: []string{"state.db", "state.db-wal", "state.db-shm"}}
	backup := stateBackupPath(stateDir, "bundle-two")
	if err := replaceComponentState(component, backup); err != nil {
		t.Fatal(err)
	}
	assertFile(t, filepath.Join(stateDir, "credential-slots.key"), "key")
	assertFile(t, filepath.Join(stateDir, "credential-slots/github"), "slot")
	assertFile(t, filepath.Join(backup, "state.db"), "old grants")
	if _, err := os.Stat(filepath.Join(stateDir, "state.db")); !os.IsNotExist(err) {
		t.Fatalf("old database stayed in place: %v", err)
	}
	if err := replaceComponentState(component, backup); err == nil {
		t.Fatal("an existing state backup was overwritten")
	}

	// The new release creates its own database and a shared-memory file the
	// old state did not have. Restoring brings back the old files exactly.
	for name, data := range map[string]string{"state.db": "new grants", "state.db-shm": "new shm"} {
		if err := os.WriteFile(filepath.Join(stateDir, name), []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := restoreComponentState(component, backup); err != nil {
		t.Fatal(err)
	}
	assertFile(t, filepath.Join(stateDir, "state.db"), "old grants")
	assertFile(t, filepath.Join(stateDir, "state.db-wal"), "old wal")
	assertFile(t, filepath.Join(stateDir, "credential-slots.key"), "key")
	if _, err := os.Stat(filepath.Join(stateDir, "state.db-shm")); !os.IsNotExist(err) {
		t.Fatalf("new shared-memory file survived the restore: %v", err)
	}
	if _, err := os.Stat(backup); !os.IsNotExist(err) {
		t.Fatalf("state backup survived the restore: %v", err)
	}
	if err := restoreComponentState(component, backup); err != nil {
		t.Fatalf("restore without a backup = %v", err)
	}
}

func TestStateFileReplacementCreatesMissingDirectory(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "missing")
	component := Component{StateDir: stateDir, ReplaceState: true, StateFiles: []string{"state.db"}}
	if err := replaceComponentState(component, stateDir+".backup"); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(stateDir); err != nil || !info.IsDir() {
		t.Fatalf("state directory = %+v, %v", info, err)
	}
	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	component.StateDir = file
	if err := replaceComponentState(component, file+".backup"); err == nil {
		t.Fatal("a regular file was accepted as a state directory")
	}
}

func TestStateFilesValidation(t *testing.T) {
	valid := Component{StateDir: "/var/lib/gh-broker", ReplaceState: true, StateFiles: []string{"state.db", "state.db-wal"}}
	if err := valid.validateState(); err != nil {
		t.Fatal(err)
	}
	for name, files := range map[string][]string{
		"empty": {""}, "dot": {"."}, "parent": {".."}, "path": {"sub/state.db"}, "duplicate": {"state.db", "state.db"},
	} {
		component := valid
		component.StateFiles = files
		if err := component.validateState(); err == nil {
			t.Fatalf("%s state file list was accepted", name)
		}
	}
	component := valid
	component.ReplaceState = false
	if err := component.validateState(); err == nil || !strings.Contains(err.Error(), "require state replacement") {
		t.Fatalf("state files without replacement = %v", err)
	}
}

func assertFile(t *testing.T, path, want string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil || string(data) != want {
		t.Fatalf("%s = %q, %v; want %q", path, data, err, want)
	}
}
