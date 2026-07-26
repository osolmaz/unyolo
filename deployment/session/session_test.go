package session

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSessionRoundTripAndResume(t *testing.T) {
	now := time.Date(2026, 7, 26, 1, 2, 3, 0, time.UTC)
	store := Store{Directory: filepath.Join(t.TempDir(), "state"), Now: func() time.Time { return now }}
	value, err := New("build-1", "test-host", now)
	if err != nil {
		t.Fatal(err)
	}
	value.Answers["mode"] = []string{"recommended"}
	value.SecretSlots = []SecretSlot{{ID: "github-token", Supplied: true}}
	value.CompletedStep = []string{"mode", "github-token"}
	value.Phase = PhaseEnrolling
	if err := store.Save(value); err != nil {
		t.Fatal(err)
	}
	loaded, err := store.Load(value.ID)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Answers["mode"][0] != "recommended" || !loaded.SecretSlots[0].Supplied {
		t.Fatalf("loaded = %#v", loaded)
	}
	resumed, found, err := store.NewestIncomplete("build-1")
	if err != nil || !found || resumed.ID != value.ID {
		t.Fatalf("NewestIncomplete() = %#v, %v, %v", resumed, found, err)
	}
	data, err := os.ReadFile(filepath.Join(store.Directory, value.ID+".json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "credential-value") {
		t.Fatal("session persisted a credential canary")
	}
	if err := store.Cancel(value.ID); err != nil {
		t.Fatal(err)
	}
}

func TestSessionRejectsUnsafeDirectoryMode(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	value, err := New("build", "host", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := (Store{Directory: directory}).Save(value); err == nil {
		t.Fatal("Save() succeeded for unsafe directory")
	}
}
