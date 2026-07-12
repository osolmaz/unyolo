package state

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestOpenConfiguresAndMigratesDatabase(t *testing.T) {
	database, err := Open(t.Context(), t.TempDir(), Options{BusyTimeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	for name, want := range map[string]int{
		"foreign_keys": 1,
		"busy_timeout": 2000,
	} {
		var got int
		if err := database.SQL().QueryRowContext(t.Context(), "PRAGMA "+name).Scan(&got); err != nil || got != want {
			t.Fatalf("PRAGMA %s = %d, %v; want %d", name, got, err, want)
		}
	}
	var journal string
	if err := database.SQL().QueryRowContext(t.Context(), "PRAGMA journal_mode").Scan(&journal); err != nil || journal != "wal" {
		t.Fatalf("journal_mode = %q, %v", journal, err)
	}
	if result, err := database.IntegrityCheck(t.Context()); err != nil || result != "ok" {
		t.Fatalf("IntegrityCheck() = %q, %v", result, err)
	}
	if count, err := database.Queries().CountPlans(t.Context()); err != nil || count != 0 {
		t.Fatalf("CountPlans() = %d, %v", count, err)
	}
}

func TestStateLeasePreventsASecondProcessOwner(t *testing.T) {
	directory := t.TempDir()
	first, err := Open(t.Context(), directory, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(t.Context(), directory, Options{}); !errors.Is(err, ErrStateInUse) {
		t.Fatalf("second Open() error = %v, want ErrStateInUse", err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	second, err := Open(context.Background(), directory, Options{})
	if err != nil {
		t.Fatalf("Open() after release: %v", err)
	}
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestOpenRejectsMissingDirectory(t *testing.T) {
	if _, err := Open(t.Context(), "", Options{}); err == nil {
		t.Fatal("Open() accepted an empty state directory")
	}
}

func TestOpenRejectsAStatePathUnderAFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(path, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(t.Context(), filepath.Join(path, "state"), Options{}); err == nil {
		t.Fatal("Open() accepted a state path below a regular file")
	}
}

func TestNilDatabaseCloseIsSafe(t *testing.T) {
	var database *Database
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestOpenRejectsCanceledMigration(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := Open(ctx, t.TempDir(), Options{}); err == nil {
		t.Fatal("Open() migrated with a canceled context")
	}
}

func TestOpenRejectsAnUnusableLeasePath(t *testing.T) {
	directory := t.TempDir()
	if err := os.Mkdir(filepath.Join(directory, leaseFile), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(t.Context(), directory, Options{}); err == nil {
		t.Fatal("Open() accepted a directory as its lease file")
	}
}
