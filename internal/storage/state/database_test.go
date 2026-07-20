package state

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pressly/goose/v3"
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

func TestOpenClearsIncompleteVersionOneNotificationReferences(t *testing.T) {
	directory := t.TempDir()
	database, err := openSQL(filepath.Join(directory, databaseFile), Options{})
	if err != nil {
		t.Fatal(err)
	}
	migrations, err := fs.Sub(migrationFiles, "migrations")
	if err != nil {
		t.Fatal(err)
	}
	provider, err := goose.NewProvider(goose.DialectSQLite3, database, migrations)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provider.UpTo(t.Context(), 1); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC).Format(time.RFC3339Nano)
	legacyNotification := `{"kind":"telegram","chat_id":42,"message_id":7,"text":"old reference"}`
	currentNotification := `{"kind":"telegram","renderer":"telegram-html-v1","chat_id":42,"message_id":8,"text":"current reference","presentation_json":"{}","presentation_digest":"sha256:presentation","rendered_digest":"sha256:rendered"}`
	insertGrant := `
		INSERT INTO grants (
			id, decision_token_verifier, client, operation, target_json, attrs_json, metadata_json,
			reason, status, revision, created_at, pending_expires_at, duration_ns,
			requested_duration_ns, pending_timeout_ns, notification_json, notification_status
		) VALUES (?, ?, 'bob', 'git.fetch', '{}', '{}', '{}', '', 'expired', 1, ?, ?, 0, 0, 1, ?, 'expired')`
	for _, record := range []struct {
		id, verifier, notification string
	}{
		{"legacy-grant", "legacy-verifier", legacyNotification},
		{"current-grant", "current-verifier", currentNotification},
	} {
		if _, err := database.ExecContext(t.Context(), insertGrant, record.id, record.verifier, now, now, record.notification); err != nil {
			t.Fatal(err)
		}
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}

	upgraded, err := Open(t.Context(), directory, Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = upgraded.Close() })
	if err := upgraded.ValidateCurrentFormat(t.Context()); err != nil {
		t.Fatal(err)
	}
	snapshot, err := upgraded.GrantSnapshot(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Grants) != 2 || snapshot.Grants[0].ID != "current-grant" || string(snapshot.Grants[0].NotificationJSON) != currentNotification ||
		snapshot.Grants[1].ID != "legacy-grant" || len(snapshot.Grants[1].NotificationJSON) != 0 {
		t.Fatalf("migrated grants = %+v, want current reference preserved and obsolete reference removed", snapshot.Grants)
	}
}

func TestOperationalStatsReportOnlyDurableQueueCounts(t *testing.T) {
	database, err := Open(t.Context(), t.TempDir(), Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	now := time.Date(2026, 7, 15, 0, 0, 0, 0, time.UTC)
	empty, err := database.GrantSnapshot(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	maxUses := 1
	created := GrantSnapshot{
		Grants: []GrantRecord{{
			ID: "grant-1", DecisionTokenVerifier: "verifier", Client: "agent-a", Operation: "repo.delete",
			TargetJSON: []byte(`{}`), AttrsJSON: []byte(`{}`), MetadataJSON: []byte(`{}`), Status: "pending",
			Revision: 1, CreatedAt: now, PendingExpiresAt: now.Add(time.Minute), Duration: time.Minute,
			RequestedDuration: time.Minute, PendingTimeout: time.Minute, MaxUses: &maxUses, RequestedMaxUses: &maxUses,
		}},
		Outbox: []NotificationOutboxRecord{{
			GrantID: "grant-1", Kind: "approval", PayloadJSON: []byte(`{}`), IdempotencyKey: "grant-1:approval",
			Status: "ambiguous", AvailableAt: now, CreatedAt: now, UpdatedAt: now,
		}},
	}
	if err := database.SaveGrantSnapshot(t.Context(), empty, created); err != nil {
		t.Fatal(err)
	}
	for _, record := range []OperationRecord{
		testOperationalRecord("queued", "pending", now),
		testOperationalRecord("running", "executing", now),
	} {
		if err := database.InsertOperation(t.Context(), record); err != nil {
			t.Fatal(err)
		}
	}
	stats, err := database.OperationalStats(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	want := OperationalStats{PendingApprovals: 1, QueuedOperations: 1, ExecutingOperations: 1, UnresolvedNotifications: 1}
	if stats != want {
		t.Fatalf("OperationalStats() = %+v, want %+v", stats, want)
	}
}

func testOperationalRecord(id, operationState string, now time.Time) OperationRecord {
	return OperationRecord{
		ID: id, APIVersion: "brokerkit.io/agent/v1", Broker: "test", ClientID: "agent-a", IdempotencyKey: id,
		Operation: "repo.delete", TargetJSON: []byte(`{}`), ArgumentsJSON: []byte(`{}`), State: operationState,
		Revision: 1, CreatedAt: now, UpdatedAt: now, PresentationJSON: []byte(`{}`),
	}
}

func TestOpenTightensStateFilePermissions(t *testing.T) {
	directory := t.TempDir()
	databasePath := filepath.Join(directory, databaseFile)
	leasePath := filepath.Join(directory, leaseFile)
	if err := os.WriteFile(databasePath, nil, 0o666); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(leasePath, nil, 0o666); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(databasePath, 0o666); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(leasePath, 0o666); err != nil {
		t.Fatal(err)
	}
	database, err := Open(t.Context(), directory, Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	for _, path := range []string{databasePath, leasePath, databasePath + "-wal", databasePath + "-shm"} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got != 0o600 {
			t.Fatalf("%s mode = %o, want 600", filepath.Base(path), got)
		}
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

func TestOpenAcceptsRelativeDirectory(t *testing.T) {
	workingDirectory, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	directory, err := filepath.Rel(workingDirectory, filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	database, err := Open(t.Context(), directory, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
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
