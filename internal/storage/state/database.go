// Package state owns unYOLO's local transactional database and process lease.
package state

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/osolmaz/unyolo/internal/storage/state/internal/dbsql"
	"github.com/pressly/goose/v3"
	_ "modernc.org/sqlite"
)

const (
	databaseFile = "state.db"
	leaseFile    = "state.lock"
	// CurrentSchemaVersion is the only state format accepted by maintenance
	// operations in this pre-release cutover.
	CurrentSchemaVersion  int64 = 1
	currentSchemaContract       = "unyolo-state-v1-grant-uses"
)

//go:embed migrations/*.sql
var migrationFiles embed.FS

type Options struct {
	BusyTimeout time.Duration
}

type Database struct {
	sql       *sql.DB
	queries   *dbsql.Queries
	lease     *lease
	directory string
	close     sync.Once
	closeErr  error
}

func Open(ctx context.Context, directory string, options Options) (*Database, error) {
	if directory == "" {
		return nil, errors.New("state directory is required")
	}
	if options.BusyTimeout <= 0 {
		options.BusyTimeout = 5 * time.Second
	}
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return nil, fmt.Errorf("create state directory: %w", err)
	}
	lock, err := acquireLease(filepath.Join(directory, leaseFile))
	if err != nil {
		return nil, err
	}
	return openLeasedDatabase(ctx, directory, options, lock)
}

func openLeasedDatabase(ctx context.Context, directory string, options Options, lock *lease) (*Database, error) {
	path := filepath.Join(directory, databaseFile)
	if err := ensurePrivateFile(path); err != nil {
		_ = lock.close()
		return nil, fmt.Errorf("secure state database: %w", err)
	}
	db, err := openSQL(path, options)
	if err != nil {
		_ = lock.close()
		return nil, err
	}
	result := &Database{sql: db, queries: dbsql.New(db), lease: lock, directory: directory}
	if err := result.migrate(ctx); err != nil {
		_ = result.Close()
		return nil, err
	}
	if err := result.ValidateCurrentFormat(ctx); err != nil {
		_ = result.Close()
		return nil, err
	}
	if _, err := result.queries.Health(ctx); err != nil {
		_ = result.Close()
		return nil, fmt.Errorf("check state database: %w", err)
	}
	return result, nil
}

// OpenExisting opens an exact current-format database under the process lease.
// It never creates a directory, database, or migration.
func OpenExisting(ctx context.Context, directory string, options Options) (*Database, error) {
	if directory == "" {
		return nil, errors.New("state directory is required")
	}
	if options.BusyTimeout <= 0 {
		options.BusyTimeout = 5 * time.Second
	}
	if err := validateExistingStateDirectory(directory); err != nil {
		return nil, err
	}
	lock, err := acquireLease(filepath.Join(directory, leaseFile))
	if err != nil {
		return nil, err
	}
	result, err := openCurrentDatabase(ctx, directory, options, lock)
	if err != nil {
		return nil, err
	}
	return result, nil
}

func validateExistingStateDirectory(directory string) error {
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("existing state directory is required")
	}
	return ensurePrivateDirectory(directory)
}

func openCurrentDatabase(ctx context.Context, directory string, options Options, lock *lease) (*Database, error) {
	path := filepath.Join(directory, databaseFile)
	if err := validatePrivateDatabaseFile(path); err != nil {
		_ = lock.close()
		return nil, err
	}
	db, err := openSQL(path, options)
	if err != nil {
		_ = lock.close()
		return nil, err
	}
	result := &Database{sql: db, queries: dbsql.New(db), lease: lock, directory: directory}
	if err := result.ValidateCurrentFormat(ctx); err != nil {
		_ = result.Close()
		return nil, err
	}
	return result, nil
}

func validatePrivateDatabaseFile(path string) error {
	info, err := os.Lstat(path) // #nosec G304 -- path is rooted in the selected state directory.
	if err != nil {
		return fmt.Errorf("read state database metadata: %w", err)
	}
	if err := validatePrivateDatabaseMode(info); err != nil {
		return err
	}
	return validatePrivateDatabaseOwner(info)
}

func validatePrivateDatabaseMode(info os.FileInfo) error {
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return errors.New("state database must be a private regular file")
	}
	return nil
}

func validatePrivateDatabaseOwner(info os.FileInfo) error {
	return validateCurrentUserOwner(info, "state database")
}

func validateCurrentUserOwner(info os.FileInfo, subject string) error {
	if stat, ok := info.Sys().(*syscall.Stat_t); ok && stat.Uid != uint32(os.Geteuid()) { // #nosec G115 -- effective UIDs are non-negative.
		return fmt.Errorf("%s must be owned by the current user", subject)
	}
	return nil
}

func ensurePrivateFile(path string) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600) // #nosec G304 -- path is rooted in the operator-selected state directory.
	if err != nil {
		return err
	}
	return errors.Join(file.Chmod(0o600), file.Close())
}

func openSQL(path string, options Options) (*sql.DB, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve state database path: %w", err)
	}
	values := url.Values{}
	for _, pragma := range []string{
		"foreign_keys(1)",
		"journal_mode(WAL)",
		fmt.Sprintf("busy_timeout(%d)", options.BusyTimeout.Milliseconds()),
		"synchronous(FULL)",
	} {
		values.Add("_pragma", pragma)
	}
	dsn := (&url.URL{Scheme: "file", Path: filepath.ToSlash(absolute), RawQuery: values.Encode()}).String()
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open state database: %w", err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	return db, nil
}

func (d *Database) migrate(ctx context.Context) error {
	directory, err := fs.Sub(migrationFiles, "migrations")
	if err != nil {
		return err
	}
	provider, err := goose.NewProvider(goose.DialectSQLite3, d.sql, directory)
	if err != nil {
		return fmt.Errorf("create state migration provider: %w", err)
	}
	results, err := provider.Up(ctx)
	if err != nil {
		return fmt.Errorf("migrate state database: %w", err)
	}
	for _, result := range results {
		if result.Error != nil {
			return fmt.Errorf("apply state migration %s: %w", result.Source.Path, result.Error)
		}
	}
	return nil
}

func (d *Database) Close() error {
	if d == nil {
		return nil
	}
	d.close.Do(func() {
		var errs []error
		if d.sql != nil {
			errs = append(errs, d.sql.Close())
		}
		if d.lease != nil {
			errs = append(errs, d.lease.close())
		}
		d.closeErr = errors.Join(errs...)
	})
	return d.closeErr
}

func (d *Database) SQL() *sql.DB { return d.sql }

func (d *Database) Queries() *dbsql.Queries { return d.queries }

// OperationalStats returns bounded aggregate state for health and metrics.
// It never reads operation arguments, targets, reasons, or notification payloads.
func (d *Database) OperationalStats(ctx context.Context) (OperationalStats, error) {
	if d == nil || d.queries == nil {
		return OperationalStats{}, errors.New("state database is unavailable")
	}
	stats, err := d.queries.OperationalStats(ctx)
	if err != nil {
		return OperationalStats{}, err
	}
	return OperationalStats{
		PendingApprovals:        stats.PendingApprovals,
		QueuedOperations:        stats.QueuedOperations,
		ExecutingOperations:     stats.ExecutingOperations,
		PendingNotifications:    stats.PendingNotifications,
		UnresolvedNotifications: stats.UnresolvedNotifications,
	}, nil
}

// OperationalStats contains only fixed-cardinality durable-state counts.
type OperationalStats struct {
	PendingApprovals        int64
	QueuedOperations        int64
	ExecutingOperations     int64
	PendingNotifications    int64
	UnresolvedNotifications int64
}

// IntegrityCheck runs SQLite's operational consistency check. PRAGMA queries
// are intentionally kept outside sqlc because sqlc does not generate them.
func (d *Database) IntegrityCheck(ctx context.Context) (string, error) {
	var result string
	err := d.sql.QueryRowContext(ctx, "PRAGMA integrity_check").Scan(&result)
	return result, err
}

// ValidateCurrentFormat rejects missing, old, or future state schemas.
func (d *Database) ValidateCurrentFormat(ctx context.Context) error {
	if d == nil || d.sql == nil {
		return errors.New("state database is unavailable")
	}
	if err := d.validateSchemaVersion(ctx); err != nil {
		return err
	}
	if err := d.validateSchemaContract(ctx); err != nil {
		return err
	}
	return d.validateQuickCheck(ctx)
}

func (d *Database) validateSchemaVersion(ctx context.Context) error {
	var version sql.NullInt64
	if err := d.sql.QueryRowContext(ctx, "SELECT max(version_id) FROM goose_db_version WHERE is_applied = 1").Scan(&version); err != nil {
		return fmt.Errorf("read state schema version: %w", err)
	}
	if !version.Valid || version.Int64 != CurrentSchemaVersion {
		return fmt.Errorf("state schema version is %d, want %d", version.Int64, CurrentSchemaVersion)
	}
	return nil
}

func (d *Database) validateSchemaContract(ctx context.Context) error {
	var contract string
	if err := d.sql.QueryRowContext(ctx, "SELECT contract FROM state_contract WHERE singleton = 1").Scan(&contract); err != nil {
		return errors.New("state format is unsupported; coordinated fresh state is required")
	}
	if contract != currentSchemaContract {
		return errors.New("state format is unsupported; coordinated fresh state is required")
	}
	return nil
}

func (d *Database) validateQuickCheck(ctx context.Context) error {
	var result string
	if err := d.sql.QueryRowContext(ctx, "PRAGMA quick_check").Scan(&result); err != nil {
		return fmt.Errorf("state quick check failed: %w", err)
	}
	if result != "ok" {
		return fmt.Errorf("state quick check failed: %s", result)
	}
	return nil
}
