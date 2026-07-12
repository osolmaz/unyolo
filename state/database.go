// Package state owns BrokerKit's local transactional database and process lease.
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
	"time"

	"github.com/osolmaz/brokerkit/state/internal/dbsql"
	"github.com/pressly/goose/v3"
	_ "modernc.org/sqlite"
)

const (
	databaseFile = "state.db"
	leaseFile    = "state.lock"
)

//go:embed migrations/*.sql
var migrationFiles embed.FS

type Options struct {
	BusyTimeout time.Duration
}

type Database struct {
	sql     *sql.DB
	queries *dbsql.Queries
	lease   *lease
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
	db, err := openSQL(filepath.Join(directory, databaseFile), options)
	if err != nil {
		_ = lock.close()
		return nil, err
	}
	result := &Database{sql: db, queries: dbsql.New(db), lease: lock}
	if err := result.migrate(ctx); err != nil {
		_ = result.Close()
		return nil, err
	}
	if _, err := result.queries.Health(ctx); err != nil {
		_ = result.Close()
		return nil, fmt.Errorf("check state database: %w", err)
	}
	return result, nil
}

func openSQL(path string, options Options) (*sql.DB, error) {
	values := url.Values{}
	for _, pragma := range []string{
		"foreign_keys(1)",
		"journal_mode(WAL)",
		fmt.Sprintf("busy_timeout(%d)", options.BusyTimeout.Milliseconds()),
		"synchronous(FULL)",
	} {
		values.Add("_pragma", pragma)
	}
	dsn := (&url.URL{Scheme: "file", Path: filepath.ToSlash(path), RawQuery: values.Encode()}).String()
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
	var errs []error
	if d.sql != nil {
		errs = append(errs, d.sql.Close())
	}
	if d.lease != nil {
		errs = append(errs, d.lease.close())
	}
	return errors.Join(errs...)
}

func (d *Database) SQL() *sql.DB { return d.sql }

func (d *Database) Queries() *dbsql.Queries { return d.queries }

// IntegrityCheck runs SQLite's operational consistency check. PRAGMA queries
// are intentionally kept outside sqlc because sqlc does not generate them.
func (d *Database) IntegrityCheck(ctx context.Context) (string, error) {
	var result string
	err := d.sql.QueryRowContext(ctx, "PRAGMA integrity_check").Scan(&result)
	return result, err
}
