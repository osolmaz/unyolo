package state

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/osolmaz/brokerkit/internal/strictjson"
	sqlite "modernc.org/sqlite"
)

const (
	backupManifestFile = "manifest.json"
	backupFormat       = "brokerkit.io/state-backup/v1"
	exportFormat       = "brokerkit.io/state-export/v1"
	maxStateFileBytes  = int64(4 << 30)
	maxExportRows      = 100_000
)

// CheckReport is a secret-free state consistency result.
type CheckReport struct {
	Format        string `json:"format"`
	SchemaVersion int64  `json:"schema_version"`
	QuickCheck    string `json:"quick_check"`
	FullCheck     string `json:"full_check,omitempty"`
	DatabaseBytes int64  `json:"database_bytes"`
}

// BackupManifest authenticates one exact current-format SQLite snapshot.
type BackupManifest struct {
	Format        string    `json:"format"`
	SchemaVersion int64     `json:"schema_version"`
	DatabaseFile  string    `json:"database_file"`
	DatabaseBytes int64     `json:"database_bytes"`
	SHA256        string    `json:"sha256"`
	CreatedAt     time.Time `json:"created_at"`
}

type sqliteBackuper interface {
	NewBackup(string) (*sqlite.Backup, error)
}

// Check validates the current state format and optionally runs SQLite's full
// integrity check.
func (d *Database) Check(ctx context.Context, full bool) (CheckReport, error) {
	if err := d.ValidateCurrentFormat(ctx); err != nil {
		return CheckReport{}, err
	}
	report := CheckReport{Format: backupFormat, SchemaVersion: CurrentSchemaVersion, QuickCheck: "ok"}
	if full {
		result, err := d.IntegrityCheck(ctx)
		if err != nil {
			return CheckReport{}, fmt.Errorf("state integrity check failed: %w", err)
		}
		if result != "ok" {
			return CheckReport{}, fmt.Errorf("state integrity check failed: %s", result)
		}
		report.FullCheck = result
	}
	info, err := os.Stat(filepath.Join(d.directory, databaseFile))
	if err != nil {
		return CheckReport{}, err
	}
	report.DatabaseBytes = info.Size()
	return report, nil
}

// Backup creates an atomic consistent SQLite snapshot directory. The output
// directory must not already exist.
func (d *Database) Backup(ctx context.Context, destination string) (BackupManifest, error) {
	if err := d.ValidateCurrentFormat(ctx); err != nil {
		return BackupManifest{}, err
	}
	if err := validateMaintenanceDestination(d.directory, destination); err != nil {
		return BackupManifest{}, err
	}
	if _, err := os.Lstat(destination); !errors.Is(err, os.ErrNotExist) {
		return BackupManifest{}, errors.New("backup destination already exists or is unavailable")
	}
	parent := filepath.Dir(destination)
	temporary, err := os.MkdirTemp(parent, ".brokerkit-backup-")
	if err != nil {
		return BackupManifest{}, err
	}
	defer func() { _ = os.RemoveAll(temporary) }()
	if err := os.Chmod(temporary, 0o700); err != nil {
		return BackupManifest{}, err
	}
	snapshot := filepath.Join(temporary, databaseFile)
	if err := d.backupSQLite(ctx, snapshot); err != nil {
		return BackupManifest{}, err
	}
	manifest, err := validateSnapshot(ctx, snapshot)
	if err != nil {
		return BackupManifest{}, err
	}
	manifest.CreatedAt = time.Now().UTC()
	encoded, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return BackupManifest{}, err
	}
	encoded = append(encoded, '\n')
	if err := writeSyncedFile(filepath.Join(temporary, backupManifestFile), encoded, 0o600); err != nil {
		return BackupManifest{}, err
	}
	if err := syncDirectory(temporary); err != nil {
		return BackupManifest{}, err
	}
	if err := publishBackup(temporary, destination); err != nil {
		return BackupManifest{}, err
	}
	return manifest, nil
}

func publishBackup(staged, destination string) (resultErr error) {
	if err := os.Mkdir(destination, 0o700); err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			resultErr = errors.Join(resultErr, os.RemoveAll(destination))
		}
	}()
	for _, name := range []string{databaseFile, backupManifestFile} {
		if err := os.Link(filepath.Join(staged, name), filepath.Join(destination, name)); err != nil {
			return err
		}
	}
	if err := syncDirectory(destination); err != nil {
		return err
	}
	if err := syncDirectory(filepath.Dir(destination)); err != nil {
		return err
	}
	committed = true
	return nil
}

func (d *Database) backupSQLite(ctx context.Context, destination string) error {
	connection, err := d.sql.Conn(ctx)
	if err != nil {
		return err
	}
	defer connection.Close()
	err = connection.Raw(func(driverConnection any) error {
		backuper, ok := driverConnection.(sqliteBackuper)
		if !ok {
			return errors.New("SQLite online backup is unavailable")
		}
		backup, err := backuper.NewBackup(destination)
		if err != nil {
			return err
		}
		finished := false
		defer func() {
			if !finished {
				_ = backup.Finish()
			}
		}()
		for more := true; more; {
			if err := ctx.Err(); err != nil {
				return err
			}
			more, err = backup.Step(128)
			if err != nil {
				return err
			}
		}
		finished = true
		return backup.Finish()
	})
	if err != nil {
		return fmt.Errorf("back up state database: %w", err)
	}
	if err := os.Chmod(destination, 0o600); err != nil {
		return err
	}
	file, err := os.OpenFile(destination, os.O_RDONLY, 0) // #nosec G304 -- destination was created in our private temporary directory.
	if err != nil {
		return err
	}
	return errors.Join(file.Sync(), file.Close())
}

// Restore replaces an offline state database with a validated current-format
// snapshot. The existing database remains in place on validation failure.
func Restore(ctx context.Context, stateDirectory, backupDirectory string) error {
	if err := validateMaintenanceDestination(stateDirectory, backupDirectory); err != nil {
		return err
	}
	if err := ensurePrivateDirectory(stateDirectory); err != nil {
		return err
	}
	lease, err := acquireLease(filepath.Join(stateDirectory, leaseFile))
	if err != nil {
		return err
	}
	defer lease.close()
	snapshot, manifest, err := loadBackup(ctx, backupDirectory)
	if err != nil {
		return err
	}
	stage, err := copySnapshot(stateDirectory, snapshot, manifest.DatabaseBytes)
	if err != nil {
		return err
	}
	defer os.Remove(stage)
	if _, err := validateSnapshot(ctx, stage); err != nil {
		return err
	}
	return installRestoredDatabase(stateDirectory, stage)
}

func loadBackup(ctx context.Context, directory string) (string, BackupManifest, error) {
	if info, err := os.Lstat(directory); err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", BackupManifest{}, errors.New("backup directory is invalid")
	}
	data, err := os.ReadFile(filepath.Join(directory, backupManifestFile)) // #nosec G304 -- operator-selected backup directory.
	if err != nil || len(data) > 16*1024 {
		return "", BackupManifest{}, errors.New("backup manifest is unavailable or oversized")
	}
	if err := validatePrivateDatabaseFile(filepath.Join(directory, backupManifestFile)); err != nil {
		return "", BackupManifest{}, err
	}
	var manifest BackupManifest
	if err := strictjson.Decode(data, &manifest, true); err != nil || manifest.Format != backupFormat || manifest.SchemaVersion != CurrentSchemaVersion ||
		manifest.DatabaseFile != databaseFile || manifest.DatabaseBytes < 1 || manifest.DatabaseBytes > maxStateFileBytes || len(manifest.SHA256) != 64 {
		return "", BackupManifest{}, errors.New("backup manifest is invalid or unsupported")
	}
	snapshot := filepath.Join(directory, manifest.DatabaseFile)
	if err := validatePrivateDatabaseFile(snapshot); err != nil {
		return "", BackupManifest{}, err
	}
	digest, size, err := fileDigest(snapshot, maxStateFileBytes)
	if err != nil || size != manifest.DatabaseBytes || digest != manifest.SHA256 {
		return "", BackupManifest{}, errors.New("backup database checksum or size does not match its manifest")
	}
	validated, err := validateSnapshot(ctx, snapshot)
	if err != nil || validated.SHA256 != manifest.SHA256 || validated.DatabaseBytes != manifest.DatabaseBytes {
		return "", BackupManifest{}, errors.New("backup database validation failed")
	}
	return snapshot, manifest, nil
}

func validateSnapshot(ctx context.Context, path string) (BackupManifest, error) {
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > maxStateFileBytes {
		return BackupManifest{}, errors.New("state snapshot is invalid")
	}
	db, err := openReadOnlySQL(path)
	if err != nil {
		return BackupManifest{}, err
	}
	value := &Database{sql: db}
	err = value.ValidateCurrentFormat(ctx)
	if err == nil {
		var result string
		err = db.QueryRowContext(ctx, "PRAGMA integrity_check").Scan(&result)
		if err == nil && result != "ok" {
			err = errors.New("SQLite integrity check failed")
		}
	}
	closeErr := db.Close()
	if err != nil || closeErr != nil {
		return BackupManifest{}, errors.Join(err, closeErr)
	}
	digest, size, err := fileDigest(path, maxStateFileBytes)
	if err != nil {
		return BackupManifest{}, err
	}
	return BackupManifest{Format: backupFormat, SchemaVersion: CurrentSchemaVersion, DatabaseFile: databaseFile,
		DatabaseBytes: size, SHA256: digest}, nil
}

func openReadOnlySQL(path string) (*sql.DB, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	values := url.Values{"mode": {"ro"}, "immutable": {"1"}}
	values.Add("_pragma", "foreign_keys(1)")
	values.Add("_pragma", "query_only(1)")
	values.Add("_pragma", "busy_timeout(1000)")
	dsn := (&url.URL{Scheme: "file", Path: filepath.ToSlash(absolute), RawQuery: values.Encode()}).String()
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	return db, nil
}

func copySnapshot(directory, source string, expectedSize int64) (string, error) {
	input, err := os.Open(source) // #nosec G304 -- validated backup snapshot.
	if err != nil {
		return "", err
	}
	defer input.Close()
	output, err := os.CreateTemp(directory, ".state-restore-*.db")
	if err != nil {
		return "", err
	}
	path := output.Name()
	remove := true
	defer func() {
		_ = output.Close()
		if remove {
			_ = os.Remove(path)
		}
	}()
	if err := output.Chmod(0o600); err != nil {
		return "", err
	}
	written, err := io.Copy(output, io.LimitReader(input, expectedSize+1))
	if err != nil || written != expectedSize {
		return "", errors.New("backup snapshot changed while it was copied")
	}
	if err := output.Sync(); err != nil {
		return "", err
	}
	if err := output.Close(); err != nil {
		return "", err
	}
	remove = false
	return path, nil
}

func installRestoredDatabase(directory, stage string) error {
	destination := filepath.Join(directory, databaseFile)
	rollback := filepath.Join(directory, ".state-rollback.db")
	if _, err := os.Lstat(rollback); err == nil {
		return errors.New("stale state restore rollback file exists")
	}
	hadExisting := false
	if _, err := os.Lstat(destination); err == nil {
		if err := validatePrivateDatabaseFile(destination); err != nil {
			return err
		}
		if err := checkpointDatabase(destination); err != nil {
			return err
		}
		if err := os.Rename(destination, rollback); err != nil {
			return err
		}
		hadExisting = true
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.Rename(stage, destination); err != nil {
		if hadExisting {
			_ = os.Rename(rollback, destination)
		}
		return err
	}
	for _, suffix := range []string{"-wal", "-shm"} {
		_ = os.Remove(destination + suffix)
	}
	if err := syncDirectory(directory); err != nil {
		_ = os.Remove(destination)
		if hadExisting {
			_ = os.Rename(rollback, destination)
			_ = syncDirectory(directory)
		}
		return err
	}
	if hadExisting {
		if err := os.Remove(rollback); err != nil {
			return err
		}
		return syncDirectory(directory)
	}
	return nil
}

func checkpointDatabase(path string) error {
	db, err := openSQL(path, Options{BusyTimeout: time.Second})
	if err != nil {
		return err
	}
	_, checkpointErr := db.Exec("PRAGMA wal_checkpoint(TRUNCATE)")
	return errors.Join(checkpointErr, db.Close())
}

func ensurePrivateDirectory(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("state directory must be an absolute clean path")
	}
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return errors.New("state directory must be private and cannot be a symlink")
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); ok && stat.Uid != uint32(os.Geteuid()) { // #nosec G115 -- effective UIDs are non-negative.
		return errors.New("state directory must be owned by the current user")
	}
	return nil
}

func validateMaintenanceDestination(stateDirectory, destination string) error {
	if !filepath.IsAbs(stateDirectory) || filepath.Clean(stateDirectory) != stateDirectory ||
		!filepath.IsAbs(destination) || filepath.Clean(destination) != destination {
		return errors.New("state and destination paths must be absolute and clean")
	}
	statePrefix := stateDirectory + string(os.PathSeparator)
	if destination == stateDirectory || strings.HasPrefix(destination, statePrefix) {
		return errors.New("maintenance destination cannot be inside the live state directory")
	}
	return nil
}

func fileDigest(path string, limit int64) (string, int64, error) {
	file, err := os.Open(path) // #nosec G304 -- caller validated the maintenance path.
	if err != nil {
		return "", 0, err
	}
	defer file.Close()
	hash := sha256.New()
	size, err := io.Copy(hash, io.LimitReader(file, limit+1))
	if err != nil || size > limit {
		return "", size, errors.New("state file is unreadable or oversized")
	}
	return hex.EncodeToString(hash.Sum(nil)), size, nil
}

func writeSyncedFile(path string, data []byte, mode os.FileMode) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode) // #nosec G304 -- private maintenance output path.
	if err != nil {
		return err
	}
	_, writeErr := file.Write(data)
	return errors.Join(writeErr, file.Sync(), file.Close())
}

func syncDirectory(path string) error {
	directory, err := os.Open(path) // #nosec G304 -- operator-selected maintenance directory.
	if err != nil {
		return err
	}
	return errors.Join(directory.Sync(), directory.Close())
}
