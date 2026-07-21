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
	"time"

	"github.com/osolmaz/brokerkit/internal/fsx"
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
	temporary, err := createBackupStage(d.directory, destination)
	if err != nil {
		return BackupManifest{}, err
	}
	defer func() { _ = os.RemoveAll(temporary) }()
	return d.writeBackupFromStage(ctx, temporary, destination)
}

func (d *Database) writeBackupFromStage(ctx context.Context, temporary, destination string) (BackupManifest, error) {
	snapshot := filepath.Join(temporary, databaseFile)
	if err := d.backupSQLite(ctx, snapshot); err != nil {
		return BackupManifest{}, err
	}
	manifest, err := validateSnapshot(ctx, snapshot)
	if err != nil {
		return BackupManifest{}, err
	}
	manifest.CreatedAt = time.Now().UTC()
	if err := writeBackupManifest(temporary, manifest); err != nil {
		return BackupManifest{}, err
	}
	if err := publishBackup(temporary, destination); err != nil {
		return BackupManifest{}, err
	}
	return manifest, nil
}

func writeBackupManifest(temporary string, manifest BackupManifest) error {
	encoded, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	if err := writeSyncedFile(filepath.Join(temporary, backupManifestFile), encoded, 0o600); err != nil {
		return err
	}
	return syncDirectory(temporary)
}

func createBackupStage(stateDirectory, destination string) (string, error) {
	if err := validateMaintenanceDestination(stateDirectory, destination); err != nil {
		return "", err
	}
	if _, err := os.Lstat(destination); !errors.Is(err, os.ErrNotExist) {
		return "", errors.New("backup destination already exists or is unavailable")
	}
	temporary, err := os.MkdirTemp(filepath.Dir(destination), ".brokerkit-backup-")
	if err != nil {
		return "", err
	}
	if err := os.Chmod(temporary, 0o700); err != nil { // #nosec G302 -- this is a private directory and requires execute bits.
		_ = os.RemoveAll(temporary)
		return "", err
	}
	return temporary, nil
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
	if err := linkBackupFiles(staged, destination); err != nil {
		return err
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

func linkBackupFiles(staged, destination string) error {
	for _, name := range []string{databaseFile, backupManifestFile} {
		if err := os.Link(filepath.Join(staged, name), filepath.Join(destination, name)); err != nil {
			return err
		}
	}
	return nil
}

func (d *Database) backupSQLite(ctx context.Context, destination string) error {
	connection, err := d.sql.Conn(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = connection.Close() }()
	err = connection.Raw(func(driverConnection any) error { return runSQLiteBackup(ctx, driverConnection, destination) })
	if err != nil {
		return fmt.Errorf("back up state database: %w", err)
	}
	return syncBackupSnapshot(destination)
}

func runSQLiteBackup(ctx context.Context, driverConnection any, destination string) error {
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
	if err := stepSQLiteBackup(ctx, backup); err != nil {
		return err
	}
	finished = true
	return backup.Finish()
}

func stepSQLiteBackup(ctx context.Context, backup *sqlite.Backup) error {
	for more := true; more; {
		if err := ctx.Err(); err != nil {
			return err
		}
		next, err := backup.Step(128)
		if err != nil {
			return err
		}
		more = next
	}
	return nil
}

func syncBackupSnapshot(destination string) error {
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
	defer func() { _ = lease.close() }()
	snapshot, manifest, err := loadBackup(ctx, backupDirectory)
	if err != nil {
		return err
	}
	stage, err := copySnapshot(stateDirectory, snapshot, manifest.DatabaseBytes)
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(stage) }()
	if _, err := validateSnapshot(ctx, stage); err != nil {
		return err
	}
	return installRestoredDatabase(stateDirectory, stage)
}

func loadBackup(ctx context.Context, directory string) (string, BackupManifest, error) {
	manifest, err := readBackupManifest(directory)
	if err != nil {
		return "", BackupManifest{}, err
	}
	snapshot := filepath.Join(directory, manifest.DatabaseFile)
	if err := validateBackupSnapshotFile(snapshot, manifest); err != nil {
		return "", BackupManifest{}, err
	}
	if err := validateBackupSnapshotContents(ctx, snapshot, manifest); err != nil {
		return "", BackupManifest{}, err
	}
	return snapshot, manifest, nil
}

func readBackupManifest(directory string) (BackupManifest, error) {
	if err := validateBackupDirectory(directory); err != nil {
		return BackupManifest{}, err
	}
	manifestPath := filepath.Join(directory, backupManifestFile)
	if err := validatePrivateDatabaseFile(manifestPath); err != nil {
		return BackupManifest{}, err
	}
	data, err := readBackupManifestFile(manifestPath)
	if err != nil {
		return BackupManifest{}, err
	}
	return decodeBackupManifest(data)
}

func validateBackupDirectory(directory string) error {
	if info, err := os.Lstat(directory); err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("backup directory is invalid")
	}
	return nil
}

func readBackupManifestFile(path string) ([]byte, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- operator-selected backup directory.
	if err != nil || len(data) > 16*1024 {
		return nil, errors.New("backup manifest is unavailable or oversized")
	}
	return data, nil
}

func decodeBackupManifest(data []byte) (BackupManifest, error) {
	var manifest BackupManifest
	if err := strictjson.Decode(data, &manifest, true); err != nil || invalidBackupManifest(manifest) {
		return BackupManifest{}, errors.New("backup manifest is invalid or unsupported")
	}
	return manifest, nil
}

func invalidBackupManifest(manifest BackupManifest) bool {
	return manifest.Format != backupFormat || manifest.SchemaVersion != CurrentSchemaVersion ||
		manifest.DatabaseFile != databaseFile || manifest.DatabaseBytes < 1 ||
		manifest.DatabaseBytes > maxStateFileBytes || len(manifest.SHA256) != 64
}

func validateBackupSnapshotFile(snapshot string, manifest BackupManifest) error {
	if err := validatePrivateDatabaseFile(snapshot); err != nil {
		return err
	}
	digest, size, err := fileDigest(snapshot, maxStateFileBytes)
	if err != nil || size != manifest.DatabaseBytes || digest != manifest.SHA256 {
		return errors.New("backup database checksum or size does not match its manifest")
	}
	return nil
}

func validateBackupSnapshotContents(ctx context.Context, snapshot string, manifest BackupManifest) error {
	validated, err := validateSnapshot(ctx, snapshot)
	if err != nil || validated.SHA256 != manifest.SHA256 || validated.DatabaseBytes != manifest.DatabaseBytes {
		return errors.New("backup database validation failed")
	}
	return nil
}

func validateSnapshot(ctx context.Context, path string) (BackupManifest, error) {
	info, err := os.Stat(path)
	if invalidSnapshotInfo(info, err) {
		return BackupManifest{}, errors.New("state snapshot is invalid")
	}
	if err := validateSnapshotDatabase(ctx, path); err != nil {
		return BackupManifest{}, err
	}
	digest, size, err := fileDigest(path, maxStateFileBytes)
	if err != nil {
		return BackupManifest{}, err
	}
	return BackupManifest{Format: backupFormat, SchemaVersion: CurrentSchemaVersion, DatabaseFile: databaseFile,
		DatabaseBytes: size, SHA256: digest}, nil
}

func invalidSnapshotInfo(info os.FileInfo, err error) bool {
	return err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > maxStateFileBytes
}

func validateSnapshotDatabase(ctx context.Context, path string) error {
	db, err := openReadOnlySQL(path)
	if err != nil {
		return err
	}
	value := &Database{sql: db}
	err = value.ValidateCurrentFormat(ctx)
	if err == nil {
		err = validateSQLiteIntegrity(ctx, db)
	}
	closeErr := db.Close()
	if err != nil || closeErr != nil {
		return errors.Join(err, closeErr)
	}
	return nil
}

func validateSQLiteIntegrity(ctx context.Context, db *sql.DB) error {
	var result string
	err := db.QueryRowContext(ctx, "PRAGMA integrity_check").Scan(&result)
	if err != nil {
		return err
	}
	if result != "ok" {
		return errors.New("SQLite integrity check failed")
	}
	return nil
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
	defer func() { _ = input.Close() }()
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
	if err := copySnapshotData(output, input, expectedSize); err != nil {
		return "", err
	}
	remove = false
	return path, nil
}

func copySnapshotData(output io.WriteCloser, input io.Reader, expectedSize int64) error {
	written, err := io.Copy(output, io.LimitReader(input, expectedSize+1))
	if err != nil || written != expectedSize {
		return errors.New("backup snapshot changed while it was copied")
	}
	file, ok := output.(*os.File)
	if ok {
		if err := file.Sync(); err != nil {
			return err
		}
	}
	return output.Close()
}

func installRestoredDatabase(directory, stage string) error {
	destination := filepath.Join(directory, databaseFile)
	rollback := filepath.Join(directory, ".state-rollback.db")
	if _, err := os.Lstat(rollback); err == nil {
		return errors.New("stale state restore rollback file exists")
	}
	hadExisting, err := prepareOptionalDatabaseRollback(destination, rollback)
	if err != nil {
		return err
	}
	return publishRestoredDatabase(directory, destination, rollback, stage, hadExisting)
}

func prepareOptionalDatabaseRollback(destination, rollback string) (bool, error) {
	if _, err := os.Lstat(destination); errors.Is(err, os.ErrNotExist) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	return true, prepareDatabaseRollback(destination, rollback)
}

func publishRestoredDatabase(directory, destination, rollback, stage string, hadExisting bool) error {
	if err := os.Rename(stage, destination); err != nil {
		restoreRollback(destination, rollback, hadExisting)
		return err
	}
	removeSQLiteSidecars(destination)
	if err := syncDirectory(directory); err != nil {
		restoreRollback(destination, rollback, hadExisting)
		return err
	}
	return removeRollback(directory, rollback, hadExisting)
}

func prepareDatabaseRollback(destination, rollback string) error {
	if err := validatePrivateDatabaseFile(destination); err != nil {
		return err
	}
	if err := checkpointDatabase(destination); err != nil {
		return err
	}
	return os.Rename(destination, rollback)
}

func restoreRollback(destination, rollback string, hadExisting bool) {
	_ = os.Remove(destination)
	if hadExisting {
		_ = os.Rename(rollback, destination)
		_ = syncDirectory(filepath.Dir(destination))
	}
}

func removeSQLiteSidecars(destination string) {
	for _, suffix := range []string{"-wal", "-shm"} {
		_ = os.Remove(destination + suffix)
	}
}

func removeRollback(directory, rollback string, hadExisting bool) error {
	if !hadExisting {
		return nil
	}
	if err := os.Remove(rollback); err != nil {
		return err
	}
	return syncDirectory(directory)
}

func checkpointDatabase(path string) error {
	db, err := openSQL(path, Options{BusyTimeout: time.Second})
	if err != nil {
		return err
	}
	_, checkpointErr := db.ExecContext(context.Background(), "PRAGMA wal_checkpoint(TRUNCATE)")
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
	if err := validatePrivateDirectoryInfo(info, err); err != nil {
		return err
	}
	return validatePrivateDirectoryOwner(info)
}

func validatePrivateDirectoryInfo(info os.FileInfo, err error) error {
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return errors.New("state directory must be private and cannot be a symlink")
	}
	return nil
}

func validatePrivateDirectoryOwner(info os.FileInfo) error {
	return validateCurrentUserOwner(info, "state directory")
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
	defer func() { _ = file.Close() }()
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

func syncDirectory(path string) error { return fsx.SyncDirectory(path) }
