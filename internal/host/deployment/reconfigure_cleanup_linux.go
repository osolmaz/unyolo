//go:build linux

package deployment

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/osolmaz/unyolo/deployment/api"
	componentprofile "github.com/osolmaz/unyolo/deployment/component"
	"github.com/osolmaz/unyolo/internal/securefile"
	"github.com/osolmaz/unyolo/internal/strictjson"
	"golang.org/x/sys/unix"
)

type staleClientMetadata struct {
	Original    string `json:"original"`
	Backup      string `json:"backup,omitempty"`
	Fingerprint string `json:"fingerprint"`
	Missing     bool   `json:"missing,omitempty"`
}

func staleClientHandle(resource ResourceReceipt) string {
	return strings.TrimPrefix(resourceReceiptKey(resource), "sha256:")
}

func (engine *Engine) quarantineStaleClient(_ context.Context, resource ResourceReceipt) (string, error) {
	handle := staleClientHandle(resource)
	metadataPath, err := cleanupMetadataPath(engine.options.Paths.StateDir, handle)
	if err != nil {
		return "", err
	}
	if err := ensureCleanupDirectory(filepath.Dir(metadataPath)); err != nil {
		return "", err
	}
	actual := componentprofile.ResourceFingerprint(context.Background(), api.Resource{Kind: "client", ID: resource.ID, Path: resource.Path}, true)
	metadata := staleClientMetadata{Original: resource.Path, Fingerprint: resource.Fingerprint, Missing: actual == "missing"}
	if metadata.Missing {
		if err := writeStaleClientMetadata(metadataPath, metadata); err != nil {
			return "", err
		}
		return handle, nil
	}
	if actual != resource.Fingerprint {
		return "", errors.New("generated client configuration changed before removal")
	}
	metadata.Backup = filepath.Join(filepath.Dir(resource.Path), ".unyolo-remove-"+handle)
	if err := renameRegularNoFollow(resource.Path, metadata.Backup); err != nil {
		return "", err
	}
	if err := writeStaleClientMetadata(metadataPath, metadata); err != nil {
		if restoreErr := renameRegularNoFollow(metadata.Backup, resource.Path); restoreErr != nil {
			return "", errors.Join(err, restoreErr)
		}
		return "", err
	}
	return handle, nil
}

func (engine *Engine) restoreStaleClient(_ context.Context, handle string) error {
	metadataPath, err := cleanupMetadataPath(engine.options.Paths.StateDir, handle)
	if err != nil {
		return err
	}
	metadata, found, err := readStaleClientMetadata(metadataPath, handle)
	if err != nil || !found {
		return err
	}
	if metadata.Missing {
		return removeCleanupMetadata(metadataPath)
	}
	actual := componentprofile.ResourceFingerprint(context.Background(), api.Resource{Kind: "client", ID: "backup", Path: metadata.Backup}, true)
	if actual != metadata.Fingerprint {
		return errors.New("quarantined client configuration changed before rollback")
	}
	if _, err := os.Lstat(metadata.Original); err == nil {
		return errors.New("client configuration path changed before rollback")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := renameRegularNoFollow(metadata.Backup, metadata.Original); err != nil {
		return err
	}
	return removeCleanupMetadata(metadataPath)
}

func (engine *Engine) discardStaleClientBackup(handle string) error {
	metadataPath, err := cleanupMetadataPath(engine.options.Paths.StateDir, handle)
	if err != nil {
		return err
	}
	metadata, found, err := readStaleClientMetadata(metadataPath, handle)
	if err != nil || !found {
		return err
	}
	if !metadata.Missing {
		if err := unlinkRegularNoFollow(metadata.Backup); err != nil {
			return err
		}
	}
	return removeCleanupMetadata(metadataPath)
}

func ensureCleanupDirectory(path string) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return errors.New("stale client cleanup directory is unsafe")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != os.Geteuid() {
		return errors.New("stale client cleanup directory is not root-owned")
	}
	return nil
}

func writeStaleClientMetadata(path string, value staleClientMetadata) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return securefile.AtomicWrite(path, append(data, '\n'), 0o600, "stale client cleanup metadata")
}

func readStaleClientMetadata(path, handle string) (staleClientMetadata, bool, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- path is derived from a validated cleanup handle.
	if errors.Is(err, os.ErrNotExist) {
		return staleClientMetadata{}, false, nil
	}
	if err != nil {
		return staleClientMetadata{}, false, err
	}
	var value staleClientMetadata
	if err := strictjson.Decode(data, &value, true); err != nil {
		return staleClientMetadata{}, false, err
	}
	if !filepath.IsAbs(value.Original) || filepath.Clean(value.Original) != value.Original || !receiptDigestPattern.MatchString(value.Fingerprint) {
		return staleClientMetadata{}, false, errors.New("stale client cleanup metadata is invalid")
	}
	expectedBackup := filepath.Join(filepath.Dir(value.Original), ".unyolo-remove-"+handle)
	if value.Missing {
		if value.Backup != "" {
			return staleClientMetadata{}, false, errors.New("missing stale client cleanup has a backup")
		}
	} else if value.Backup != expectedBackup {
		return staleClientMetadata{}, false, errors.New("stale client cleanup backup is invalid")
	}
	return value, true, nil
}

func removeCleanupMetadata(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func renameRegularNoFollow(source, destination string) error {
	if !filepath.IsAbs(source) || filepath.Clean(source) != source || filepath.Dir(source) != filepath.Dir(destination) || filepath.Clean(destination) != destination {
		return errors.New("stale client cleanup path is invalid")
	}
	parent, err := openCleanupDirectoryNoFollow(filepath.Dir(source))
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(parent) }()
	var stat unix.Stat_t
	if err := unix.Fstatat(parent, filepath.Base(source), &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG {
		return errors.New("stale client configuration is not a regular file")
	}
	if err := unix.Renameat2(parent, filepath.Base(source), parent, filepath.Base(destination), unix.RENAME_NOREPLACE); err != nil {
		return fmt.Errorf("quarantine stale client configuration: %w", err)
	}
	return nil
}

func unlinkRegularNoFollow(path string) error {
	parent, err := openCleanupDirectoryNoFollow(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(parent) }()
	var stat unix.Stat_t
	if err := unix.Fstatat(parent, filepath.Base(path), &stat, unix.AT_SYMLINK_NOFOLLOW); errors.Is(err, syscall.ENOENT) {
		return nil
	} else if err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG {
		return errors.New("stale client backup is not a regular file")
	}
	return unix.Unlinkat(parent, filepath.Base(path), 0)
}

func openCleanupDirectoryNoFollow(path string) (int, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return -1, errors.New("stale client parent path is invalid")
	}
	fd, err := unix.Open(string(filepath.Separator), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return -1, err
	}
	for _, part := range strings.Split(strings.TrimPrefix(path, string(filepath.Separator)), string(filepath.Separator)) {
		if part == "" {
			continue
		}
		next, openErr := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		_ = unix.Close(fd)
		if openErr != nil {
			return -1, openErr
		}
		fd = next
	}
	return fd, nil
}
