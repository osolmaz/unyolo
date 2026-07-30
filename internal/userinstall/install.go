// Package userinstall atomically activates a verified staged unYOLO CLI release.
package userinstall

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/osolmaz/unyolo/deployment/provider"
	"github.com/osolmaz/unyolo/internal/strictjson"
)

const (
	ManifestAPIVersion = "unyolo.io/user-install/v1"
	StageAPIVersion    = "unyolo.io/bootstrap-stage/v1"
)

var (
	releasePattern    = regexp.MustCompile(`^unyolo/(v[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?)$`)
	commitPattern     = regexp.MustCompile(`^[0-9a-f]{40}$`)
	digestPattern     = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	repositoryPattern = regexp.MustCompile(`^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$`)
)

// StageRecord binds staged files to the release verified by the bootstrap.
type StageRecord struct {
	APIVersion    string      `json:"api_version"`
	Release       string      `json:"release"`
	SourceCommit  string      `json:"source_commit"`
	ArchiveSHA256 string      `json:"archive_sha256"`
	Attestation   Attestation `json:"attestation"`
}

// Attestation records the GitHub identity used to verify the staged archive.
type Attestation struct {
	Repository string `json:"repository"`
	Workflow   string `json:"workflow"`
	SourceRef  string `json:"source_ref"`
}

// File records one activated release file.
type File struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

// Manifest records one complete user-level activation.
type Manifest struct {
	APIVersion    string      `json:"api_version"`
	Release       string      `json:"release"`
	SourceCommit  string      `json:"source_commit"`
	ArchiveSHA256 string      `json:"archive_sha256"`
	Attestation   Attestation `json:"attestation"`
	Files         []File      `json:"files"`
	InstalledAt   time.Time   `json:"installed_at"`
}

// Options configures one activation. DataHome and BinHome default to the invoking user's XDG paths.
type Options struct {
	StageRoot string
	DataHome  string
	BinHome   string
	Now       func() time.Time
}

// Activate verifies the staged release, prepares an immutable version directory, and switches one current link.
func Activate(ctx context.Context, options Options) error {
	normalized, record, version, err := validateOptions(options)
	if err != nil {
		return err
	}
	files := []struct {
		source string
		name   string
		mode   os.FileMode
	}{
		{filepath.Join(normalized.StageRoot, "bin", "unyolo"), "unyolo", 0o755},
		{filepath.Join(normalized.StageRoot, "libexec", "openclaw-unyolo-setup"), "openclaw-unyolo-setup", 0o755},
	}
	providerOptions, err := provider.LoadDirectory(filepath.Join(normalized.StageRoot, "share", "providers"))
	if err != nil {
		return err
	}
	for _, option := range providerOptions {
		files = append(files, struct {
			source string
			name   string
			mode   os.FileMode
		}{
			source: filepath.Join(normalized.StageRoot, "share", "providers", option.ID+".json"),
			name:   filepath.Join("providers", option.ID+".json"), mode: 0o644,
		})
	}
	manifest := Manifest{
		APIVersion: ManifestAPIVersion, Release: record.Release, SourceCommit: record.SourceCommit,
		ArchiveSHA256: record.ArchiveSHA256, Attestation: record.Attestation, InstalledAt: normalized.Now().UTC(),
	}
	for _, file := range files {
		digest, err := verifySourceFile(file.source)
		if err != nil {
			return err
		}
		manifest.Files = append(manifest.Files, File{Path: file.name, SHA256: digest})
	}
	if err := verifyStagedVersion(ctx, files[0].source, version); err != nil {
		return err
	}

	if err := ensureOwnedDirectory(normalized.DataHome, 0o755); err != nil {
		return fmt.Errorf("prepare user data directory: %w", err)
	}
	root := filepath.Join(normalized.DataHome, "unyolo")
	releases := filepath.Join(root, "releases")
	if err := ensureOwnedDirectory(releases, 0o700); err != nil {
		return fmt.Errorf("prepare user release directory: %w", err)
	}
	final := filepath.Join(releases, version)
	if err := prepareRelease(final, releases, files, manifest); err != nil {
		return err
	}
	if err := ensureOwnedDirectory(normalized.BinHome, 0o755); err != nil {
		return fmt.Errorf("prepare user binary directory: %w", err)
	}
	return switchActive(root, normalized.BinHome, version)
}

func validateOptions(options Options) (Options, StageRecord, string, error) {
	if options.Now == nil {
		options.Now = time.Now
	}
	if !filepath.IsAbs(options.StageRoot) || filepath.Clean(options.StageRoot) != options.StageRoot {
		return Options{}, StageRecord{}, "", errors.New("bootstrap stage must be an absolute clean path")
	}
	if err := verifyOwnedDirectory(options.StageRoot); err != nil {
		return Options{}, StageRecord{}, "", fmt.Errorf("inspect bootstrap stage: %w", err)
	}
	if options.DataHome == "" {
		if configured := os.Getenv("XDG_DATA_HOME"); configured != "" {
			options.DataHome = configured
		} else {
			home, err := os.UserHomeDir()
			if err != nil {
				return Options{}, StageRecord{}, "", err
			}
			options.DataHome = filepath.Join(home, ".local", "share")
		}
	}
	if options.BinHome == "" {
		if configured := os.Getenv("XDG_BIN_HOME"); configured != "" {
			options.BinHome = configured
		} else {
			home, err := os.UserHomeDir()
			if err != nil {
				return Options{}, StageRecord{}, "", err
			}
			options.BinHome = filepath.Join(home, ".local", "bin")
		}
	}
	for _, path := range []string{options.DataHome, options.BinHome} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return Options{}, StageRecord{}, "", errors.New("user installation roots must be absolute and clean")
		}
	}
	recordPath := filepath.Join(options.StageRoot, "stage.json")
	if _, err := verifySourceFile(recordPath); err != nil {
		return Options{}, StageRecord{}, "", fmt.Errorf("inspect bootstrap stage record: %w", err)
	}
	data, err := os.ReadFile(recordPath) // #nosec G304 -- fixed regular file below the validated private stage.
	if err != nil {
		return Options{}, StageRecord{}, "", fmt.Errorf("read bootstrap stage record: %w", err)
	}
	if len(data) > 16*1024 {
		return Options{}, StageRecord{}, "", errors.New("bootstrap stage record exceeds size limit")
	}
	var record StageRecord
	if err := strictjson.Decode(data, &record, true); err != nil {
		return Options{}, StageRecord{}, "", fmt.Errorf("decode bootstrap stage record: %w", err)
	}
	match := releasePattern.FindStringSubmatch(record.Release)
	if record.APIVersion != StageAPIVersion || len(match) != 2 || !commitPattern.MatchString(record.SourceCommit) || !digestPattern.MatchString(record.ArchiveSHA256) || !validAttestation(record) {
		return Options{}, StageRecord{}, "", errors.New("bootstrap stage record is invalid")
	}
	return options, record, match[1], nil
}

func validAttestation(record StageRecord) bool {
	attestation := record.Attestation
	return repositoryPattern.MatchString(attestation.Repository) && attestation.Workflow == attestation.Repository+"/.github/workflows/release.yml" &&
		attestation.SourceRef == "refs/tags/"+record.Release
}

func verifyStagedVersion(ctx context.Context, binary, version string) error {
	command := exec.CommandContext(ctx, binary, "--version") // #nosec G204 -- binary is the fixed staged CLI path.
	output, err := command.Output()
	if err != nil {
		return fmt.Errorf("run staged CLI version check: %w", err)
	}
	if strings.TrimSpace(string(output)) != version {
		return errors.New("staged CLI version does not match the verified release")
	}
	return nil
}

func verifySourceFile(path string) (string, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() < 1 {
		return "", errors.New("staged release contains an invalid file")
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); !ok || int(stat.Uid) != os.Geteuid() {
		return "", errors.New("staged release file is not owned by the invoking user")
	}
	file, err := os.Open(path) // #nosec G304 -- validated fixed staged file.
	if err != nil {
		return "", err
	}
	hash := sha256.New()
	_, copyErr := io.Copy(hash, file)
	closeErr := file.Close()
	if copyErr != nil || closeErr != nil {
		return "", errors.Join(copyErr, closeErr)
	}
	return fmt.Sprintf("sha256:%x", hash.Sum(nil)), nil
}

func prepareRelease(final, releases string, files []struct {
	source string
	name   string
	mode   os.FileMode
}, manifest Manifest) error {
	if _, err := os.Lstat(final); err == nil {
		return verifyExistingRelease(final, manifest)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	staging, err := os.MkdirTemp(releases, ".release-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(staging) }()
	if err := os.Chmod(staging, 0o700); err != nil {
		return err
	}
	for _, file := range files {
		if err := copyRegular(file.source, filepath.Join(staging, file.name), file.mode); err != nil {
			return err
		}
	}
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if err := os.WriteFile(filepath.Join(staging, "manifest.json"), data, 0o600); err != nil {
		return err
	}
	if err := syncDirectory(staging); err != nil {
		return err
	}
	if err := os.Rename(staging, final); err != nil {
		return err
	}
	return syncDirectory(releases)
}

func verifyExistingRelease(root string, expected Manifest) error {
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("existing user release is invalid")
	}
	data, err := os.ReadFile(filepath.Join(root, "manifest.json")) // #nosec G304 -- fixed path in a validated release directory.
	if err != nil {
		return err
	}
	var existing Manifest
	if err := strictjson.Decode(data, &existing, true); err != nil {
		return err
	}
	if existing.APIVersion != ManifestAPIVersion || existing.Release != expected.Release || existing.SourceCommit != expected.SourceCommit || existing.ArchiveSHA256 != expected.ArchiveSHA256 || existing.Attestation != expected.Attestation || len(existing.Files) != len(expected.Files) {
		return errors.New("existing user release does not match the verified stage")
	}
	for index, file := range expected.Files {
		if existing.Files[index] != file {
			return errors.New("existing user release manifest does not match the verified stage")
		}
		digest, err := verifySourceFile(filepath.Join(root, file.Path))
		if err != nil || digest != file.SHA256 {
			return errors.New("existing user release file does not match its manifest")
		}
	}
	return nil
}

func copyRegular(source, destination string, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
		return err
	}
	input, err := os.Open(source) // #nosec G304 -- source passed from fixed verified stage entries.
	if err != nil {
		return err
	}
	defer func() { _ = input.Close() }()
	output, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode) // #nosec G304 -- destination is a new private release directory.
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(output, input)
	syncErr := output.Sync()
	closeErr := output.Close()
	return errors.Join(copyErr, syncErr, closeErr)
}

func switchActive(root, binHome, version string) error {
	current := filepath.Join(root, "current")
	currentTemp := filepath.Join(root, fmt.Sprintf(".current-%d", os.Getpid()))
	_ = os.Remove(currentTemp)
	defer func() { _ = os.Remove(currentTemp) }()
	if err := os.Symlink(filepath.Join("releases", version), currentTemp); err != nil {
		return err
	}
	binPath := filepath.Join(binHome, "unyolo")
	binTemp := filepath.Join(binHome, fmt.Sprintf(".unyolo-%d", os.Getpid()))
	_ = os.Remove(binTemp)
	defer func() { _ = os.Remove(binTemp) }()
	target, err := filepath.Rel(binHome, filepath.Join(current, "unyolo"))
	if err != nil {
		return err
	}
	if err := os.Symlink(target, binTemp); err != nil {
		return err
	}
	oldTarget, oldErr := os.Readlink(current)
	if err := os.Rename(currentTemp, current); err != nil {
		_ = os.Remove(binTemp)
		return err
	}
	if err := os.Rename(binTemp, binPath); err != nil {
		if oldErr == nil {
			rollback := currentTemp + ".rollback"
			if linkErr := os.Symlink(oldTarget, rollback); linkErr == nil {
				_ = os.Rename(rollback, current)
			}
		} else {
			_ = os.Remove(current)
		}
		return err
	}
	return errors.Join(syncDirectory(root), syncDirectory(binHome))
}

func ensureOwnedDirectory(path string, mode os.FileMode) error {
	if err := os.MkdirAll(path, mode); err != nil {
		return err
	}
	return verifyOwnedDirectory(path)
}

func verifyOwnedDirectory(path string) error {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || filepath.Clean(resolved) != filepath.Clean(path) {
		return errors.New("directory path must not contain symbolic links")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("directory must be real")
	}
	if info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("directory must not be group-writable (mode %04o)", info.Mode().Perm())
	}
	if runtime.GOOS != "windows" {
		if stat, ok := info.Sys().(*syscall.Stat_t); !ok || int(stat.Uid) != os.Geteuid() {
			return errors.New("directory must be owned by the invoking user")
		}
	}
	return nil
}

func syncDirectory(path string) error {
	directory, err := os.Open(path) // #nosec G304 -- caller supplies a validated installation directory.
	if err != nil {
		return err
	}
	return errors.Join(directory.Sync(), directory.Close())
}
