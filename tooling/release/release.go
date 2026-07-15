// Package release builds reproducible broker release archives.
package release

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"
)

var supportedTargets = []Target{{"linux", "amd64"}, {"linux", "arm64"}, {"darwin", "amd64"}, {"darwin", "arm64"}}

var brokerNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// Options configures release asset generation.
type Options struct {
	Directory     string
	Broker        string
	Command       string
	Version       string
	Dist          string
	ExtraCommands map[string]string
	Targets       []Target
}

// Target identifies one natively built release platform.
type Target struct {
	GOOS   string
	GOARCH string
}

func (target Target) String() string { return target.GOOS + "/" + target.GOARCH }

// ParseTarget parses one supported release platform.
func ParseTarget(value string) (Target, error) {
	goos, goarch, found := strings.Cut(strings.TrimSpace(value), "/")
	target := Target{GOOS: goos, GOARCH: goarch}
	if !found || !isSupportedTarget(target) {
		return Target{}, fmt.Errorf("unsupported release target %q", value)
	}
	return target, nil
}

// Run builds the selected native release assets and their checksums.
func Run(ctx context.Context, options Options) error {
	normalized, err := normalizeOptions(options)
	if err != nil {
		return err
	}
	if err := os.RemoveAll(normalized.Dist); err != nil {
		return err
	}
	if err := os.MkdirAll(normalized.Dist, 0o750); err != nil {
		return err
	}
	return buildAssets(ctx, normalized)
}

func normalizeOptions(options Options) (Options, error) {
	if err := validate(options); err != nil {
		return Options{}, err
	}
	directory, dist, err := safePaths(options.Directory, options.Dist)
	if err != nil {
		return Options{}, err
	}
	options.Directory, options.Dist = directory, dist
	options.Targets, err = normalizedTargets(options.Targets)
	if err != nil {
		return Options{}, err
	}
	return options, nil
}

func buildAssets(ctx context.Context, options Options) error {
	var checksums strings.Builder
	for _, target := range options.Targets {
		asset, err := build(ctx, options, target.GOOS, target.GOARCH)
		if err != nil {
			return err
		}
		digest, err := fileDigest(asset)
		if err != nil {
			return err
		}
		fmt.Fprintf(&checksums, "%x  %s\n", digest, filepath.Base(asset))
	}
	return os.WriteFile(filepath.Join(options.Dist, "checksums.txt"), []byte(checksums.String()), 0o600)
}

func normalizedTargets(values []Target) ([]Target, error) {
	if len(values) == 0 {
		return []Target{{GOOS: runtime.GOOS, GOARCH: runtime.GOARCH}}, nil
	}
	result := append([]Target(nil), values...)
	seen := make(map[Target]struct{}, len(result))
	for _, target := range result {
		if !isSupportedTarget(target) || target.GOOS != runtime.GOOS || target.GOARCH != runtime.GOARCH {
			return nil, fmt.Errorf("release target %s requires a matching native runner", target)
		}
		if _, exists := seen[target]; exists {
			return nil, fmt.Errorf("release target %s is duplicated", target)
		}
		seen[target] = struct{}{}
	}
	return result, nil
}

func isSupportedTarget(target Target) bool {
	for _, supported := range supportedTargets {
		if target == supported {
			return true
		}
	}
	return false
}

func safePaths(directory, dist string) (string, string, error) {
	directoryPath, err := canonicalPath(directory)
	if err != nil {
		return "", "", fmt.Errorf("resolve source directory: %w", err)
	}
	distPath, err := canonicalPath(dist)
	if err != nil {
		return "", "", fmt.Errorf("resolve release directory: %w", err)
	}
	relative, err := filepath.Rel(distPath, directoryPath)
	if err != nil {
		return "", "", err
	}
	if relative == "." || (relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))) {
		return "", "", errors.New("release directory must not contain the source directory")
	}
	return directoryPath, distPath, nil
}

func canonicalPath(path string) (string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	current := filepath.Clean(absolute)
	var missing []string
	for {
		resolved, resolveErr := filepath.EvalSymlinks(current)
		if resolveErr == nil {
			for index := len(missing) - 1; index >= 0; index-- {
				resolved = filepath.Join(resolved, missing[index])
			}
			return filepath.Clean(resolved), nil
		}
		if !errors.Is(resolveErr, os.ErrNotExist) {
			return "", resolveErr
		}
		parent := filepath.Dir(current)
		if parent == current {
			return "", resolveErr
		}
		missing = append(missing, filepath.Base(current))
		current = parent
	}
}

func validate(options Options) error {
	if !requiredReleaseOptions(options) {
		return errors.New("directory, broker, command, version, and dist are required")
	}
	if !brokerNamePattern.MatchString(options.Broker) {
		return errors.New("broker must be a file name")
	}
	return validateExtraCommands(options.Broker, options.ExtraCommands)
}

func requiredReleaseOptions(options Options) bool {
	return options.Directory != "" && options.Broker != "" && options.Command != "" && options.Version != "" && options.Dist != ""
}

func validateExtraCommands(broker string, commands map[string]string) error {
	for name, command := range commands {
		if !brokerNamePattern.MatchString(name) || name == broker || strings.TrimSpace(command) == "" {
			return errors.New("extra commands must use unique safe binary names and nonempty packages")
		}
	}
	return nil
}

func build(ctx context.Context, options Options, goos, goarch string) (string, error) {
	work, err := os.MkdirTemp("", "brokerkit-release-*")
	if err != nil {
		return "", err
	}
	defer func() { _ = os.RemoveAll(work) }()
	binaries := make(map[string]string, len(options.ExtraCommands)+1)
	binary := filepath.Join(work, options.Broker)
	if err := buildExecutable(ctx, options, options.Command, binary, goos, goarch); err != nil {
		return "", err
	}
	binaries[options.Broker] = binary
	names := make([]string, 0, len(options.ExtraCommands))
	for name := range options.ExtraCommands {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		path := filepath.Join(work, name)
		if err := buildExecutable(ctx, options, options.ExtraCommands[name], path, goos, goarch); err != nil {
			return "", err
		}
		binaries[name] = path
	}
	asset := filepath.Join(options.Dist, fmt.Sprintf("%s_%s_%s.tar.gz", options.Broker, goos, goarch))
	return asset, archiveBinaries(asset, options, binaries)
}

func buildExecutable(ctx context.Context, options Options, command string, binary string, goos string, goarch string) error {
	// #nosec G204 -- the executable and flags are fixed; values come from the release operator.
	cmd := exec.CommandContext(ctx, "go", "build", "-trimpath", "-ldflags", "-s -w -X main.version="+options.Version, "-o", binary, command)
	cmd.Dir = options.Directory
	cgo := "0"
	if goos == "darwin" {
		cgo = "1"
	}
	cmd.Env = append(os.Environ(), "GOOS="+goos, "GOARCH="+goarch, "CGO_ENABLED="+cgo)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("build %s/%s: %w", goos, goarch, err)
	}
	return nil
}

func archive(asset string, options Options, binary string) error {
	return archiveBinaries(asset, options, map[string]string{options.Broker: binary})
}

func archiveBinaries(asset string, options Options, binaries map[string]string) error {
	file, err := os.OpenFile(asset, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600) // #nosec G304 -- validated release output path.
	if err != nil {
		return err
	}
	gzipWriter := gzip.NewWriter(file)
	gzipWriter.ModTime = time.Unix(0, 0).UTC()
	tarWriter := tar.NewWriter(gzipWriter)
	files := archiveFiles(options, binaries)
	if err := writeArchiveFiles(tarWriter, files); err != nil {
		_ = tarWriter.Close()
		_ = gzipWriter.Close()
		_ = file.Close()
		return err
	}
	if err := tarWriter.Close(); err != nil {
		return err
	}
	if err := gzipWriter.Close(); err != nil {
		return err
	}
	return file.Close()
}

type archiveFile struct {
	path string
	name string
	mode int64
}

func archiveFiles(options Options, binaries map[string]string) []archiveFile {
	files := make([]archiveFile, 0, len(binaries)+2)
	names := make([]string, 0, len(binaries))
	for name := range binaries {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		files = append(files, archiveFile{binaries[name], name, 0o755})
	}
	files = append(files,
		archiveFile{filepath.Join(options.Directory, "README.md"), "README.md", 0o644},
		archiveFile{filepath.Join(options.Directory, "LICENSE"), "LICENSE", 0o644},
	)
	return files
}

func writeArchiveFiles(writer *tar.Writer, files []archiveFile) error {
	for _, source := range files {
		if err := addFile(writer, source.path, source.name, source.mode); err != nil {
			return err
		}
	}
	return nil
}

func addFile(writer *tar.Writer, source, name string, mode int64) (returnErr error) {
	file, err := os.Open(source) // #nosec G304 -- release input is operator configured.
	if err != nil {
		return err
	}
	defer func() {
		if err := file.Close(); returnErr == nil {
			returnErr = err
		}
	}()
	info, err := file.Stat()
	if err != nil {
		return err
	}
	header, err := tar.FileInfoHeader(info, "")
	if err != nil {
		return err
	}
	epoch := time.Unix(0, 0).UTC()
	header.Name, header.ModTime, header.AccessTime, header.ChangeTime = name, epoch, epoch, epoch
	header.Mode, header.Uid, header.Gid, header.Uname, header.Gname = mode, 0, 0, "", ""
	if err := writer.WriteHeader(header); err != nil {
		return err
	}
	_, err = io.Copy(writer, file)
	return err
}

func fileDigest(path string) ([sha256.Size]byte, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- generated release path.
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	return sha256.Sum256(data), nil
}

// HostTarget returns the current release target for tests and diagnostics.
func HostTarget() string { return runtime.GOOS + "/" + runtime.GOARCH }
