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
	"runtime"
	"strings"
	"time"
)

var targets = [][2]string{{"linux", "amd64"}, {"linux", "arm64"}, {"darwin", "amd64"}, {"darwin", "arm64"}}

// Options configures release asset generation.
type Options struct {
	Directory string
	Broker    string
	Command   string
	Version   string
	Dist      string
}

// Run builds all supported release assets and checksums.
func Run(ctx context.Context, options Options) error {
	if err := validate(options); err != nil {
		return err
	}
	if err := os.RemoveAll(options.Dist); err != nil {
		return err
	}
	if err := os.MkdirAll(options.Dist, 0o750); err != nil {
		return err
	}
	var checksums strings.Builder
	for _, target := range targets {
		asset, err := build(ctx, options, target[0], target[1])
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

func validate(options Options) error {
	if options.Directory == "" || options.Broker == "" || options.Command == "" || options.Version == "" || options.Dist == "" {
		return errors.New("directory, broker, command, version, and dist are required")
	}
	if strings.ContainsAny(options.Broker, `/\\`) {
		return errors.New("broker must be a file name")
	}
	return nil
}

func build(ctx context.Context, options Options, goos, goarch string) (string, error) {
	work, err := os.MkdirTemp("", "brokerkit-release-*")
	if err != nil {
		return "", err
	}
	defer func() { _ = os.RemoveAll(work) }()
	binary := filepath.Join(work, options.Broker)
	// #nosec G204 -- the executable and flags are fixed; values come from the release operator.
	cmd := exec.CommandContext(ctx, "go", "build", "-trimpath", "-ldflags", "-s -w -X main.version="+options.Version, "-o", binary, options.Command)
	cmd.Dir = options.Directory
	cmd.Env = append(os.Environ(), "GOOS="+goos, "GOARCH="+goarch, "CGO_ENABLED=0")
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("build %s/%s: %w", goos, goarch, err)
	}
	asset := filepath.Join(options.Dist, fmt.Sprintf("%s_%s_%s.tar.gz", options.Broker, goos, goarch))
	return asset, archive(asset, options, binary)
}

func archive(asset string, options Options, binary string) error {
	file, err := os.OpenFile(asset, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600) // #nosec G304 -- validated release output path.
	if err != nil {
		return err
	}
	gzipWriter := gzip.NewWriter(file)
	gzipWriter.ModTime = time.Unix(0, 0).UTC()
	tarWriter := tar.NewWriter(gzipWriter)
	for _, source := range []string{binary, filepath.Join(options.Directory, "README.md"), filepath.Join(options.Directory, "LICENSE")} {
		if err := addFile(tarWriter, source, filepath.Base(source)); err != nil {
			_ = tarWriter.Close()
			_ = gzipWriter.Close()
			_ = file.Close()
			return err
		}
	}
	if err := tarWriter.Close(); err != nil {
		return err
	}
	if err := gzipWriter.Close(); err != nil {
		return err
	}
	return file.Close()
}

func addFile(writer *tar.Writer, source, name string) (returnErr error) {
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
