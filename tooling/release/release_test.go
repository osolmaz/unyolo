package release

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestValidate(t *testing.T) {
	valid := Options{Directory: ".", Broker: "test-broker", Command: "./cmd/test", Version: "v0.1.0", Dist: "dist"}
	if err := validate(valid); err != nil {
		t.Fatal(err)
	}
	for _, broker := range []string{"../bad", "bad\nforged", "bad name", "."} {
		valid.Broker = broker
		if err := validate(valid); err == nil {
			t.Fatalf("validate() accepted broker %q", broker)
		}
	}
}

func TestSafePathsRejectsSourceRemoval(t *testing.T) {
	directory := t.TempDir()
	for _, dist := range []string{directory, filepath.Dir(directory)} {
		if _, _, err := safePaths(directory, dist); err == nil {
			t.Fatalf("safePaths(%q, %q) accepted destructive output", directory, dist)
		}
	}
	if _, _, err := safePaths(directory, filepath.Join(directory, "dist")); err != nil {
		t.Fatalf("safePaths() rejected nested output: %v", err)
	}
}

func TestHostTarget(t *testing.T) {
	if HostTarget() == "/" {
		t.Fatal("HostTarget() is empty")
	}
}

func TestRunBuildsDeterministicReleaseAssets(t *testing.T) {
	directory := t.TempDir()
	writeReleaseFile(t, directory, "go.mod", "module example.test/release\n\ngo 1.25.0\n")
	writeReleaseFile(t, directory, "main.go", "package main\nvar version = \"dev\"\nfunc main() {}\n")
	writeReleaseFile(t, directory, "README.md", "# test\n")
	writeReleaseFile(t, directory, "LICENSE", "test license\n")
	dist := filepath.Join(directory, "dist")
	options := Options{Directory: directory, Broker: "test-broker", Command: ".", Version: "v0.1.0", Dist: dist}
	if err := Run(t.Context(), options); err != nil {
		t.Fatal(err)
	}
	first, err := os.ReadFile(filepath.Join(dist, "checksums.txt")) // #nosec G304 -- test-owned path.
	if err != nil {
		t.Fatal(err)
	}
	asset := filepath.Join(dist, "test-broker_linux_amd64.tar.gz")
	if names := archiveNames(t, asset); !slices.Equal(names, []string{"test-broker", "README.md", "LICENSE"}) {
		t.Fatalf("archive names = %v", names)
	}
	assertArchiveMetadata(t, asset)
	if err := Run(t.Context(), options); err != nil {
		t.Fatal(err)
	}
	second, err := os.ReadFile(filepath.Join(dist, "checksums.txt")) // #nosec G304 -- test-owned path.
	if err != nil || string(first) != string(second) || strings.Count(string(second), "test-broker_") != 4 {
		t.Fatalf("checksums are not deterministic: %v", err)
	}
}

func TestRunReportsBuildFailure(t *testing.T) {
	directory := t.TempDir()
	writeReleaseFile(t, directory, "go.mod", "module example.test/release-failure\n\ngo 1.25.0\n")
	writeReleaseFile(t, directory, "README.md", "# test\n")
	writeReleaseFile(t, directory, "LICENSE", "test license\n")
	err := Run(t.Context(), Options{
		Directory: directory, Broker: "test-broker", Command: "./cmd/missing", Version: "v0.1.0",
		Dist: filepath.Join(directory, "dist"),
	})
	if err == nil {
		t.Fatal("Run() accepted a missing command")
	}
}

func TestArchiveReportsMissingInput(t *testing.T) {
	directory := t.TempDir()
	binary := filepath.Join(directory, "test-broker")
	writeReleaseFile(t, directory, "test-broker", "binary")
	writeReleaseFile(t, directory, "LICENSE", "test license\n")
	err := archive(filepath.Join(directory, "asset.tar.gz"), Options{Directory: directory}, binary)
	if err == nil {
		t.Fatal("archive() accepted a missing README")
	}
}

func assertArchiveMetadata(t *testing.T, path string) {
	t.Helper()
	reader, closeArchive := openArchive(t, path)
	defer closeArchive()
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			return
		}
		if err != nil {
			t.Fatal(err)
		}
		wantMode := int64(0o644)
		if header.Name == "test-broker" {
			wantMode = 0o755
		}
		if header.Mode != wantMode || header.Uid != 0 || header.Gid != 0 || header.Uname != "" || header.Gname != "" {
			t.Fatalf("archive metadata for %q = mode %o uid %d gid %d uname %q gname %q", header.Name, header.Mode, header.Uid, header.Gid, header.Uname, header.Gname)
		}
	}
}

func archiveNames(t *testing.T, path string) []string {
	t.Helper()
	reader, closeArchive := openArchive(t, path)
	defer closeArchive()
	var names []string
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		names = append(names, header.Name)
	}
	return names
}

func openArchive(t *testing.T, path string) (*tar.Reader, func()) {
	t.Helper()
	file, err := os.Open(path) // #nosec G304 -- generated test fixture.
	if err != nil {
		t.Fatal(err)
	}
	gzipReader, err := gzip.NewReader(file)
	if err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	closeArchive := func() {
		if err := gzipReader.Close(); err != nil {
			t.Error(err)
		}
		if err := file.Close(); err != nil {
			t.Error(err)
		}
	}
	return tar.NewReader(gzipReader), closeArchive
}

func writeReleaseFile(t *testing.T, directory, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(directory, name), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}
