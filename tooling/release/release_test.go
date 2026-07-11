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
	valid.Broker = "../bad"
	if err := validate(valid); err == nil {
		t.Fatal("validate() accepted path-like broker")
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
	if err := Run(t.Context(), options); err != nil {
		t.Fatal(err)
	}
	second, err := os.ReadFile(filepath.Join(dist, "checksums.txt")) // #nosec G304 -- test-owned path.
	if err != nil || string(first) != string(second) || strings.Count(string(second), "test-broker_") != 4 {
		t.Fatalf("checksums are not deterministic: %v", err)
	}
}

func archiveNames(t *testing.T, path string) []string {
	t.Helper()
	file, err := os.Open(path) // #nosec G304 -- generated test fixture.
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			t.Error(err)
		}
	}()
	gzipReader, err := gzip.NewReader(file)
	if err != nil {
		t.Fatal(err)
	}
	reader := tar.NewReader(gzipReader)
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

func writeReleaseFile(t *testing.T, directory, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(directory, name), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}
