package installer

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestInstallerDownloadsVerifiesAndInstalls(t *testing.T) {
	asset := "test-broker_linux_amd64.tar.gz"
	releaseDir := t.TempDir()
	writeReleaseAsset(t, filepath.Join(releaseDir, asset), "test-broker", "#!/bin/sh\necho v1.2.3\n")
	writeChecksums(t, releaseDir, asset)
	server := releaseServer(t, releaseDir, asset)
	defer server.Close()
	installDir := t.TempDir()
	command := installerCommand(t, installDir, server.URL, "")
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("installer failed: %v\n%s", err, output)
	}
	installed := filepath.Join(installDir, "test-broker")
	info, err := os.Stat(installed)
	if err != nil || info.Mode().Perm() != 0o755 {
		t.Fatalf("installed binary info = %+v err=%v", info, err)
	}
	if !strings.Contains(string(output), "Downloading example/test-broker v1.2.3 for linux/amd64") ||
		!strings.Contains(string(output), "v1.2.3") {
		t.Fatalf("installer output = %s", output)
	}
}

func TestInstallerPlacesCompanionBinaryInLibexec(t *testing.T) {
	asset := "test-broker_linux_amd64.tar.gz"
	releaseDir := t.TempDir()
	writeReleaseAssetEntries(t, filepath.Join(releaseDir, asset), map[string]string{
		"test-broker": "#!/bin/sh\necho v1.2.3\n", "test-broker-exec": "#!/bin/sh\necho helper-v1.2.3\n",
	})
	writeChecksums(t, releaseDir, asset)
	server := releaseServer(t, releaseDir, asset)
	defer server.Close()
	installDir := filepath.Join(t.TempDir(), "bin")
	libexecDir := filepath.Join(t.TempDir(), "libexec")
	command := installerCommand(t, installDir, server.URL, "v1.2.3")
	command.Env = append(command.Env, "COMPANION_BINARIES=test-broker-exec", "LIBEXEC_DIR="+libexecDir)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("installer failed: %v\n%s", err, output)
	}
	if info, err := os.Stat(filepath.Join(libexecDir, "test-broker-exec")); err != nil || info.Mode().Perm() != 0o755 {
		t.Fatalf("companion binary info = %+v err=%v", info, err)
	}
	if !strings.Contains(string(output), "helper-v1.2.3") {
		t.Fatalf("installer did not verify helper: %s", output)
	}
}

func TestInstallerRejectsChecksumMismatch(t *testing.T) {
	asset := "test-broker_linux_amd64.tar.gz"
	releaseDir := t.TempDir()
	writeReleaseAsset(t, filepath.Join(releaseDir, asset), "test-broker", "#!/bin/sh\necho v1.2.3\n")
	if err := os.WriteFile(filepath.Join(releaseDir, "checksums.txt"), []byte(strings.Repeat("0", 64)+"  "+asset+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	server := releaseServer(t, releaseDir, asset)
	defer server.Close()
	output, err := installerCommand(t, t.TempDir(), server.URL, "v1.2.3").CombinedOutput()
	if err == nil || !strings.Contains(string(output), "FAILED") {
		t.Fatalf("installer checksum result err=%v output=%s", err, output)
	}
}

func TestInstallerSelectsQualifiedComponentRelease(t *testing.T) {
	asset := "test-broker_linux_amd64.tar.gz"
	releaseDir := t.TempDir()
	writeReleaseAsset(t, filepath.Join(releaseDir, asset), "test-broker", "#!/bin/sh\necho component-v1.2.3\n")
	writeChecksums(t, releaseDir, asset)
	server := releaseServer(t, releaseDir, asset)
	defer server.Close()
	command := installerCommand(t, t.TempDir(), server.URL, "")
	command.Env = append(command.Env, "TAG_PREFIX=test-broker/", "BROKERKIT_RELEASES_URL="+server.URL+"/releases")
	output, err := command.CombinedOutput()
	if err != nil || !strings.Contains(string(output), "test-broker/v1.2.3") {
		t.Fatalf("qualified installer err=%v output=%s", err, output)
	}
}

func TestInstallerVerifiesInstalledBinaryInsteadOfEarlierPATHEntry(t *testing.T) {
	asset := "test-broker_linux_amd64.tar.gz"
	releaseDir := t.TempDir()
	writeReleaseAsset(t, filepath.Join(releaseDir, asset), "test-broker", "#!/bin/sh\necho installed-v1.2.3\n")
	writeChecksums(t, releaseDir, asset)
	server := releaseServer(t, releaseDir, asset)
	defer server.Close()
	oldBinDir := t.TempDir()
	oldBinary := filepath.Join(oldBinDir, "test-broker")
	if err := os.WriteFile(oldBinary, []byte("#!/bin/sh\necho stale-path-version\nexit 9\n"), 0o755); err != nil { // #nosec G306 -- executable fixture requires execute bits.
		t.Fatal(err)
	}
	command := installerCommand(t, t.TempDir(), server.URL, "v1.2.3")
	command.Env = append(command.Env, "PATH="+oldBinDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	output, err := command.CombinedOutput()
	if err != nil || !strings.Contains(string(output), "installed-v1.2.3") || strings.Contains(string(output), "stale-path-version") {
		t.Fatalf("installer err=%v output=%s", err, output)
	}
}

func TestInstallerRejectsUnsupportedPlatformAndInvalidInputs(t *testing.T) {
	tests := []struct {
		name string
		env  []string
		want string
	}{
		{name: "os", env: []string{"BROKER=test-broker", "REPO=example/test-broker", "BROKERKIT_UNAME_S=Windows", "BROKERKIT_UNAME_M=x86_64"}, want: "unsupported OS"},
		{name: "broker", env: []string{"BROKER=../bad", "REPO=example/test-broker"}, want: "BROKER must contain"},
		{name: "repo", env: []string{"BROKER=test-broker", "REPO=missing"}, want: "owner/name"},
		{name: "nested repo", env: []string{"BROKER=test-broker", "REPO=example/team/test-broker"}, want: "owner/name"},
		{name: "unsafe repo", env: []string{"BROKER=test-broker", "REPO=ex..ample/test-broker"}, want: "unsafe path"},
		{name: "relative install", env: []string{"BROKER=test-broker", "REPO=example/test-broker", "INSTALL_DIR=relative"}, want: "absolute normalized"},
		{name: "release tag", env: []string{"BROKER=test-broker", "REPO=example/test-broker", "VERSION=../../payload"}, want: "release tag contains unsupported"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			command := exec.CommandContext(context.Background(), "sh", scriptPath(t)) // #nosec G204 -- test executes the repository-owned installer path.
			command.Env = append(os.Environ(), tc.env...)
			output, err := command.CombinedOutput()
			if err == nil || !strings.Contains(string(output), tc.want) {
				t.Fatalf("installer err=%v output=%s, want %q", err, output, tc.want)
			}
		})
	}
}

func installerCommand(t *testing.T, installDir string, serverURL string, version string) *exec.Cmd {
	t.Helper()
	command := exec.CommandContext(context.Background(), "sh", scriptPath(t)) // #nosec G204 -- test executes the repository-owned installer path.
	command.Env = append(os.Environ(),
		"BROKER=test-broker",
		"REPO=example/test-broker",
		"INSTALL_DIR="+installDir,
		"VERSION="+version,
		"BROKERKIT_UNAME_S=Linux",
		"BROKERKIT_UNAME_M=x86_64",
		"BROKERKIT_LATEST_RELEASE_URL="+serverURL+"/latest",
		"BROKERKIT_RELEASE_BASE_URL="+serverURL+"/release",
	)
	return command
}

func scriptPath(t *testing.T) string {
	t.Helper()
	path, err := filepath.Abs("install.sh")
	if err != nil {
		t.Fatal(err)
	}
	return path
}

func writeReleaseAsset(t *testing.T, path string, binaryName string, body string) {
	writeReleaseAssetEntries(t, path, map[string]string{binaryName: body})
}

func writeReleaseAssetEntries(t *testing.T, path string, entries map[string]string) {
	t.Helper()
	file, err := os.Create(path) // #nosec G304 -- test writes its private fixture path.
	if err != nil {
		t.Fatal(err)
	}
	gzipWriter := gzip.NewWriter(file)
	tarWriter := tar.NewWriter(gzipWriter)
	for name, body := range entries {
		data := []byte(body)
		if err := tarWriter.WriteHeader(&tar.Header{Name: name, Mode: 0o755, Size: int64(len(data))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tarWriter.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}

func writeChecksums(t *testing.T, dir string, asset string) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, asset)) // #nosec G304 -- test reads its private fixture path.
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(data)
	body := fmt.Sprintf("%x  %s\n", digest, asset)
	if err := os.WriteFile(filepath.Join(dir, "checksums.txt"), []byte(body), 0o600); err != nil { // #nosec G703 -- test writes its private fixture path.
		t.Fatal(err)
	}
}

func releaseServer(t *testing.T, dir string, asset string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/latest":
			_, _ = io.WriteString(w, `{"tag_name":"v1.2.3"}`)
		case "/releases":
			_, _ = io.WriteString(w, `[{"tag_name":"openclaw-brokerkit/v9.0.0"},{"tag_name":"test-broker/v1.2.3"}]`)
		case "/release/" + asset:
			http.ServeFile(w, r, filepath.Join(dir, asset))
		case "/release/checksums.txt":
			http.ServeFile(w, r, filepath.Join(dir, "checksums.txt"))
		default:
			http.NotFound(w, r)
		}
	}))
}
