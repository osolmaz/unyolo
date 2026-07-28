package layout

import (
	"path/filepath"
	"runtime"
	"testing"
)

func TestRootAndExecutablePath(t *testing.T) {
	if LinuxRoot() != "/opt/unyolo" || DarwinRoot() != "/Library/Application Support/unyolo" {
		t.Fatal("platform roots changed unexpectedly")
	}
	wantRoot := "/opt/unyolo"
	if runtime.GOOS == "darwin" {
		wantRoot = "/Library/Application Support/unyolo"
	}
	if got := Root(); got != wantRoot {
		t.Fatalf("Root() = %q", got)
	}
	if got := ExecutablePath(filepath.Join("bin", "gh-broker")); got != filepath.Join(wantRoot, "current", "bin", "gh-broker") {
		t.Fatalf("ExecutablePath() = %q", got)
	}
}

func TestReleaseDestination(t *testing.T) {
	root := filepath.Join(string(filepath.Separator), "opt", "unyolo")
	path := filepath.Join(root, "releases", "bundle-one", "bin", "gh-broker")
	if got := ReleaseDestination(path, root); got != filepath.Join("bin", "gh-broker") {
		t.Fatalf("ReleaseDestination() = %q", got)
	}
	for _, outside := range []string{root, filepath.Join(root, "releases"), filepath.Join(root, "current", "bin", "gh-broker")} {
		if got := ReleaseDestination(outside, root); got != "" {
			t.Fatalf("ReleaseDestination(%q) = %q", outside, got)
		}
	}
}

func TestSafeDestination(t *testing.T) {
	if !SafeDestination(filepath.Join("libexec", "sudo-broker-exec")) {
		t.Fatal("safe destination was rejected")
	}
	for _, path := range []string{"", ".", "../bin", filepath.Join(string(filepath.Separator), "bin", "broker")} {
		if SafeDestination(path) {
			t.Fatalf("SafeDestination(%q) = true", path)
		}
	}
}

func TestValidCurrentTarget(t *testing.T) {
	if !ValidCurrentTarget(filepath.Join("releases", "bundle-one")) {
		t.Fatal("valid current target was rejected")
	}
	for _, target := range []string{"", "releases", "../bundle-one", "/opt/unyolo/releases/bundle-one", "releases/one/bin"} {
		if ValidCurrentTarget(target) {
			t.Fatalf("ValidCurrentTarget(%q) = true", target)
		}
	}
}
