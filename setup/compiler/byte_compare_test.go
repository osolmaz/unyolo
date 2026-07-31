package compiler

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCompileMutatedProviderProfileFailsOwnership(t *testing.T) {
	t.Parallel()
	sourceSet := buildTestSourceSet(t)
	profilePath := filepath.Join(sourceSet, "providers", "github", "profile.json")
	data, err := os.ReadFile(profilePath) // #nosec G304 -- test-owned path.
	if err != nil {
		t.Fatal(err)
	}
	tampered := strings.ReplaceAll(string(data), "/etc/gh-broker/secrets", "/etc/rogue/secrets")
	if err := os.WriteFile(profilePath, []byte(tampered), 0o600); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(t.TempDir(), "compiled")
	if _, err := Compile(Options{Installation: compilerInstallation(), SourceSet: sourceSet, Destination: dest}); err == nil {
		t.Fatal("Compile() accepted a provider profile with resources outside its ownership envelope")
	}
}
