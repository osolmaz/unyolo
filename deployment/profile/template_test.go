package profile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMaterializeReleaseTemplateHydratesArtifactsAndBindsIdentity(t *testing.T) {
	source := testPack(t)
	profilePath := filepath.Join(source, "components", "fake.json")
	profileData, err := os.ReadFile(profilePath)
	if err != nil {
		t.Fatal(err)
	}
	profileData = append(profileData[:len(profileData)-2], []byte(",\n  \"identity_template\": [\"$UNYOLO_OPERATOR\", \"$UNYOLO_AGENT\"]\n}\n")...)
	if err := os.WriteFile(profilePath, profileData, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Lock(source, false); err != nil {
		t.Fatal(err)
	}
	artifactRoot := t.TempDir()
	if err := os.Mkdir(filepath.Join(artifactRoot, "artifacts"), 0o700); err != nil {
		t.Fatal(err)
	}
	artifact, err := os.ReadFile(filepath.Join(source, "artifacts", "fake"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(artifactRoot, "artifacts", "fake"), artifact, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(source, "artifacts", "fake")); err != nil {
		t.Fatal(err)
	}
	snapshot, err := Load(source)
	if err != nil {
		t.Fatalf("template without hydrated artifacts did not load: %v", err)
	}
	parent := t.TempDir()
	if err := os.Chmod(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(parent, "selected-host")
	path, err := MaterializeReleaseTemplate(snapshot, artifactRoot, destination, "selected-host", "alice", []string{"fake"})
	if err != nil {
		t.Fatal(err)
	}
	generated, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if generated.Deployment.Name != "selected-host" || len(generated.Deployment.Operators) != 1 || generated.Deployment.Operators[0].UnixUser != "alice" {
		t.Fatalf("generated deployment identity = %+v", generated.Deployment)
	}
	if _, err := generated.VerifyArtifact(generated.Manifest.Components[0].Source, generated.Manifest.Components[0].SHA256); err != nil {
		t.Fatalf("hydrated runtime artifact: %v", err)
	}
	boundProfile, err := os.ReadFile(filepath.Join(path, "components", "fake.json"))
	if err != nil || !strings.Contains(string(boundProfile), `"alice"`) || !strings.Contains(string(boundProfile), `"unyolo-agent"`) || strings.Contains(string(boundProfile), "$UNYOLO_") {
		t.Fatalf("template identities were not bound: %s, %v", boundProfile, err)
	}
	if repeated, err := MaterializeReleaseTemplate(snapshot, artifactRoot, destination, "selected-host", "alice", []string{"fake"}); err != nil || repeated != destination {
		t.Fatalf("idempotent template materialization = %q, %v", repeated, err)
	}
}
