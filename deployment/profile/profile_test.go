package profile

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/osolmaz/brokerkit/internal/host/bundle"
	"github.com/osolmaz/brokerkit/protocol/contract"
)

func TestLockAndLoadDeploymentPack(t *testing.T) {
	root := testPack(t)
	if err := Lock(root, true); err != ErrLockOutOfDate {
		t.Fatalf("Lock(check) error = %v, want ErrLockOutOfDate", err)
	}
	if err := Lock(root, false); err != nil {
		t.Fatalf("Lock() error = %v", err)
	}
	if err := Lock(root, true); err != nil {
		t.Fatalf("Lock(check after update) error = %v", err)
	}
	snapshot, err := Load(root)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if snapshot.Deployment.Name != "test-host" || snapshot.Manifest.BundleID != "test-bundle" || len(snapshot.Files) != 5 {
		t.Fatalf("unexpected snapshot: %#v", snapshot)
	}
	if !strings.HasPrefix(snapshot.Digest, "sha256:") {
		t.Fatalf("digest = %q", snapshot.Digest)
	}
}

func TestLoadRejectsNestedReferenceSymlink(t *testing.T) {
	root := testPack(t)
	outside := filepath.Join(t.TempDir(), "outside.json")
	if err := os.WriteFile(outside, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(root, "policies", "fake.json")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "policies", "fake.json")); err != nil {
		t.Fatal(err)
	}
	if err := Lock(root, false); err == nil || !strings.Contains(err.Error(), "symbolic links") {
		t.Fatalf("Lock() error = %v, want symlink rejection", err)
	}
}

func testPack(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	for _, directory := range []string{"runtime", "components", "policies", "artifacts"} {
		if err := os.Mkdir(filepath.Join(root, directory), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	artifact := []byte("#!/bin/sh\nexit 0\n")
	artifactDigest := sha256.Sum256(artifact)
	artifactPath := filepath.Join(root, "artifacts", "fake")
	if err := os.WriteFile(artifactPath, artifact, 0o700); err != nil {
		t.Fatal(err)
	}
	manifest := bundle.Manifest{
		APIVersion: bundle.APIVersion, BundleID: "test-bundle", SourceCommit: strings.Repeat("a", 40),
		OperatingSystem: runtime.GOOS, Architecture: runtime.GOARCH,
		OperatorContractDigest: contract.OperatorV1Digest, AgentContractDigest: contract.AgentV1Digest,
		Components: []bundle.Component{{
			Name: "fake", Source: "artifacts/fake", Destination: "bin/fake",
			SHA256: "sha256:" + fmtHex(artifactDigest[:]), BuildID: "test", Role: bundle.RoleCompanion,
			StateFormatDigest: "sha256:" + strings.Repeat("0", 64), Required: false,
			Setup: &bundle.SetupAdapter{
				Protocol: "brokerkit.io/setup-component/v1", Arguments: []string{"setup-component"},
				Ownership: bundle.OwnershipEnvelope{Paths: []string{"/tmp/brokerkit-fake"}},
			},
		}},
	}
	manifestData, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(root, "runtime", "manifest.json"), manifestData, 0o600)
	writeTestFile(t, filepath.Join(root, "runtime", "manifest.sig"), []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(private, manifestData))+"\n"), 0o600)
	writeTestFile(t, filepath.Join(root, "runtime", "release.pub"), []byte(base64.StdEncoding.EncodeToString(public)+"\n"), 0o600)
	writeTestFile(t, filepath.Join(root, "policies", "fake.json"), []byte("{}\n"), 0o600)
	component := `{"api_version":"brokerkit.io/fake-deployment/v1","policy":{"path":"policies/fake.json","sha256":"sha256:` + strings.Repeat("0", 64) + `"}}` + "\n"
	writeTestFile(t, filepath.Join(root, "components", "fake.json"), []byte(component), 0o600)
	deployment := Deployment{
		APIVersion: APIVersion, Name: "test-host",
		Runtime: Runtime{
			Manifest:  Reference{Path: "runtime/manifest.json", SHA256: zeroDigest()},
			Signature: Reference{Path: "runtime/manifest.sig", SHA256: zeroDigest()},
			PublicKey: Reference{Path: "runtime/release.pub", SHA256: zeroDigest()},
		},
		Agents:     []Agent{{ID: "agent", ClientID: "agent", UnixUser: "nobody", AccountMode: "existing", Home: "/tmp/agent", Shell: "/bin/false", ComponentIDs: []string{"fake"}}},
		Operators:  []Operator{{ID: "operator", UnixUser: "operator"}},
		Components: []Component{{ID: "fake", Profile: Reference{Path: "components/fake.json", SHA256: zeroDigest()}}},
	}
	data, err := json.Marshal(deployment)
	if err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(root, EntryFilename), append(data, '\n'), 0o600)
	return root
}

func writeTestFile(t *testing.T, path string, data []byte, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, data, mode); err != nil {
		t.Fatal(err)
	}
}

func zeroDigest() string { return "sha256:" + strings.Repeat("0", 64) }

func fmtHex(value []byte) string {
	const digits = "0123456789abcdef"
	result := make([]byte, len(value)*2)
	for index, current := range value {
		result[index*2] = digits[current>>4]
		result[index*2+1] = digits[current&15]
	}
	return string(result)
}
