package profile

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
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
	if err := Lock(root, true); !errors.Is(err, ErrLockOutOfDate) {
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

func TestLoadUnlockedAndVerifyArtifact(t *testing.T) {
	root := testPack(t)
	if err := Lock(root, false); err != nil {
		t.Fatal(err)
	}
	snapshot, err := LoadUnlocked(root)
	if err != nil {
		t.Fatal(err)
	}
	artifactPath := "artifacts/fake"
	resolved, err := snapshot.VerifyArtifact(artifactPath, hash([]byte("#!/bin/sh\nexit 0\n")))
	if err != nil || !filepath.IsAbs(resolved) {
		t.Fatalf("VerifyArtifact(%q) = %q, %v", artifactPath, resolved, err)
	}
	if _, err := snapshot.VerifyArtifact("missing", "sha256:"+strings.Repeat("0", 64)); err == nil {
		t.Fatal("missing artifact was accepted")
	}
	if _, err := snapshot.VerifyArtifact("../escape", "sha256:"+strings.Repeat("0", 64)); err == nil {
		t.Fatal("escaping artifact was accepted")
	}
}

func TestDeploymentValidationRejectsUnsafeIdentities(t *testing.T) {
	base := Deployment{
		APIVersion: APIVersion, Name: "host",
		Runtime: Runtime{
			Manifest:  Reference{Path: "manifest", SHA256: "sha256:" + strings.Repeat("0", 64)},
			Signature: Reference{Path: "signature", SHA256: "sha256:" + strings.Repeat("1", 64)},
			PublicKey: Reference{Path: "key", SHA256: "sha256:" + strings.Repeat("2", 64)},
		},
		Agents:     []Agent{{ID: "agent", ClientID: "client", UnixUser: "agent", AccountMode: "managed", Home: "/var/lib/agent", Shell: "/usr/sbin/nologin", ComponentIDs: []string{"github"}}},
		Operators:  []Operator{{ID: "operator", UnixUser: "operator"}},
		Components: []Component{{ID: "github", Profile: Reference{Path: "component", SHA256: "sha256:" + strings.Repeat("3", 64)}}},
	}
	if err := base.Validate(); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		edit func(*Deployment)
	}{
		{"version", func(value *Deployment) { value.APIVersion = "old" }},
		{"name", func(value *Deployment) { value.Name = "bad name" }},
		{"agent mode", func(value *Deployment) { value.Agents[0].AccountMode = "root" }},
		{"agent user", func(value *Deployment) { value.Agents[0].UnixUser = "bad user" }},
		{"agent shell", func(value *Deployment) { value.Agents[0].Shell = "/bin/bash" }},
		{"operator", func(value *Deployment) { value.Operators[0].UnixUser = "bad user" }},
		{"component", func(value *Deployment) { value.Components[0].ID = "bad id" }},
		{"unknown binding", func(value *Deployment) { value.Agents[0].ComponentIDs = []string{"missing"} }},
		{"integration", func(value *Deployment) {
			value.Integrations = []Integration{{ID: "one", Kind: "two", AgentID: "agent", Profile: base.Components[0].Profile}}
		}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			value := base
			value.Agents = append([]Agent(nil), base.Agents...)
			value.Operators = append([]Operator(nil), base.Operators...)
			value.Components = append([]Component(nil), base.Components...)
			test.edit(&value)
			if err := value.Validate(); err == nil {
				t.Fatal("unsafe deployment was accepted")
			}
		})
	}
}

func TestRuntimeComponentAndNestedReferenceValidation(t *testing.T) {
	setup := &bundle.SetupAdapter{Protocol: "brokerkit.io/setup-component/v1", Arguments: []string{"setup-component"}}
	deployment := Deployment{Components: []Component{{ID: "github"}}}
	if err := deployment.validateRuntimeComponents(bundle.Manifest{Components: []bundle.Component{{Name: "github", Setup: setup}}}); err != nil {
		t.Fatal(err)
	}
	if err := deployment.validateRuntimeComponents(bundle.Manifest{}); err == nil {
		t.Fatal("missing runtime component was accepted")
	}
	if err := deployment.validateRuntimeComponents(bundle.Manifest{Components: []bundle.Component{{Name: "github"}}}); err == nil {
		t.Fatal("component without setup adapter was accepted")
	}
	deployment.Components = nil
	deployment.Integrations = []Integration{{ID: "openclaw", Kind: "openclaw"}}
	if err := deployment.validateRuntimeComponents(bundle.Manifest{}); err == nil {
		t.Fatal("missing integration adapter was accepted")
	}

	data := []byte(`{"files":[{"source":{"path":"policy.json","sha256":"sha256:` + strings.Repeat("a", 64) + `"}}]}`)
	references, err := nestedReferences(data)
	if err != nil || len(references) != 1 || references[0].Path != "policy.json" {
		t.Fatalf("nestedReferences() = %#v, %v", references, err)
	}
	for _, invalid := range [][]byte{
		[]byte(`{"a":1,"a":2}`),
		[]byte(`{"source":{"path":"../escape","sha256":"sha256:` + strings.Repeat("a", 64) + `"}}`),
	} {
		if _, err := nestedReferences(invalid); err == nil {
			t.Fatalf("invalid nested reference was accepted: %s", invalid)
		}
	}
	if compare("a", "b") != -1 || compare("b", "a") != 1 || compare("a", "a") != 0 {
		t.Fatal("canonical comparator is incorrect")
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

func hash(value []byte) string {
	sum := sha256.Sum256(value)
	return "sha256:" + fmtHex(sum[:])
}

func fmtHex(value []byte) string {
	const digits = "0123456789abcdef"
	result := make([]byte, len(value)*2)
	for index, current := range value {
		result[index*2] = digits[current>>4]
		result[index*2+1] = digits[current&15]
	}
	return string(result)
}
