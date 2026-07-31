package compiler

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/osolmaz/unyolo/deployment/component"
	"github.com/osolmaz/unyolo/internal/host/bundle"
	"github.com/osolmaz/unyolo/protocol/contract"
	"github.com/osolmaz/unyolo/setup/installation"
	setupintent "github.com/osolmaz/unyolo/setup/intent"
)

func compilerInstallation() installation.Installation {
	return installation.Installation{
		APIVersion: installation.APIVersion, Name: installation.DefaultName,
		CredentialService: setupintent.CredentialService{Location: setupintent.ServiceNative, Providers: []string{"github"}},
		Approvers:         []installation.Approver{{ID: "onur", Account: "onur"}},
		Connections: []installation.Connection{
			{ID: "bob", ClientID: "bob", Target: installation.Target{Kind: installation.TargetLocalAccount, Isolation: "separate", AccountMode: setupintent.AccountExisting, Account: "bob", Home: "/home/bob", Shell: "/bin/bash", UID: 1000, GID: 1000}, Providers: []string{"github"}},
			{ID: "remote", ClientID: "remote", Target: installation.Target{Kind: installation.TargetRemote, Isolation: "remote", RemoteName: "workstation"}, Providers: []string{"github"}},
		},
	}
}

func TestCompileDeploymentBindsInstallationAndTargets(t *testing.T) {
	t.Parallel()
	source := compilerInstallation()
	manifest := bundle.Manifest{
		Components: []bundle.Component{{Name: "github", Source: "artifacts/gh-broker"}},
	}
	providers := []SourceProvider{{APIVersion: SourceProviderAPIVersion, ID: "github", Components: []string{"github"}, Profile: "profile.json"}}
	sourceDigest := "sha256:" + strings.Repeat("1", 64)
	first, err := compileDeployment(source, providers, manifest, sourceDigest)
	if err != nil {
		t.Fatal(err)
	}
	second, err := compileDeployment(source, providers, manifest, sourceDigest)
	if err != nil {
		t.Fatal(err)
	}
	firstJSON, _ := json.Marshal(first)
	secondJSON, _ := json.Marshal(second)
	if string(firstJSON) != string(secondJSON) || first.InstallationDigest == "" {
		t.Fatal("deployment compilation is not deterministic or digest-bound")
	}
	if len(first.Agents) != 2 || first.Agents[0].Target.UnixUser != "bob" || first.Agents[1].Target.Kind != "remote" {
		t.Fatalf("compiled agents = %#v", first.Agents)
	}
	// Server-only installations retain their approvers even without any connections.
	source.Connections = nil
	serverOnly, err := compileDeployment(source, providers, manifest, sourceDigest)
	if err != nil || len(serverOnly.Agents) != 0 {
		t.Fatalf("server-only deployment = %#v, %v", serverOnly.Agents, err)
	}
}

func TestCompileProducesDeterministicByteIdenticalOutput(t *testing.T) {
	t.Parallel()
	sourceSet := buildTestSourceSet(t)
	firstDir := filepath.Join(t.TempDir(), "first")
	first, err := Compile(Options{Installation: compilerInstallation(), SourceSet: sourceSet, Destination: firstDir})
	if err != nil {
		t.Fatalf("Compile() first: %v", err)
	}
	secondDir := filepath.Join(t.TempDir(), "second")
	second, err := Compile(Options{Installation: compilerInstallation(), SourceSet: sourceSet, Destination: secondDir})
	if err != nil {
		t.Fatalf("Compile() second: %v", err)
	}
	if first.Digest != second.Digest {
		t.Fatalf("compilation is not deterministic: %q vs %q", first.Digest, second.Digest)
	}
	if len(first.Files) != len(second.Files) {
		t.Fatalf("file count mismatch: %d vs %d", len(first.Files), len(second.Files))
	}
	for path, file := range first.Files {
		mirror, ok := second.Files[path]
		if !ok || mirror.SHA256 != file.SHA256 || string(mirror.Data) != string(file.Data) {
			t.Fatalf("compilation output differs at %q", path)
		}
	}
}

func TestCompileRejectsMissingProvider(t *testing.T) {
	t.Parallel()
	sourceSet := buildTestSourceSet(t)
	source := compilerInstallation()
	source.CredentialService.Providers = []string{"missing"}
	dest := filepath.Join(t.TempDir(), "compiled")
	if _, err := Compile(Options{Installation: source, SourceSet: sourceSet, Destination: dest}); err == nil {
		t.Fatal("Compile() accepted a provider that is absent from the source set")
	}
}

func buildTestSourceSet(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, directory := range []string{"artifacts", "runtime", "providers", "integrations", filepath.Join("platform", runtime.GOOS)} {
		if err := os.MkdirAll(filepath.Join(root, directory), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := os.ReadFile(executable)
	if err != nil {
		t.Fatal(err)
	}
	artifactDigest := sha256.Sum256(artifact)
	if err := os.WriteFile(filepath.Join(root, "artifacts", "gh-broker"), artifact, 0o700); err != nil {
		t.Fatal(err)
	}
	manifest := bundle.Manifest{
		APIVersion: bundle.APIVersion, BundleID: "test-bundle", SourceCommit: strings.Repeat("a", 40),
		OperatingSystem: runtime.GOOS, Architecture: runtime.GOARCH,
		OperatorContractDigest: contract.OperatorV1Digest, AgentContractDigest: contract.AgentV1Digest,
		SetupCapabilities: bundle.SetupCapabilities{
			NativeServiceBackend: "systemd", Features: []string{"native_service", "local_accounts", "local_socket"},
		},
		Components: []bundle.Component{{
			Name: "github", Source: "artifacts/gh-broker", Destination: "bin/gh-broker",
			SHA256: "sha256:" + hexOf(artifactDigest[:]), BuildID: "test", Role: bundle.RoleProvider,
			Services:            []string{"gh-broker.service"},
			AgentContractDigest: contract.AgentV1Digest,
			StateFormatDigest:   "sha256:" + strings.Repeat("0", 64), Required: false,
			Setup: &bundle.SetupAdapter{
				Protocol:  "unyolo.io/setup-component/v1",
				Arguments: []string{"setup-component"},
				Ownership: bundle.OwnershipEnvelope{
					Paths:    []string{"/etc/gh-broker"},
					Services: []string{"gh-broker.service"},
					Accounts: []string{"gh-broker"},
					Groups:   []string{"gh-broker", "gh-broker-agent", "gh-broker-operator"},
				},
			},
		}},
	}
	manifestData, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	manifestData = append(manifestData, '\n')
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	writeTestSourceFile(t, filepath.Join(root, "runtime", "manifest.json"), manifestData)
	writeTestSourceFile(t, filepath.Join(root, "runtime", "manifest.sig"), []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, manifestData))+"\n"))
	writeTestSourceFile(t, filepath.Join(root, "runtime", "release.pub"), []byte(base64.StdEncoding.EncodeToString(publicKey)+"\n"))

	profileTemplate := `{
  "api_version": "unyolo.io/github-deployment/v1",
  "accounts": [{"name": "gh-broker", "group": "gh-broker", "home": "/etc/gh-broker", "shell": "/usr/sbin/nologin"}],
  "groups": [
    {"name": "gh-broker"},
    {"name": "gh-broker-agent", "members": []},
    {"name": "gh-broker-operator", "members": []}
  ],
  "directories": [
    {"id": "config", "destination": "/etc/gh-broker", "mode": 488, "owner": "root", "group": "gh-broker"}
  ],
  "credentials": [
    {"slot": "github-agent-secret", "destination": "/etc/gh-broker/secrets", "mode": 384, "owner": "gh-broker", "group": "gh-broker", "encoding": "client_secret_file", "client_id": "agent"},
    {"slot": "github-operator-secret", "destination": "/etc/gh-broker/operator-secrets", "mode": 384, "owner": "gh-broker", "group": "gh-broker", "encoding": "client_secret_file", "client_id": "operator"}
  ],
  "clients": [
    {"agent_id": "agent", "broker_name": "gh-broker", "env_prefix": "GH_BROKER", "secret_slot": "github-agent-secret", "endpoint": "unix:///run/unyolo/github/agent/broker.sock"}
  ],
  "services": ["gh-broker.service"]
}
`
	providerRoot := filepath.Join(root, "providers", "github")
	if err := os.MkdirAll(providerRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	writeTestSourceFile(t, filepath.Join(providerRoot, "profile.json"), []byte(profileTemplate))
	source := SourceProvider{
		APIVersion: SourceProviderAPIVersion, ID: "github", Components: []string{"github"}, Profile: "profile.json",
		RenderArguments: []string{"-test.run=TestCompilerRenderHelperProcess", "--", "setup-component-render-helper"},
		Ownership: bundle.OwnershipEnvelope{
			Paths: []string{"/etc/gh-broker"}, Services: []string{"gh-broker.service"},
			Accounts: []string{"gh-broker"}, Groups: []string{"gh-broker", "gh-broker-agent", "gh-broker-operator"},
		},
	}
	sourceData, err := json.MarshalIndent(source, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	sourceData = append(sourceData, '\n')
	writeTestSourceFile(t, filepath.Join(providerRoot, "source.json"), sourceData)
	return root
}

func TestCompilerRenderHelperProcess(t *testing.T) {
	if !slices.Contains(os.Args, "setup-component-render-helper") {
		return
	}
	if err := component.ServeRender(os.Stdin, os.Stdout, component.StandardRenderer{}); err != nil {
		_, _ = os.Stderr.WriteString(err.Error() + "\n")
		os.Exit(2)
	}
	os.Exit(0)
}

func writeTestSourceFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func hexOf(data []byte) string {
	const digits = "0123456789abcdef"
	result := make([]byte, len(data)*2)
	for index, current := range data {
		result[index*2] = digits[current>>4]
		result[index*2+1] = digits[current&15]
	}
	return string(result)
}
