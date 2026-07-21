package bundle

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/osolmaz/brokerkit/protocol/contract"
)

func TestLoadRequiresValidDetachedSignature(t *testing.T) {
	manifest := testManifest(t, "bundle-one", "one")
	data, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	manifestPath := filepath.Join(dir, "manifest.json")
	signaturePath := filepath.Join(dir, "manifest.sig")
	publicPath := filepath.Join(dir, "manifest.pub")
	writeTestFile(t, manifestPath, data)
	writeTestFile(t, signaturePath, []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, data))))
	writeTestFile(t, publicPath, []byte(base64.StdEncoding.EncodeToString(publicKey)))
	loaded, loadedData, err := Load(manifestPath, signaturePath, publicPath, false)
	if err != nil || loaded.BundleID != manifest.BundleID || string(loadedData) != string(data) {
		t.Fatalf("Load() = %+v, %v", loaded, err)
	}
	writeTestFile(t, signaturePath, []byte(base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))))
	if _, _, err := Load(manifestPath, signaturePath, publicPath, false); err == nil {
		t.Fatal("Load() accepted an invalid signature")
	}
}

func TestHostPinsOneReleaseTrustRoot(t *testing.T) {
	state, keys := t.TempDir(), t.TempDir()
	publicOne, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicTwo, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	one, two := filepath.Join(keys, "one.pub"), filepath.Join(keys, "two.pub")
	writeTestFile(t, one, []byte(base64.StdEncoding.EncodeToString(publicOne)))
	writeTestFile(t, two, []byte(base64.StdEncoding.EncodeToString(publicTwo)))
	selected, needsPin, err := TrustedPublicKey(state, one)
	if err != nil || selected != one || !needsPin {
		t.Fatalf("TrustedPublicKey() = %q, %v, %v", selected, needsPin, err)
	}
	pinned, err := PinTrustedPublicKey(state, one)
	if err != nil || filepath.Base(pinned) != trustedKeyFilename {
		t.Fatalf("PinTrustedPublicKey() = %q, %v", pinned, err)
	}
	selected, needsPin, err = TrustedPublicKey(state, "")
	if err != nil || selected != pinned || needsPin {
		t.Fatalf("pinned TrustedPublicKey() = %q, %v, %v", selected, needsPin, err)
	}
	if _, _, err := TrustedPublicKey(state, two); err == nil {
		t.Fatal("host accepted a different release trust root")
	}
}

func TestOperatorProbeRequiresAuthenticatedExpectedBuild(t *testing.T) {
	token := strings.Repeat("t", 32)
	buildID := "gh-broker-v1"
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/.well-known/brokerkit-operator":
			if request.Header.Get("Authorization") != "Bearer "+token {
				http.Error(writer, `{}`, http.StatusUnauthorized)
				return
			}
			_, _ = fmt.Fprintf(writer, `{"api_version":"brokerkit.io/operator/v1","contract_digest":%q,"build_id":%q}`, contract.OperatorV1Digest, buildID)
		case "/healthz":
			_, _ = fmt.Fprintf(writer, `{"status":"ok","contract_digest":%q,"build_id":%q}`, contract.OperatorV1Digest, buildID)
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()
	tokenPath := filepath.Join(t.TempDir(), "operator-token")
	writeTestFile(t, tokenPath, []byte(token+"\n"))
	component := Component{OperatorEndpoint: strings.Replace(server.URL, "http://", "tcp://", 1), OperatorTokenFile: tokenPath, BuildID: buildID}
	if err := operatorProbe(t.Context(), component); err != nil {
		t.Fatal(err)
	}
	component.BuildID = "different-build"
	if err := operatorProbe(t.Context(), component); err == nil {
		t.Fatal("operator build mismatch was accepted")
	}
	writeTestFile(t, tokenPath, []byte("\n"))
	if err := operatorProbe(t.Context(), component); err == nil {
		t.Fatal("empty operator token was accepted")
	}
}

func TestOperatorProbeRejectsMissingTokenAndInvalidEndpoint(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing-token")
	if _, err := readOperatorToken(missing); err == nil {
		t.Fatal("missing operator token was accepted")
	}
	tokenPath := filepath.Join(t.TempDir(), "operator-token")
	writeTestFile(t, tokenPath, []byte(strings.Repeat("t", 32)))
	if err := operatorProbe(t.Context(), Component{OperatorEndpoint: "invalid", OperatorTokenFile: tokenPath}); err == nil {
		t.Fatal("invalid operator endpoint was accepted")
	}
}

func TestDefaultPathsMatchPlatform(t *testing.T) {
	original := runtimeGOOS
	t.Cleanup(func() { runtimeGOOS = original })
	runtimeGOOS = func() string { return "darwin" }
	if got := DefaultPaths(); !strings.Contains(got.Root, "Application Support") || got.Root != got.StateDir {
		t.Fatalf("darwin paths = %+v", got)
	}
	runtimeGOOS = func() string { return "linux" }
	if got := DefaultPaths(); got.Root != "/opt/brokerkit" || got.StateDir != "/var/lib/brokerkit-host" {
		t.Fatalf("linux paths = %+v", got)
	}
}

func TestInstallerNormalizeRequiresHostDependencies(t *testing.T) {
	empty := Installer{}
	if err := empty.normalize(); err == nil {
		t.Fatal("empty installer was accepted")
	}
	paths := Paths{Root: filepath.Join(t.TempDir(), "root"), StateDir: filepath.Join(t.TempDir(), "state")}
	installer := Installer{Paths: paths}
	if err := installer.normalize(); err == nil {
		t.Fatal("installer without a service manager was accepted")
	}
	installer.Manager = &fakeManager{}
	if err := installer.normalize(); err != nil || installer.Now == nil || installer.Probe == nil {
		t.Fatalf("normalize() error = %v, dependencies assigned = %t", err, installer.Now != nil && installer.Probe != nil)
	}
}

func TestManifestValidationFailsClosed(t *testing.T) {
	tests := map[string]func(*Manifest){
		"api version":          func(value *Manifest) { value.APIVersion = "unknown" },
		"identity":             func(value *Manifest) { value.BundleID = "../bad" },
		"platform":             func(value *Manifest) { value.Architecture = "unknown" },
		"protocol":             func(value *Manifest) { value.AgentContractDigest = "sha256:" + strings.Repeat("f", 64) },
		"no components":        func(value *Manifest) { value.Components = nil },
		"duplicate component":  func(value *Manifest) { value.Components = append(value.Components, value.Components[0]) },
		"unsafe source":        func(value *Manifest) { value.Components[0].Source = "../binary" },
		"bad artifact digest":  func(value *Manifest) { value.Components[0].SHA256 = "bad" },
		"unsafe state":         func(value *Manifest) { value.Components[0].StateDir = "relative" },
		"unsafe token":         func(value *Manifest) { value.Components[0].OperatorTokenFile = "relative" },
		"replacement no state": func(value *Manifest) { value.Components[0].StateDir, value.Components[0].ReplaceState = "", true },
		"development build":    func(value *Manifest) { value.Components[0].BuildID = "dev-build" },
		"bad role":             func(value *Manifest) { value.Components[0].Role = "root" },
		"duplicate service":    func(value *Manifest) { value.Components[1].Services = []string{"gh.service"} },
		"unpaired endpoint":    func(value *Manifest) { value.Components[0].OperatorTokenFile = "" },
		"provider no endpoint": func(value *Manifest) {
			value.Components[0].OperatorEndpoint, value.Components[0].OperatorTokenFile = "", ""
		},
		"operator protocol": func(value *Manifest) {
			value.Components[0].OperatorContractDigest = "sha256:" + strings.Repeat("f", 64)
		},
		"agent protocol":      func(value *Manifest) { value.Components[0].AgentContractDigest = "sha256:" + strings.Repeat("f", 64) },
		"required no service": func(value *Manifest) { value.Components[0].Services = nil },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			manifest := testManifest(t, "bundle-one", "one")
			mutate(&manifest)
			if err := manifest.Validate(false); err == nil {
				t.Fatal("invalid manifest was accepted")
			}
		})
	}
}

func TestActivateRejectsManifestByteMismatch(t *testing.T) {
	root, state, artifacts := filepath.Join(t.TempDir(), "root"), filepath.Join(t.TempDir(), "state"), t.TempDir()
	manifest, data := writeManifestArtifacts(t, artifacts, testManifest(t, "bundle-one", "one"))
	manifest.BundleID = "bundle-two"
	installer := Installer{Paths: Paths{Root: root, StateDir: state}, Manager: &fakeManager{}, Probe: func(context.Context, Component) error { return nil }}
	if err := installer.Activate(t.Context(), manifest, data, artifacts); err == nil {
		t.Fatal("activation accepted manifest bytes for a different bundle")
	}
}

func TestStageRejectsRelativeArtifactsAndChangedBundleIdentity(t *testing.T) {
	root, artifacts := filepath.Join(t.TempDir(), "root"), t.TempDir()
	installer := Installer{Paths: Paths{Root: root, StateDir: filepath.Join(t.TempDir(), "state")}}
	manifest, data := writeManifestArtifacts(t, artifacts, testManifest(t, "bundle-one", "one"))
	if _, err := installer.stage(manifest, data, "relative"); err == nil {
		t.Fatal("relative artifact directory was accepted")
	}
	if _, err := installer.stage(manifest, data, artifacts); err != nil {
		t.Fatal(err)
	}
	if _, err := installer.stage(manifest, append(append([]byte(nil), data...), '\n'), artifacts); err == nil {
		t.Fatal("existing bundle identity accepted different manifest bytes")
	}
	stagedArtifact := filepath.Join(root, "releases", manifest.BundleID, manifest.Components[0].Destination)
	if err := os.Chmod(stagedArtifact, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(stagedArtifact, []byte("changed"), 0o555); err != nil {
		t.Fatal(err)
	}
	if err := installer.verifyRelease(manifest, filepath.Join(root, "releases", manifest.BundleID)); err == nil {
		t.Fatal("changed immutable release artifact was accepted")
	}
	missing := testManifest(t, "bundle-two", "two")
	missing, missingData := writeManifestArtifacts(t, artifacts, missing)
	if err := os.Remove(filepath.Join(artifacts, missing.Components[0].Source)); err != nil {
		t.Fatal(err)
	}
	if _, err := installer.stage(missing, missingData, artifacts); err == nil {
		t.Fatal("bundle with a missing artifact was staged")
	}
}

func TestReadActivationRejectsInvalidRecord(t *testing.T) {
	state := t.TempDir()
	installer := Installer{Paths: Paths{Root: filepath.Join(t.TempDir(), "root"), StateDir: state}}
	path := filepath.Join(state, activationFilename)
	for _, data := range [][]byte{[]byte("{"), []byte(`{"api_version":"unknown"}`)} {
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := installer.readActivation(); err == nil {
			t.Fatal("invalid activation record was accepted")
		}
	}
}

func TestActivationLockRejectsConcurrentOwner(t *testing.T) {
	state := t.TempDir()
	first, err := acquireLock(state)
	if err != nil {
		t.Fatal(err)
	}
	defer first.close()
	if _, err := acquireLock(state); err == nil {
		t.Fatal("concurrent activation lock was acquired")
	}
}

func TestClearMissingTransactionIsIdempotent(t *testing.T) {
	state := t.TempDir()
	installer := Installer{Paths: Paths{StateDir: state}}
	if err := installer.clearTransaction(); err != nil {
		t.Fatal(err)
	}
}

func TestBoundedReadAndDigestRejectInvalidFiles(t *testing.T) {
	path := filepath.Join(t.TempDir(), "value")
	writeTestFile(t, path, []byte("too-large"))
	if _, err := readBounded(path, 1); err == nil {
		t.Fatal("oversized bounded file was accepted")
	}
	if _, err := digestFile(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("missing digest source was accepted")
	}
}

func TestActivateOrdersServicesAndRollsBackCompleteRelease(t *testing.T) {
	root, state, artifacts := filepath.Join(t.TempDir(), "root"), filepath.Join(t.TempDir(), "state"), t.TempDir()
	manager := &fakeManager{root: root, destinations: map[string]string{"gh.service": "bin/gh", "telegram.service": "bin/telegram"}, active: map[string]bool{}}
	installer := Installer{Paths: Paths{Root: root, StateDir: state}, Manager: manager,
		Probe: func(_ context.Context, component Component) error {
			if component.BuildID == "two" && component.Role == RoleConsumer {
				return errors.New("injected readiness failure")
			}
			return nil
		}}
	one, oneData := writeManifestArtifacts(t, artifacts, testManifest(t, "bundle-one", "one"))
	if err := installer.Activate(t.Context(), one, oneData, artifacts); err != nil {
		t.Fatal(err)
	}
	if err := installer.Activate(t.Context(), one, oneData, artifacts); err != nil {
		t.Fatalf("idempotent activation failed: %v", err)
	}
	assertCurrentBundle(t, root, "bundle-one")
	if strings.Join(manager.actions, ",") != "reload,start:gh.service,start:telegram.service" {
		t.Fatalf("first activation order = %v", manager.actions)
	}
	manager.actions = nil
	two, twoData := writeManifestArtifacts(t, artifacts, testManifest(t, "bundle-two", "two"))
	if err := installer.Activate(t.Context(), two, twoData, artifacts); err == nil {
		t.Fatal("candidate readiness failure did not roll back")
	}
	assertCurrentBundle(t, root, "bundle-one")
	actions := strings.Join(manager.actions, ",")
	if !strings.HasPrefix(actions, "stop:telegram.service,stop:gh.service,reload,start:gh.service,start:telegram.service") ||
		!strings.HasSuffix(actions, "stop:telegram.service,stop:gh.service,reload,start:gh.service,start:telegram.service") {
		t.Fatalf("upgrade and rollback order = %s", actions)
	}
	report, err := installer.Status(t.Context())
	if err != nil || !report.Healthy || report.Activation.ActiveBundleID != "bundle-one" {
		t.Fatalf("Status() = %+v, %v", report, err)
	}
}

func TestStatusRejectsDeletedOrDifferentExecutable(t *testing.T) {
	root, state, artifacts := filepath.Join(t.TempDir(), "root"), filepath.Join(t.TempDir(), "state"), t.TempDir()
	manager := &fakeManager{root: root, destinations: map[string]string{"gh.service": "bin/gh", "telegram.service": "bin/telegram"}, active: map[string]bool{}}
	installer := Installer{Paths: Paths{Root: root, StateDir: state}, Manager: manager, Probe: func(context.Context, Component) error { return nil }}
	manifest, data := writeManifestArtifacts(t, artifacts, testManifest(t, "bundle-one", "one"))
	if err := installer.Activate(t.Context(), manifest, data, artifacts); err != nil {
		t.Fatal(err)
	}
	manager.deleted = "telegram.service"
	report, err := installer.Status(t.Context())
	if err != nil || report.Healthy || len(report.Problems) == 0 {
		t.Fatalf("Status() = %+v, %v", report, err)
	}
}

func TestStatusReportsAuthenticatedReadinessFailure(t *testing.T) {
	root, state, artifacts := filepath.Join(t.TempDir(), "root"), filepath.Join(t.TempDir(), "state"), t.TempDir()
	manager := &fakeManager{root: root, destinations: map[string]string{"gh.service": "bin/gh", "telegram.service": "bin/telegram"}, active: map[string]bool{}}
	failProbe := false
	installer := Installer{Paths: Paths{Root: root, StateDir: state}, Manager: manager, Probe: func(context.Context, Component) error {
		if failProbe {
			return errors.New("route unavailable")
		}
		return nil
	}}
	manifest, data := writeManifestArtifacts(t, artifacts, testManifest(t, "bundle-one", "one"))
	if err := installer.Activate(t.Context(), manifest, data, artifacts); err != nil {
		t.Fatal(err)
	}
	failProbe = true
	report, err := installer.Status(t.Context())
	if err != nil || report.Healthy || !strings.Contains(strings.Join(report.Problems, "\n"), "readiness check failed") {
		t.Fatalf("Status() = %+v, %v", report, err)
	}
}

func TestActivateRollsBackWhenServiceKeepsRunningPreviousExecutable(t *testing.T) {
	root, state, artifacts := filepath.Join(t.TempDir(), "root"), filepath.Join(t.TempDir(), "state"), t.TempDir()
	manager := &fakeManager{root: root, destinations: map[string]string{"gh.service": "bin/gh", "telegram.service": "bin/telegram"}, active: map[string]bool{}}
	installer := Installer{Paths: Paths{Root: root, StateDir: state}, Manager: manager, Probe: func(context.Context, Component) error { return nil }}
	one, oneData := writeManifestArtifacts(t, artifacts, testManifest(t, "bundle-one", "one"))
	if err := installer.Activate(t.Context(), one, oneData, artifacts); err != nil {
		t.Fatal(err)
	}
	manager.staleService = "telegram.service"
	two, twoData := writeManifestArtifacts(t, artifacts, testManifest(t, "bundle-two", "two"))
	if err := installer.Activate(t.Context(), two, twoData, artifacts); err == nil {
		t.Fatal("activation accepted a service running the previous executable")
	}
	assertCurrentBundle(t, root, "bundle-one")
}

func TestActivateRecordsRecoveryRequiredWhenRollbackFails(t *testing.T) {
	root, state, artifacts := filepath.Join(t.TempDir(), "root"), filepath.Join(t.TempDir(), "state"), t.TempDir()
	manager := &fakeManager{root: root, destinations: map[string]string{"gh.service": "bin/gh", "telegram.service": "bin/telegram"}, active: map[string]bool{}}
	installer := Installer{Paths: Paths{Root: root, StateDir: state}, Manager: manager,
		Probe: func(_ context.Context, component Component) error {
			if component.BuildID == "two" && component.Role == RoleConsumer {
				return errors.New("injected readiness failure")
			}
			return nil
		}}
	one, oneData := writeManifestArtifacts(t, artifacts, testManifest(t, "bundle-one", "one"))
	if err := installer.Activate(t.Context(), one, oneData, artifacts); err != nil {
		t.Fatal(err)
	}
	manager.failStartBundle = "bundle-one"
	two, twoData := writeManifestArtifacts(t, artifacts, testManifest(t, "bundle-two", "two"))
	if err := installer.Activate(t.Context(), two, twoData, artifacts); err == nil {
		t.Fatal("activation succeeded despite failed rollback")
	}
	record, err := installer.readActivation()
	if err != nil || !record.RecoveryRequired || record.ActiveBundleID != "bundle-one" {
		t.Fatalf("recovery record = %+v, %v", record, err)
	}
}

func TestActivateRecoversPreviousServicesAfterPartialStopFailure(t *testing.T) {
	root, state, artifacts := filepath.Join(t.TempDir(), "root"), filepath.Join(t.TempDir(), "state"), t.TempDir()
	manager := &fakeManager{root: root, destinations: map[string]string{"gh.service": "bin/gh", "telegram.service": "bin/telegram"}, active: map[string]bool{}}
	installer := Installer{Paths: Paths{Root: root, StateDir: state}, Manager: manager, Probe: func(context.Context, Component) error { return nil }}
	one, oneData := writeManifestArtifacts(t, artifacts, testManifest(t, "bundle-one", "one"))
	if err := installer.Activate(t.Context(), one, oneData, artifacts); err != nil {
		t.Fatal(err)
	}
	manager.failStopOnce = "gh.service"
	two, twoData := writeManifestArtifacts(t, artifacts, testManifest(t, "bundle-two", "two"))
	if err := installer.Activate(t.Context(), two, twoData, artifacts); err == nil {
		t.Fatal("activation succeeded despite a partial stop failure")
	}
	assertCurrentBundle(t, root, "bundle-one")
	if !manager.active["gh.service"] || !manager.active["telegram.service"] {
		t.Fatalf("previous services were not recovered: %v", manager.active)
	}
}

func TestFailedFirstActivationRestoresUninstalledState(t *testing.T) {
	root, state, artifacts := filepath.Join(t.TempDir(), "root"), filepath.Join(t.TempDir(), "state"), t.TempDir()
	manager := &fakeManager{root: root, destinations: map[string]string{"gh.service": "bin/gh", "telegram.service": "bin/telegram"}, active: map[string]bool{}}
	installer := Installer{Paths: Paths{Root: root, StateDir: state}, Manager: manager,
		Probe: func(context.Context, Component) error { return errors.New("injected first-install readiness failure") }}
	manifest, data := writeManifestArtifacts(t, artifacts, testManifest(t, "bundle-one", "one"))
	if err := installer.Activate(t.Context(), manifest, data, artifacts); err == nil {
		t.Fatal("failed first activation was accepted")
	}
	if _, err := os.Lstat(filepath.Join(root, "current")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed first activation retained current: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(state, activationFilename)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed first activation retained activation record: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(state, transactionFilename)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed first activation retained transaction: %v", err)
	}
}

func TestStatusReportsInterruptedActivation(t *testing.T) {
	root, state, artifacts := filepath.Join(t.TempDir(), "root"), filepath.Join(t.TempDir(), "state"), t.TempDir()
	manager := &fakeManager{root: root, destinations: map[string]string{"gh.service": "bin/gh", "telegram.service": "bin/telegram"}, active: map[string]bool{}}
	installer := Installer{Paths: Paths{Root: root, StateDir: state}, Manager: manager, Probe: func(context.Context, Component) error { return nil }}
	manifest, data := writeManifestArtifacts(t, artifacts, testManifest(t, "bundle-one", "one"))
	if err := installer.Activate(t.Context(), manifest, data, artifacts); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(state, transactionFilename), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	report, err := installer.Status(t.Context())
	if err != nil || report.Healthy || !strings.Contains(strings.Join(report.Problems, "\n"), "interrupted activation") {
		t.Fatalf("Status() = %+v, %v", report, err)
	}
}

func TestStatusReportsCurrentPointerMismatch(t *testing.T) {
	root, state, artifacts := filepath.Join(t.TempDir(), "root"), filepath.Join(t.TempDir(), "state"), t.TempDir()
	manager := &fakeManager{root: root, destinations: map[string]string{"gh.service": "bin/gh", "telegram.service": "bin/telegram"}, active: map[string]bool{}}
	installer := Installer{Paths: Paths{Root: root, StateDir: state}, Manager: manager, Probe: func(context.Context, Component) error { return nil }}
	manifest, data := writeManifestArtifacts(t, artifacts, testManifest(t, "bundle-one", "one"))
	if err := installer.Activate(t.Context(), manifest, data, artifacts); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(root, "current")); err != nil {
		t.Fatal(err)
	}
	report, err := installer.Status(t.Context())
	if err != nil || report.Healthy || !strings.Contains(strings.Join(report.Problems, "\n"), "pointer") {
		t.Fatalf("Status() = %+v, %v", report, err)
	}
}

func TestRollbackRequiresPreviousBundle(t *testing.T) {
	root, state, artifacts := filepath.Join(t.TempDir(), "root"), filepath.Join(t.TempDir(), "state"), t.TempDir()
	manager := &fakeManager{root: root, destinations: map[string]string{"gh.service": "bin/gh", "telegram.service": "bin/telegram"}, active: map[string]bool{}}
	installer := Installer{Paths: Paths{Root: root, StateDir: state}, Manager: manager, Probe: func(context.Context, Component) error { return nil }}
	manifest, data := writeManifestArtifacts(t, artifacts, testManifest(t, "bundle-one", "one"))
	if err := installer.Activate(t.Context(), manifest, data, artifacts); err != nil {
		t.Fatal(err)
	}
	if err := installer.Rollback(t.Context()); err == nil {
		t.Fatal("rollback without a previous bundle was accepted")
	}
}

func TestMissingStateReplacementAndRecoveryRecord(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "provider-state")
	backup := stateDir + ".backup"
	if err := replaceStateDirectory(stateDir, backup); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(stateDir); err != nil || !info.IsDir() {
		t.Fatalf("replacement state = %+v, %v", info, err)
	}
	if err := restoreStateDirectory(stateDir, backup); err != nil {
		t.Fatal(err)
	}
	hostState := t.TempDir()
	installer := Installer{Paths: Paths{Root: filepath.Join(t.TempDir(), "root"), StateDir: hostState}, Now: time.Now}
	if err := installer.writeRecoveryRecord("", "bundle-one"); err != nil {
		t.Fatal(err)
	}
	record, err := installer.readActivation()
	if err != nil || !record.RecoveryRequired || record.ActiveBundleID != "bundle-one" {
		t.Fatalf("recovery record = %+v, %v", record, err)
	}
}

func TestInterruptedActivationRestoresPreviousReleaseAndRecord(t *testing.T) {
	root, state, artifacts := filepath.Join(t.TempDir(), "root"), filepath.Join(t.TempDir(), "state"), t.TempDir()
	manager := &fakeManager{root: root, destinations: map[string]string{"gh.service": "bin/gh", "telegram.service": "bin/telegram"}, active: map[string]bool{}}
	installer := Installer{Paths: Paths{Root: root, StateDir: state}, Manager: manager, Probe: func(context.Context, Component) error { return nil }}
	one, oneData := writeManifestArtifacts(t, artifacts, testManifest(t, "bundle-one", "one"))
	if err := installer.Activate(t.Context(), one, oneData, artifacts); err != nil {
		t.Fatal(err)
	}
	previous, err := installer.activationSnapshot()
	if err != nil || previous == nil {
		t.Fatalf("activationSnapshot() = %+v, %v", previous, err)
	}
	two, twoData := writeManifestArtifacts(t, artifacts, testManifest(t, "bundle-two", "two"))
	if _, err := installer.stage(two, twoData, artifacts); err != nil {
		t.Fatal(err)
	}
	transaction := activationTransaction{APIVersion: APIVersion, CandidateBundleID: two.BundleID,
		PreviousBundleID: one.BundleID, PreviousActivation: previous,
		FinalActivation: Activation{APIVersion: APIVersion, ActiveBundleID: two.BundleID, PreviousBundleID: one.BundleID, ActivatedAt: time.Now().UTC()},
		StartedAt:       time.Now().UTC()}
	if err := writeJSONAtomic(filepath.Join(state, transactionFilename), transaction, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := installer.switchCurrent(two.BundleID); err != nil {
		t.Fatal(err)
	}
	if err := installer.recoverInterruptedActivation(); err != nil {
		t.Fatal(err)
	}
	assertCurrentBundle(t, root, one.BundleID)
	restored, err := installer.readActivation()
	if err != nil || restored.ActiveBundleID != one.BundleID || restored.RecoveryRequired {
		t.Fatalf("restored activation = %+v, %v", restored, err)
	}
	if _, err := os.Stat(filepath.Join(state, transactionFilename)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("completed recovery retained its transaction journal")
	}
}

func TestInterruptedActivationKeepsCommittedCandidate(t *testing.T) {
	root, state, artifacts := filepath.Join(t.TempDir(), "root"), filepath.Join(t.TempDir(), "state"), t.TempDir()
	manager := &fakeManager{root: root, destinations: map[string]string{"gh.service": "bin/gh", "telegram.service": "bin/telegram"}, active: map[string]bool{}}
	installer := Installer{Paths: Paths{Root: root, StateDir: state}, Manager: manager, Probe: func(context.Context, Component) error { return nil }}
	one, oneData := writeManifestArtifacts(t, artifacts, testManifest(t, "bundle-one", "one"))
	if err := installer.Activate(t.Context(), one, oneData, artifacts); err != nil {
		t.Fatal(err)
	}
	previous, err := installer.activationSnapshot()
	if err != nil || previous == nil {
		t.Fatalf("activationSnapshot() = %+v, %v", previous, err)
	}
	two, twoData := writeManifestArtifacts(t, artifacts, testManifest(t, "bundle-two", "two"))
	if _, err := installer.stage(two, twoData, artifacts); err != nil {
		t.Fatal(err)
	}
	final := Activation{APIVersion: APIVersion, ActiveBundleID: two.BundleID, PreviousBundleID: one.BundleID, ActivatedAt: time.Now().UTC()}
	transaction := activationTransaction{APIVersion: APIVersion, CandidateBundleID: two.BundleID,
		PreviousBundleID: one.BundleID, PreviousActivation: previous, FinalActivation: final, StartedAt: time.Now().UTC()}
	if err := writeJSONAtomic(filepath.Join(state, transactionFilename), transaction, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := installer.switchCurrent(two.BundleID); err != nil {
		t.Fatal(err)
	}
	if err := manager.Reload(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := installer.start(t.Context(), two); err != nil {
		t.Fatal(err)
	}
	if err := writeJSONAtomic(filepath.Join(state, activationFilename), final, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := installer.recoverInterruptedActivation(); err != nil {
		t.Fatal(err)
	}
	assertCurrentBundle(t, root, two.BundleID)
	restored, err := installer.readActivation()
	if err != nil || restored.ActiveBundleID != two.BundleID {
		t.Fatalf("committed activation = %+v, %v", restored, err)
	}
}

func TestInterruptedRollbackRestoresPreCommandBundle(t *testing.T) {
	root, state, artifacts := filepath.Join(t.TempDir(), "root"), filepath.Join(t.TempDir(), "state"), t.TempDir()
	manager := &fakeManager{root: root, destinations: map[string]string{"gh.service": "bin/gh", "telegram.service": "bin/telegram"}, active: map[string]bool{}}
	installer := Installer{Paths: Paths{Root: root, StateDir: state}, Manager: manager, Probe: func(context.Context, Component) error { return nil }}
	one, oneData := writeManifestArtifacts(t, artifacts, testManifest(t, "bundle-one", "one"))
	if err := installer.Activate(t.Context(), one, oneData, artifacts); err != nil {
		t.Fatal(err)
	}
	two, twoData := writeManifestArtifacts(t, artifacts, testManifest(t, "bundle-two", "two"))
	if err := installer.Activate(t.Context(), two, twoData, artifacts); err != nil {
		t.Fatal(err)
	}
	previous, err := installer.activationSnapshot()
	if err != nil || previous == nil {
		t.Fatalf("activationSnapshot() = %+v, %v", previous, err)
	}
	final := Activation{APIVersion: APIVersion, ActiveBundleID: one.BundleID, PreviousBundleID: two.BundleID, ActivatedAt: time.Now().UTC()}
	transaction := activationTransaction{APIVersion: APIVersion, CandidateBundleID: one.BundleID,
		PreviousBundleID: two.BundleID, PreviousActivation: previous, FinalActivation: final, StartedAt: time.Now().UTC()}
	if err := writeJSONAtomic(filepath.Join(state, transactionFilename), transaction, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := installer.switchCurrent(one.BundleID); err != nil {
		t.Fatal(err)
	}
	if err := installer.recoverInterruptedActivation(); err != nil {
		t.Fatal(err)
	}
	assertCurrentBundle(t, root, two.BundleID)
	restored, err := installer.readActivation()
	if err != nil || restored.ActiveBundleID != two.BundleID || restored.PreviousBundleID != one.BundleID {
		t.Fatalf("restored activation = %+v, %v", restored, err)
	}
}

func TestActivationTransactionValidation(t *testing.T) {
	now := time.Now().UTC()
	previous := Activation{APIVersion: APIVersion, ActiveBundleID: "bundle-one", ActivatedAt: now}
	valid := activationTransaction{APIVersion: APIVersion, CandidateBundleID: "bundle-two", PreviousBundleID: "bundle-one",
		PreviousActivation: &previous,
		FinalActivation:    Activation{APIVersion: APIVersion, ActiveBundleID: "bundle-two", PreviousBundleID: "bundle-one", ActivatedAt: now},
		StartedAt:          now}
	if !validActivationTransaction(valid) {
		t.Fatal("valid activation transaction was rejected")
	}
	for name, mutate := range map[string]func(*activationTransaction){
		"api":            func(value *activationTransaction) { value.APIVersion = "unknown" },
		"started":        func(value *activationTransaction) { value.StartedAt = time.Time{} },
		"same bundle":    func(value *activationTransaction) { value.CandidateBundleID = value.PreviousBundleID },
		"missing prior":  func(value *activationTransaction) { value.PreviousActivation = nil },
		"recovery prior": func(value *activationTransaction) { value.PreviousActivation.RecoveryRequired = true },
		"wrong prior":    func(value *activationTransaction) { value.PreviousActivation.ActiveBundleID = "bundle-three" },
		"wrong final":    func(value *activationTransaction) { value.FinalActivation.ActiveBundleID = "bundle-three" },
		"final history":  func(value *activationTransaction) { value.FinalActivation.PreviousBundleID = "bundle-three" },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := valid
			prior := previous
			candidate.PreviousActivation = &prior
			mutate(&candidate)
			if validActivationTransaction(candidate) {
				t.Fatal("invalid activation transaction was accepted")
			}
		})
	}
}

func TestStateFormatReplacementIsExplicitAndRollbackRestoresOldState(t *testing.T) {
	root, hostState, artifacts := filepath.Join(t.TempDir(), "root"), filepath.Join(t.TempDir(), "host"), t.TempDir()
	providerState := filepath.Join(t.TempDir(), "provider")
	if err := os.MkdirAll(providerState, 0o700); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(providerState, "state.db"), []byte("old-state"))
	manager := &fakeManager{root: root, destinations: map[string]string{"gh.service": "bin/gh", "telegram.service": "bin/telegram"}, active: map[string]bool{}}
	installer := Installer{Paths: Paths{Root: root, StateDir: hostState}, Manager: manager, Probe: func(context.Context, Component) error { return nil }}
	one := testManifest(t, "bundle-one", "one")
	one.Components[0].StateDir = providerState
	one, oneData := writeManifestArtifacts(t, artifacts, one)
	if err := installer.Activate(t.Context(), one, oneData, artifacts); err != nil {
		t.Fatal(err)
	}
	two := testManifest(t, "bundle-two", "two")
	two.Components[0].StateDir = providerState
	two.Components[0].StateFormatDigest = "sha256:" + strings.Repeat("3", 64)
	two, twoData := writeManifestArtifacts(t, artifacts, two)
	if err := installer.Activate(t.Context(), two, twoData, artifacts); err == nil {
		t.Fatal("state format change without replacement was accepted")
	}
	two.BundleID = "bundle-three"
	two.Components[0].ReplaceState = true
	twoData, err := json.Marshal(two)
	if err != nil {
		t.Fatal(err)
	}
	if err := installer.Activate(t.Context(), two, twoData, artifacts); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(providerState, "state.db")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("candidate inherited old-format state")
	}
	if err := installer.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(providerState, "state.db"))
	if err != nil || string(data) != "old-state" {
		t.Fatalf("restored state = %q, %v", data, err)
	}
}

type fakeManager struct {
	root            string
	destinations    map[string]string
	active          map[string]bool
	actions         []string
	deleted         string
	failStartBundle string
	staleService    string
	failStopOnce    string
}

func (m *fakeManager) Stop(_ context.Context, service string) error {
	m.actions = append(m.actions, "stop:"+service)
	m.active[service] = false
	if m.failStopOnce == service {
		m.failStopOnce = ""
		return errors.New("injected stop failure")
	}
	return nil
}

func (m *fakeManager) Start(_ context.Context, service string) error {
	m.actions = append(m.actions, "start:"+service)
	if m.failStartBundle != "" {
		current, err := filepath.EvalSymlinks(filepath.Join(m.root, "current"))
		if err == nil && filepath.Base(current) == m.failStartBundle {
			return errors.New("injected start failure")
		}
	}
	m.active[service] = true
	return nil
}

func (m *fakeManager) Reload(context.Context) error {
	m.actions = append(m.actions, "reload")
	return nil
}

func (m *fakeManager) Status(_ context.Context, service string) (ServiceStatus, error) {
	if !m.active[service] {
		return ServiceStatus{}, nil
	}
	current, err := filepath.EvalSymlinks(filepath.Join(m.root, "current"))
	if err != nil {
		return ServiceStatus{}, err
	}
	executable := filepath.Join(current, m.destinations[service])
	if m.staleService == service && filepath.Base(current) != "bundle-one" {
		executable = filepath.Join(m.root, "releases", "bundle-one", m.destinations[service])
	}
	if m.deleted == service {
		executable += " (deleted)"
	}
	return ServiceStatus{Active: true, PID: 42, Executable: executable}, nil
}

func testManifest(t *testing.T, bundleID, buildID string) Manifest {
	t.Helper()
	return Manifest{APIVersion: APIVersion, BundleID: bundleID, SourceCommit: strings.Repeat("a", 40),
		OperatingSystem: runtime.GOOS, Architecture: runtime.GOARCH, OperatorContractDigest: contract.OperatorV1Digest,
		AgentContractDigest: contract.AgentV1Digest, Components: []Component{
			{Name: "gh-broker", Source: "gh-" + buildID, Destination: "bin/gh", SHA256: "sha256:" + strings.Repeat("0", 64), BuildID: buildID, Role: RoleProvider,
				Services: []string{"gh.service"}, OperatorEndpoint: "unix:///tmp/gh.sock", OperatorTokenFile: "/run/secrets/gh-operator", OperatorContractDigest: contract.OperatorV1Digest,
				AgentContractDigest: contract.AgentV1Digest, StateFormatDigest: "sha256:" + strings.Repeat("1", 64), Required: true},
			{Name: "brokerkit-telegram", Source: "telegram-" + buildID, Destination: "bin/telegram", SHA256: "sha256:" + strings.Repeat("0", 64), BuildID: buildID,
				Role: RoleConsumer, Services: []string{"telegram.service"}, StateFormatDigest: "sha256:" + strings.Repeat("2", 64), Required: true},
		}}
}

func writeManifestArtifacts(t *testing.T, artifacts string, manifest Manifest) (Manifest, []byte) {
	t.Helper()
	for index := range manifest.Components {
		data := []byte(manifest.BundleID + ":" + manifest.Components[index].Name)
		writeTestFile(t, filepath.Join(artifacts, manifest.Components[index].Source), data)
		digest := sha256.Sum256(data)
		manifest.Components[index].SHA256 = "sha256:" + fmt.Sprintf("%x", digest)
	}
	data, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	return manifest, data
}

func assertCurrentBundle(t *testing.T, root, expected string) {
	t.Helper()
	target, err := os.Readlink(filepath.Join(root, "current"))
	if err != nil || filepath.Base(target) != expected {
		t.Fatalf("current = %q, %v", target, err)
	}
}

func writeTestFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}
