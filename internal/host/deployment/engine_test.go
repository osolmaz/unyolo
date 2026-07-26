package deployment

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/osolmaz/brokerkit/deployment/api"
	"github.com/osolmaz/brokerkit/deployment/profile"
	deploymentruntime "github.com/osolmaz/brokerkit/deployment/runtime"
	"github.com/osolmaz/brokerkit/internal/host/bundle"
	"github.com/osolmaz/brokerkit/internal/host/identity"
	"github.com/osolmaz/brokerkit/protocol/contract"
)

type fakeManager struct{}

func (fakeManager) Stop(context.Context, string) error  { return nil }
func (fakeManager) Start(context.Context, string) error { return nil }
func (fakeManager) Reload(context.Context) error        { return nil }
func (fakeManager) Status(context.Context, string) (bundle.ServiceStatus, error) {
	return bundle.ServiceStatus{Active: true}, nil
}

func TestBuildIdentityPlanCreatesOnlyMissingManagedAgents(t *testing.T) {
	snapshot := profile.Snapshot{Deployment: profile.Deployment{
		Agents: []profile.Agent{{ID: "agent", AccountMode: "managed", UnixUser: "brokerkit-agent", Home: "/var/lib/brokerkit-agent", Shell: "/usr/sbin/nologin"}},
	}}
	response, err := buildIdentityPlan(snapshot, map[string]identity.Account{"agent:agent": {Missing: true}})
	if err != nil {
		t.Fatal(err)
	}
	if len(response.Actions) != 1 || response.Actions[0].Resource.Kind != "account" || response.Actions[0].Resource.ID != "brokerkit-agent" {
		t.Fatalf("actions = %#v", response.Actions)
	}
	response, err = buildIdentityPlan(snapshot, map[string]identity.Account{"agent:agent": {Name: "brokerkit-agent"}})
	if err != nil || len(response.Actions) != 0 {
		t.Fatalf("existing account plan = %#v, %v", response.Actions, err)
	}
}

func TestEnginePlanApplyVerifyNoop(t *testing.T) {
	pack := engineTestPack(t)
	root, state := t.TempDir(), filepath.Join(t.TempDir(), "state")
	engine, err := New(Options{
		Paths: bundle.Paths{Root: root, StateDir: state}, Manager: fakeManager{}, Development: true,
		Identity: engineTestIdentity(),
	})
	if err != nil {
		t.Fatal(err)
	}
	validated, err := engine.Validate(t.Context(), pack)
	if err != nil || validated.Deployment.Name != "engine-host" {
		t.Fatalf("Validate() = %#v, %v", validated.Deployment, err)
	}
	planned, err := engine.Plan(t.Context(), pack)
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}
	if planned.Plan.Kind != "install" || planned.Plan.Digest == "" {
		t.Fatalf("plan = %#v", planned.Plan)
	}
	if err := engine.rollbackComponent(t.Context(), planned.Snapshot, "fake", planned.Responses[0].PlanDigest, "rollback-id"); err != nil {
		t.Fatalf("rollbackComponent() = %v", err)
	}
	report, err := engine.Apply(t.Context(), pack, planned.Plan.Digest, nil)
	if err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	if !report.Healthy || report.RuntimeBundleID != "engine-test" {
		t.Fatalf("report = %#v", report)
	}
	exported, err := engine.ExportObserved(t.Context(), pack)
	if err != nil || exported.DeploymentName != "engine-host" || len(exported.Components) != 1 {
		t.Fatalf("ExportObserved() = %#v, %v", exported, err)
	}
	unchanged, err := engine.Plan(t.Context(), pack)
	if err != nil {
		t.Fatal(err)
	}
	if unchanged.Plan.Kind != "noop" || len(unchanged.Plan.Actions) != 0 {
		t.Fatalf("unchanged plan = %#v", unchanged.Plan)
	}
	if verified, err := engine.verifyPlanned(t.Context(), unchanged); err != nil || !verified.Healthy {
		t.Fatalf("verifyPlanned() = %#v, %v", verified, err)
	}
	inactive := unchanged
	inactive.ActiveBundleID = "other"
	if verified, err := engine.verifyPlanned(t.Context(), inactive); err == nil || verified.Healthy {
		t.Fatalf("inactive runtime verification = %#v, %v", verified, err)
	}
	if _, err := engine.Apply(t.Context(), pack, planned.Plan.Digest, nil); err == nil || !strings.Contains(err.Error(), "plan_stale") {
		t.Fatalf("stale apply error = %v", err)
	}
}

func TestProductionEngineRequiresPinnedProfileTrust(t *testing.T) {
	pack := engineTestPack(t)
	snapshot, err := profile.Load(pack)
	if err != nil {
		t.Fatal(err)
	}
	state := t.TempDir()
	engine := &Engine{options: Options{Paths: bundle.Paths{Root: t.TempDir(), StateDir: state}}}
	if err := engine.verifySnapshotTrust(snapshot); err == nil {
		t.Fatal("unpinned profile trust root was accepted")
	}
	publicKey := filepath.Join(pack, filepath.FromSlash(snapshot.Deployment.Runtime.PublicKey.Path))
	if _, err := bundle.PinTrustedPublicKey(state, publicKey); err != nil {
		t.Fatal(err)
	}
	if err := engine.verifySnapshotTrust(snapshot); err != nil {
		t.Fatal(err)
	}
}

func TestPlanRejectsNonPlanningAdapterStatus(t *testing.T) {
	pack := engineTestPack(t)
	if err := os.WriteFile(filepath.Join(pack, "components", "fake.json"), []byte(`{"api_version":"fake/v1","test_plan_status":"valid"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := profile.Lock(pack, false); err != nil {
		t.Fatal(err)
	}
	engine, err := New(Options{
		Paths:   bundle.Paths{Root: t.TempDir(), StateDir: filepath.Join(t.TempDir(), "state")},
		Manager: fakeManager{}, Development: true, Identity: engineTestIdentity(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := engine.Plan(t.Context(), pack); err == nil || !strings.Contains(err.Error(), "during planning") {
		t.Fatalf("non-planning adapter status error = %v", err)
	}
}

func TestSecretSourcesAndEngineOptions(t *testing.T) {
	root := t.TempDir()
	secretPath := filepath.Join(root, "secret")
	if err := os.WriteFile(secretPath, []byte("secret-value"), 0o600); err != nil {
		t.Fatal(err)
	}
	files, err := openSecretSources([]SecretSource{{Name: "token", Path: secretPath}})
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(files["token"])
	if err != nil || string(data) != "secret-value" {
		t.Fatalf("secret descriptor = %q, %v", data, err)
	}
	closeSecretSources(files)
	for _, sources := range [][]SecretSource{
		{{Name: "", Path: secretPath}},
		{{Name: "token", Path: "relative"}},
		{{Name: "token", Path: secretPath}, {Name: "token", Path: secretPath}},
	} {
		if _, err := openSecretSources(sources); err == nil {
			t.Fatalf("unsafe secret sources were accepted: %#v", sources)
		}
	}
	if _, err := New(Options{Paths: bundle.DefaultPaths(), Development: true}); err == nil {
		t.Fatal("development engine accepted production paths")
	}
	if _, err := New(Options{Paths: bundle.Paths{Root: root, StateDir: root}, Development: true}); err == nil {
		t.Fatal("engine accepted overlapping root and state paths")
	}
}

func TestPlanAssemblyHelpers(t *testing.T) {
	planned := Planned{
		Snapshot: profile.Snapshot{
			Deployment: profile.Deployment{
				Agents:     []profile.Agent{{ID: "agent", UnixUser: "brokerkit-agent", AccountMode: "managed", Home: "/var/lib/brokerkit-agent", Shell: "/usr/sbin/nologin"}},
				Components: []profile.Component{{ID: "github"}},
			},
			Manifest: bundle.Manifest{Components: []bundle.Component{{Name: "github", Services: []string{"gh-broker.service"}}}},
		},
		Accounts: map[string]identity.Account{"agent:agent": {Missing: true}},
		Responses: []api.Response{{
			ComponentID: "github", PlanDigest: engineDigest("github"),
			Actions:     []api.PlannedAction{{ID: "service", Restart: true, Resource: api.Resource{Kind: "service", ID: "gh-broker.service"}}},
			Credentials: []api.CredentialAction{{Slot: "token", Action: "install"}},
		}},
	}
	engine := &Engine{}
	steps, err := engine.identitySteps(planned)
	if runtime.GOOS == "linux" && (err != nil || len(steps) != 1) {
		t.Fatalf("identitySteps() = %d, %v", len(steps), err)
	}
	if services := restartServices(planned); len(services) != 1 || services[0] != "gh-broker.service" {
		t.Fatalf("services = %v", services)
	}
	secretPath := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(secretPath, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(secretPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = file.Close() }()
	files := map[string]*os.File{"token": file}
	secrets, err := secretsForComponent(planned.Responses[0], files)
	if err != nil || len(secrets) != 1 || secrets[0].Name != "token" {
		t.Fatalf("secrets = %#v, %v", secrets, err)
	}
	if _, err := secretsForComponent(planned.Responses[0], nil); err == nil {
		t.Fatal("missing component secret was accepted")
	}
	if err := validateCredentialOwnership(planned.Responses); err != nil {
		t.Fatal(err)
	}
	duplicate := append([]api.Response(nil), planned.Responses...)
	duplicate = append(duplicate, api.Response{ComponentID: "sudo", Credentials: []api.CredentialAction{{Slot: "token", Action: "install"}}})
	if err := validateCredentialOwnership(duplicate); err == nil {
		t.Fatal("duplicate credential ownership was accepted")
	}
}

func TestDeleteManagedAgentRejectsUnknownHandle(t *testing.T) {
	agent := profile.Agent{UnixUser: "missing-brokerkit-agent", Home: "/home/missing-brokerkit-agent", Shell: "/usr/sbin/nologin"}
	if err := deleteManagedAgent(t.Context(), agent, "retained"); err == nil {
		t.Fatal("unknown managed-agent rollback handle was accepted")
	}
}

func TestEngineAdapterHelper(t *testing.T) {
	if len(os.Args) < 2 || os.Args[len(os.Args)-1] != "engine-adapter" {
		return
	}
	var request api.Request
	if err := deploymentruntime.ReadFrame(os.Stdin, &request); err != nil {
		os.Exit(2)
	}
	response := api.Response{APIVersion: api.APIVersion, ComponentID: request.ComponentID}
	switch request.Action {
	case api.ActionValidate:
		response.Status = "valid"
	case api.ActionPlan:
		response.Status, response.PlanDigest = "planned", engineDigest("component-plan")
		if strings.Contains(string(request.Profile), `"test_plan_status":"valid"`) {
			response.Status, response.PlanDigest = "valid", ""
		}
	case api.ActionApply:
		response.Status, response.PlanDigest, response.RollbackHandle = "applied", request.PlanDigest, "rollback-id"
	case api.ActionVerify:
		response.Status, response.Verification = "verified", []string{"fake client read succeeded"}
	case api.ActionRollback:
		response.Status, response.PlanDigest = "rolled_back", request.PlanDigest
	case api.ActionFinalize:
		response.Status, response.PlanDigest = "finalized", request.PlanDigest
	}
	if err := deploymentruntime.WriteFrame(os.Stdout, response); err != nil {
		os.Exit(3)
	}
	os.Exit(0)
}

func engineTestPack(t *testing.T) string {
	t.Helper()
	pack := t.TempDir()
	for _, directory := range []string{"runtime", "components", "artifacts"} {
		if err := os.Mkdir(filepath.Join(pack, directory), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := os.ReadFile(executable) // #nosec G304 -- current test executable.
	if err != nil {
		t.Fatal(err)
	}
	artifactPath := filepath.Join(pack, "artifacts", "fake")
	if err := os.WriteFile(artifactPath, artifact, 0o700); err != nil {
		t.Fatal(err)
	}
	manifest := bundle.Manifest{
		APIVersion: bundle.APIVersion, BundleID: "engine-test", SourceCommit: strings.Repeat("a", 40),
		OperatingSystem: runtime.GOOS, Architecture: runtime.GOARCH,
		OperatorContractDigest: contract.OperatorV1Digest, AgentContractDigest: contract.AgentV1Digest,
		Components: []bundle.Component{{
			Name: "fake", Source: "artifacts/fake", Destination: "bin/fake", SHA256: engineDigestBytes(artifact),
			BuildID: "engine-test", Role: bundle.RoleCompanion, StateFormatDigest: engineDigest("state"),
			Setup: &bundle.SetupAdapter{
				Protocol:  api.APIVersion,
				Arguments: []string{"-test.run=TestEngineAdapterHelper", "--", "engine-adapter"},
				Ownership: bundle.OwnershipEnvelope{Paths: []string{"/tmp/engine-test"}},
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
	writeEngineFile(t, filepath.Join(pack, "runtime", "manifest.json"), manifestData)
	writeEngineFile(t, filepath.Join(pack, "runtime", "manifest.sig"), []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(private, manifestData))))
	writeEngineFile(t, filepath.Join(pack, "runtime", "release.pub"), []byte(base64.StdEncoding.EncodeToString(public)))
	writeEngineFile(t, filepath.Join(pack, "components", "fake.json"), []byte(`{"api_version":"brokerkit.io/fake-deployment/v1"}`))

	deployment := map[string]any{
		"api_version": "brokerkit.io/host-deployment/v1", "name": "engine-host",
		"runtime": map[string]any{
			"manifest":   engineRef("runtime/manifest.json", manifestData),
			"signature":  engineRefFile(t, pack, "runtime/manifest.sig"),
			"public_key": engineRefFile(t, pack, "runtime/release.pub"),
		},
		"agents":     []any{map[string]any{"id": "agent", "client_id": "agent", "unix_user": "agent", "account_mode": "existing", "home": "/home/agent", "shell": "/bin/false", "component_ids": []string{"fake"}}},
		"operators":  []any{map[string]any{"id": "operator", "unix_user": "operator"}},
		"components": []any{map[string]any{"id": "fake", "profile": engineRefFile(t, pack, "components/fake.json")}},
	}
	data, err := json.MarshalIndent(deployment, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	writeEngineFile(t, filepath.Join(pack, "deployment.json"), append(data, '\n'))
	return pack
}

func engineTestIdentity() identity.Inspector {
	users := map[string]*user.User{
		"agent":    {Username: "agent", Uid: "1001", Gid: "1001", HomeDir: "/home/agent"},
		"operator": {Username: "operator", Uid: "1002", Gid: "1002", HomeDir: "/home/operator"},
	}
	return identity.Inspector{
		LookupUser:     func(name string) (*user.User, error) { return users[name], nil },
		LookupGroupIDs: func(value *user.User) ([]string, error) { return []string{value.Gid}, nil },
		LookupGroupID:  func(id string) (*user.Group, error) { return &user.Group{Name: "group-" + id, Gid: id}, nil },
		LookupShell:    func(context.Context, string) (string, error) { return "/bin/false", nil },
	}
}

func engineRef(path string, data []byte) map[string]any {
	return map[string]any{"path": path, "sha256": engineDigestBytes(data)}
}

func engineRefFile(t *testing.T, root, path string) map[string]any {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(root, path))
	if err != nil {
		t.Fatal(err)
	}
	return engineRef(path, data)
}

func writeEngineFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func engineDigest(value string) string      { return engineDigestBytes([]byte(value)) }
func engineDigestBytes(value []byte) string { return fmt.Sprintf("sha256:%x", sha256.Sum256(value)) }
