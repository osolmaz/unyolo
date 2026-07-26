package deployment

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
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
	planned, err := engine.Plan(t.Context(), pack)
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}
	if planned.Plan.Kind != "install" || planned.Plan.Digest == "" {
		t.Fatalf("plan = %#v", planned.Plan)
	}
	report, err := engine.Apply(t.Context(), pack, planned.Plan.Digest, nil)
	if err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	if !report.Healthy || report.RuntimeBundleID != "engine-test" {
		t.Fatalf("report = %#v", report)
	}
	unchanged, err := engine.Plan(t.Context(), pack)
	if err != nil {
		t.Fatal(err)
	}
	if unchanged.Plan.Kind != "noop" || len(unchanged.Plan.Actions) != 0 {
		t.Fatalf("unchanged plan = %#v", unchanged.Plan)
	}
	if _, err := engine.Apply(t.Context(), pack, planned.Plan.Digest, nil); err == nil || !strings.Contains(err.Error(), "plan_stale") {
		t.Fatalf("stale apply error = %v", err)
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
	case api.ActionApply:
		response.Status, response.PlanDigest, response.RollbackHandle = "applied", request.PlanDigest, "rollback-id"
	case api.ActionVerify:
		response.Status, response.Verification = "verified", []string{"fake client read succeeded"}
	case api.ActionRollback:
		response.Status, response.PlanDigest = "rolled_back", request.PlanDigest
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
		LookupShell:    func(string) (string, error) { return "/bin/false", nil },
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
