package component

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/osolmaz/brokerkit/deployment/api"
	deploymentruntime "github.com/osolmaz/brokerkit/deployment/runtime"
	"github.com/osolmaz/brokerkit/internal/config/client"
)

func TestAdapterPlanApplyVerifyRollback(t *testing.T) {
	current, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	group, err := user.LookupGroupId(current.Gid)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	agentHome := filepath.Join(root, "agent")
	if err := os.Mkdir(agentHome, 0o700); err != nil {
		t.Fatal(err)
	}
	policy := []byte("{\"rules\":[]}\n")
	profile := Profile{
		APIVersion:  "brokerkit.io/test-deployment/v1",
		Directories: []Directory{{ID: "config", Destination: filepath.Join(root, "config"), Mode: 0o700, Owner: current.Username, Group: group.Name}},
		Files:       []ManagedFile{{ID: "policy", Source: Reference{Path: "policy.json", SHA256: digest(policy)}, Destination: filepath.Join(root, "config", "policy.json"), Mode: 0o600, Owner: current.Username, Group: group.Name}},
		Credentials: []Credential{{Slot: "client-secret", Destination: filepath.Join(root, "config", "secrets"), Mode: 0o600, Owner: current.Username, Group: group.Name, Encoding: "client_secret_file", ClientID: "agent"}},
		Clients:     []Client{{AgentID: "agent", BrokerName: "test-broker", EnvPrefix: "TEST_BROKER", SecretSlot: "client-secret", Endpoint: "unix:///tmp/test.sock"}},
	}
	profileData, err := json.Marshal(profile)
	if err != nil {
		t.Fatal(err)
	}
	config := Config{
		ComponentID: "test", ProfileAPI: profile.APIVersion, AllowedPaths: []string{root}, BackupDirectory: filepath.Join(root, "backups"),
		ClientProbe: func(context.Context, api.AgentBinding, Client) error { return nil },
	}
	base := api.Request{
		APIVersion: api.APIVersion, DeploymentDigest: strings.Repeat("a", 71), ComponentID: "test", Profile: profileData,
		Files:  []api.File{{Path: "policy.json", SHA256: digest(policy), Data: policy}},
		Agents: []api.AgentBinding{{ID: "agent", ClientID: "agent", UnixUser: current.Username, Home: agentHome}},
	}
	base.DeploymentDigest = "sha256:" + strings.Repeat("a", 64)

	base.Action = api.ActionPlan
	planned := runAdapter(t, base, config)
	if planned.Status != "planned" || len(planned.Actions) != 3 || planned.Credentials[0].Action != "install" {
		t.Fatalf("plan = %#v", planned)
	}
	secretPath := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(secretPath, []byte(strings.Repeat("s", 32)), 0o600); err != nil {
		t.Fatal(err)
	}
	secret, err := os.Open(secretPath)
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Close()
	base.Action, base.PlanDigest = api.ActionApply, planned.PlanDigest
	base.Secrets = []api.SecretDescriptor{{Name: "client-secret", FD: int(secret.Fd())}}
	applied := runAdapter(t, base, config)
	if applied.Status != "applied" || len(applied.RollbackHandle) != 32 {
		t.Fatalf("apply = %#v", applied)
	}
	base.Action, base.Secrets, base.PlanDigest = api.ActionVerify, nil, ""
	verified := runAdapter(t, base, config)
	if verified.Status != "verified" || len(verified.Verification) != 4 {
		t.Fatalf("verify = %#v", verified)
	}
	loaded, err := clientconfig.Read(agentHome, "test-broker", "TEST_BROKER")
	if err != nil || loaded.ClientID != "agent" || loaded.SharedSecret != strings.Repeat("s", 32) {
		t.Fatalf("client = %#v, %v", loaded, err)
	}
	base.Action, base.PlanDigest, base.RollbackHandle = api.ActionRollback, applied.PlanDigest, applied.RollbackHandle
	rolledBack := runAdapter(t, base, config)
	if rolledBack.Status != "rolled_back" {
		t.Fatalf("rollback = %#v", rolledBack)
	}
	if _, err := os.Stat(filepath.Join(root, "config")); !os.IsNotExist(err) {
		t.Fatalf("config remains after rollback: %v", err)
	}
}

func TestPlanDigestBindsCredentialState(t *testing.T) {
	current, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	group, err := user.LookupGroupId(current.Gid)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	destination := filepath.Join(root, "credential")
	if err := os.WriteFile(destination, []byte(strings.Repeat("a", 32)), 0o600); err != nil {
		t.Fatal(err)
	}
	profile := Profile{
		APIVersion: "brokerkit.io/test-deployment/v1",
		Credentials: []Credential{{
			Slot: "credential", Destination: destination, Mode: 0o600,
			Owner: current.Username, Group: group.Name, Encoding: "raw",
		}},
	}
	profileData, err := json.Marshal(profile)
	if err != nil {
		t.Fatal(err)
	}
	request := api.Request{
		APIVersion: api.APIVersion, Action: api.ActionPlan,
		DeploymentDigest: "sha256:" + strings.Repeat("a", 64),
		ComponentID:      "test", Profile: profileData,
	}
	config := Config{
		ComponentID: "test", ProfileAPI: profile.APIVersion,
		AllowedPaths: []string{root}, BackupDirectory: filepath.Join(root, "backups"),
	}
	before := runAdapter(t, request, config)
	if err := os.WriteFile(destination, []byte(strings.Repeat("b", 32)), 0o600); err != nil {
		t.Fatal(err)
	}
	after := runAdapter(t, request, config)
	if before.PlanDigest == after.PlanDigest {
		t.Fatal("credential replacement did not invalidate the component plan")
	}
}

func TestProfileRejectsDuplicateGroupMembers(t *testing.T) {
	profile := Profile{
		APIVersion: "brokerkit.io/test-deployment/v1",
		Groups:     []Group{{Name: "test", Members: []string{"agent", "agent"}}},
	}
	config := Config{
		ComponentID: "test", ProfileAPI: profile.APIVersion,
		AllowedGroups: []string{"test"}, BackupDirectory: t.TempDir(),
	}
	if err := validateProfile(profile, config, nil); err == nil {
		t.Fatal("duplicate group members were accepted")
	}
}

func runAdapter(t *testing.T, request api.Request, config Config) api.Response {
	t.Helper()
	var input, output bytes.Buffer
	if err := deploymentruntime.WriteFrame(&input, request); err != nil {
		t.Fatal(err)
	}
	if err := Serve(context.Background(), &input, &output, config); err != nil {
		t.Fatal(err)
	}
	var response api.Response
	if err := deploymentruntime.ReadFrame(&output, &response); err != nil {
		t.Fatal(err)
	}
	return response
}

func currentIDs(t *testing.T) (int, int) {
	t.Helper()
	current, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	uid, _ := strconv.Atoi(current.Uid)
	gid, _ := strconv.Atoi(current.Gid)
	return uid, gid
}
