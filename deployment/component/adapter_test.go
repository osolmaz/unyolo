package component

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"syscall"
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
		ClientProbe: func(context.Context, api.AgentBinding, Client, string) error { return nil },
	}
	base := api.Request{
		APIVersion: api.APIVersion, DeploymentDigest: strings.Repeat("a", 71), ComponentID: "test", Profile: profileData,
		Files:  []api.File{{Path: "policy.json", SHA256: digest(policy), Data: policy}},
		Agents: []api.AgentBinding{{ID: "agent", ClientID: "agent", UnixUser: current.Username, Home: agentHome}},
	}
	base.DeploymentDigest = "sha256:" + strings.Repeat("a", 64)

	base.Action = api.ActionPlan
	planned := runAdapter(t, base, config)
	if planned.Status != "planned" || len(planned.Actions) != 4 || planned.Credentials[0].Action != "install" {
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
	secretFD, err := syscall.Dup(int(secret.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	base.Action, base.PlanDigest = api.ActionApply, planned.PlanDigest
	base.Secrets = []api.SecretDescriptor{{Name: "client-secret", FD: secretFD}}
	applied := runAdapter(t, base, config)
	_ = secret.Close()
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

	profile.Credentials[0].Action = "rotate"
	base.Profile, err = json.Marshal(profile)
	if err != nil {
		t.Fatal(err)
	}
	base.Action = api.ActionPlan
	rotation := runAdapter(t, base, config)
	if rotation.Credentials[0].Action != "rotate" || len(rotation.Actions) != 2 {
		t.Fatalf("rotation plan = %#v", rotation)
	}
	rotatedSecretPath := filepath.Join(t.TempDir(), "rotated-secret")
	if err := os.WriteFile(rotatedSecretPath, []byte(strings.Repeat("r", 32)), 0o600); err != nil {
		t.Fatal(err)
	}
	rotatedSecret, err := os.Open(rotatedSecretPath)
	if err != nil {
		t.Fatal(err)
	}
	rotatedFD, err := syscall.Dup(int(rotatedSecret.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	base.Action, base.PlanDigest = api.ActionApply, rotation.PlanDigest
	base.Secrets = []api.SecretDescriptor{{Name: "client-secret", FD: rotatedFD, Rotate: true}}
	rotated := runAdapter(t, base, config)
	_ = rotatedSecret.Close()
	loaded, err = clientconfig.Read(agentHome, "test-broker", "TEST_BROKER")
	if err != nil || loaded.SharedSecret != strings.Repeat("r", 32) {
		t.Fatalf("rotated client = %#v, %v", loaded, err)
	}
	base.Action, base.Secrets, base.PlanDigest, base.RollbackHandle = api.ActionRollback, nil, rotated.PlanDigest, rotated.RollbackHandle
	if response := runAdapter(t, base, config); response.Status != "rolled_back" {
		t.Fatalf("rotation rollback = %#v", response)
	}
	loaded, err = clientconfig.Read(agentHome, "test-broker", "TEST_BROKER")
	if err != nil || loaded.SharedSecret != strings.Repeat("s", 32) {
		t.Fatalf("restored client = %#v, %v", loaded, err)
	}

	profile.Credentials[0].Action = ""
	base.Profile, err = json.Marshal(profile)
	if err != nil {
		t.Fatal(err)
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

func TestValidateProfileRejectsUnsafeResources(t *testing.T) {
	root := t.TempDir()
	config := Config{
		ComponentID: "test", ProfileAPI: "brokerkit.io/test-deployment/v1",
		AllowedPaths: []string{root}, AllowedServices: []string{"test.service"},
		AllowedAccounts: []string{"service"}, AllowedGroups: []string{"service"}, BackupDirectory: filepath.Join(root, "backups"),
	}
	valid := func() Profile {
		return Profile{
			APIVersion:  config.ProfileAPI,
			Accounts:    []Account{{Name: "service", Group: "service", Home: "/var/lib/service", Shell: "/usr/sbin/nologin"}},
			Groups:      []Group{{Name: "service"}},
			Directories: []Directory{{ID: "directory", Destination: filepath.Join(root, "config"), Mode: 0o750, Owner: "root", Group: "service"}},
			Files:       []ManagedFile{{ID: "file", Source: Reference{Path: "file", SHA256: digest([]byte("file"))}, Destination: filepath.Join(root, "file"), Mode: 0o640, Owner: "root", Group: "service"}},
			Credentials: []Credential{{Slot: "secret", Destination: filepath.Join(root, "secret"), Mode: 0o640, Owner: "root", Group: "service", Encoding: "raw"}},
			Clients:     []Client{{AgentID: "agent", BrokerName: "test", EnvPrefix: "TEST", SecretSlot: "secret"}},
			Services:    []string{"test.service"},
		}
	}
	agents := []api.AgentBinding{{ID: "agent", ClientID: "agent", UnixUser: "agent", Home: "/home/agent"}}
	if err := validateProfile(valid(), config, agents); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		edit func(*Profile)
	}{
		{"API", func(value *Profile) { value.APIVersion = "old" }},
		{"account", func(value *Profile) { value.Accounts[0].Name = "other" }},
		{"account home", func(value *Profile) { value.Accounts[0].Home = "relative" }},
		{"group", func(value *Profile) { value.Groups[0].Name = "other" }},
		{"directory", func(value *Profile) { value.Directories[0].Destination = "/outside" }},
		{"directory mode", func(value *Profile) { value.Directories[0].Mode = 0o777 }},
		{"file source", func(value *Profile) { value.Files[0].Source.Path = "" }},
		{"credential slot", func(value *Profile) { value.Credentials[0].Slot = "" }},
		{"credential encoding", func(value *Profile) { value.Credentials[0].Encoding = "env" }},
		{"credential action", func(value *Profile) { value.Credentials[0].Action = "replace" }},
		{"client agent", func(value *Profile) { value.Clients[0].AgentID = "missing" }},
		{"client slot", func(value *Profile) { value.Clients[0].SecretSlot = "missing" }},
		{"service", func(value *Profile) { value.Services[0] = "other.service" }},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			value := valid()
			test.edit(&value)
			if err := validateProfile(value, config, agents); err == nil {
				t.Fatal("unsafe profile was accepted")
			}
		})
	}
}

func TestCredentialEncodingAndActions(t *testing.T) {
	secret := []byte("secret-value")
	raw := encodeCredential(Credential{Encoding: "raw"}, secret)
	if string(raw) != string(secret) {
		t.Fatalf("raw = %q", raw)
	}
	encoded := encodeCredential(Credential{Encoding: "client_secret_file", ClientID: "agent"}, secret)
	if !strings.Contains(string(encoded), "agent = secret-value") {
		t.Fatalf("client secret = %q", encoded)
	}
	credentials := []api.CredentialAction{{Slot: "a", Action: "retain"}, {Slot: "b", Action: "install"}}
	if credentialAction(credentials, "a") != "retain" || credentialAction(credentials, "missing") != "" {
		t.Fatal("credential action lookup is incorrect")
	}
	credentialsProfile := []Credential{{Slot: "a"}}
	found, ok := credentialBySlot(credentialsProfile, "a")
	_, missing := credentialBySlot(credentialsProfile, "missing")
	if !ok || found.Slot != "a" || missing {
		t.Fatal("credential slot lookup is incorrect")
	}
}

func TestCredentialIOHelpers(t *testing.T) {
	root := t.TempDir()
	rawPath := filepath.Join(root, "raw")
	if err := os.WriteFile(rawPath, []byte("raw-secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	raw, err := readInstalledCredential(Credential{Destination: rawPath, Encoding: "raw"})
	if err != nil || string(raw) != "raw-secret" {
		t.Fatalf("raw credential = %q, %v", raw, err)
	}
	clientPath := filepath.Join(root, "client")
	if err := os.WriteFile(clientPath, []byte("agent = client-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	secret, err := readInstalledCredential(Credential{Destination: clientPath, Encoding: "client_secret_file", ClientID: "agent"})
	if err != nil || string(secret) != "client-secret" {
		t.Fatalf("client credential = %q, %v", secret, err)
	}
	if _, err := readInstalledCredential(Credential{Destination: filepath.Join(root, "missing")}); err == nil {
		t.Fatal("missing installed credential was accepted")
	}
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write([]byte("descriptor-secret")); err != nil {
		t.Fatal(err)
	}
	_ = writer.Close()
	values, err := readSecrets([]api.SecretDescriptor{{Name: "token", FD: int(reader.Fd())}})
	if err != nil || string(values["token"]) != "descriptor-secret" {
		t.Fatalf("descriptor secrets = %#v, %v", values, err)
	}
	clearSecrets(values)
	for _, value := range values["token"] {
		if value != 0 {
			t.Fatal("secret map was not cleared")
		}
	}
}

func TestFilesystemApplyHelpers(t *testing.T) {
	current, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	group, err := user.LookupGroupId(current.Gid)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	directory := Directory{ID: "config", Destination: filepath.Join(root, "config"), Mode: 0o700, Owner: current.Username, Group: group.Name}
	if err := applyDirectories([]Directory{directory}); err != nil {
		t.Fatal(err)
	}
	if !matchesDirectory(directory) {
		t.Fatal("applied directory does not match")
	}
	fileData := []byte("managed")
	managed := ManagedFile{ID: "file", Source: Reference{Path: "source", SHA256: digest(fileData)}, Destination: filepath.Join(root, "config", "file"), Mode: 0o600, Owner: current.Username, Group: group.Name}
	if err := applyFiles([]ManagedFile{managed}, map[string]api.File{"source": {Path: "source", SHA256: digest(fileData), Data: fileData}}); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(managed.Destination)
	if err != nil || fileDigest(managed.Destination) != managed.Source.SHA256 || info.Mode().Perm() != os.FileMode(managed.Mode) || !matchesOwner(info, managed.Owner, managed.Group) {
		t.Fatal("applied file does not match")
	}
	if _, _, err := resolveOwner("missing-brokerkit-test-user", group.Name); err == nil {
		t.Fatal("missing owner was accepted")
	}
}

func TestHostInspectionHelpers(t *testing.T) {
	current, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	group, err := user.LookupGroupId(current.Gid)
	if err != nil {
		t.Fatal(err)
	}
	shell, err := accountShell(t.Context(), current.Username)
	if err != nil {
		t.Fatal(err)
	}
	account := Account{Name: current.Username, Group: group.Name, Home: current.HomeDir, Shell: shell}
	members, err := groupMemberNames(t.Context(), group.Name)
	if err != nil {
		t.Fatal(err)
	}
	groupProfile := Group{Name: group.Name, Members: members}
	if !accountMatches(t.Context(), account) || !groupMatches(t.Context(), groupProfile) || !memberInGroup(current.Username, group.Name) {
		t.Fatal("current account or group did not match")
	}
	if accountFingerprint(t.Context(), account) == "missing" || groupFingerprint(t.Context(), groupProfile) == "missing" {
		t.Fatal("current account or group fingerprint is missing")
	}
	if err := applyGroups(t.Context(), []Group{{Name: group.Name}}); err != nil {
		t.Fatal(err)
	}
	if err := applyAccounts(t.Context(), []Account{account}); err != nil {
		t.Fatal(err)
	}
	if err := applyGroupMembers(t.Context(), []Group{groupProfile}); err != nil {
		t.Fatal(err)
	}
	accounts, groups, err := snapshotIdentityBackups(t.Context(), Profile{Accounts: []Account{account}, Groups: []Group{groupProfile}})
	if err != nil || len(accounts) != 1 || !accounts[0].Existed || len(groups) != 1 || !groups[0].Existed {
		t.Fatalf("identity backup = %#v, %#v, %v", accounts, groups, err)
	}
	root := t.TempDir()
	file := filepath.Join(root, "file")
	if pathFingerprint(filepath.Join(root, "missing")) != "missing" {
		t.Fatal("missing fingerprint is not stable")
	}
	if err := os.WriteFile(file, []byte("value"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(pathFingerprint(file), "sha256:") || !strings.HasPrefix(pathFingerprint(root), "sha256:") {
		t.Fatal("path fingerprint is invalid")
	}
	ids, paths := map[string]bool{}, map[string]bool{}
	if !validResource("file", file, 0o600, current.Username, group.Name, []string{root}, ids, paths) {
		t.Fatal("valid resource was rejected")
	}
	if validResource("file", file, 0o600, current.Username, group.Name, []string{root}, ids, paths) || ownedPath("relative", []string{root}) {
		t.Fatal("duplicate or relative resource was accepted")
	}
	if !isAgentClientPath(filepath.Join(current.HomeDir, ".config", "test", "client.json")) {
		t.Fatal("agent client path was not recognized")
	}
}

func TestProbeFailures(t *testing.T) {
	if err := runClientProbe(t.Context(), api.AgentBinding{UnixUser: "missing-brokerkit-test-user"}, Client{}, "/bin/false"); err == nil {
		t.Fatal("missing probe user was accepted")
	}
	for _, args := range [][]string{nil, {"relative", "broker", "PREFIX"}, {t.TempDir(), "missing", "PREFIX"}} {
		if err := Probe(t.Context(), args); err == nil {
			t.Fatalf("probe arguments were accepted: %v", args)
		}
	}
}

func TestBackupAndRollbackHelpers(t *testing.T) {
	root := t.TempDir()
	file := filepath.Join(root, "file")
	created := filepath.Join(root, "created")
	directory := filepath.Join(root, "managed")
	if err := os.Mkdir(directory, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte("before"), 0o600); err != nil {
		t.Fatal(err)
	}
	config := Config{AllowedPaths: []string{root}, BackupDirectory: filepath.Join(root, "backups")}
	record, err := createBackup(t.Context(), config, []string{file, created, directory}, Profile{})
	if err != nil || len(record.Entries) != 3 {
		t.Fatalf("backup = %#v, %v", record, err)
	}
	if err := os.WriteFile(file, []byte("after"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(created, []byte("created"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(directory, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := rollback(t.Context(), config, record.ID); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(file)
	if err != nil || string(data) != "before" {
		t.Fatalf("restored file = %q, %v", data, err)
	}
	if _, err := os.Stat(created); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("created file remains: %v", err)
	}
	if info, err := os.Stat(directory); err != nil || info.Mode().Perm() != 0o750 {
		t.Fatalf("restored directory mode = %v, %v", info, err)
	}
	finalized, err := createBackup(t.Context(), config, []string{file}, Profile{})
	if err != nil {
		t.Fatal(err)
	}
	if err := finalizeBackup(config, finalized.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(config.BackupDirectory, finalized.ID+".json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("finalized backup remains: %v", err)
	}
	if err := rollback(t.Context(), config, "missing"); err == nil {
		t.Fatal("missing rollback handle was accepted")
	}
	outside := Config{AllowedPaths: []string{root}, BackupDirectory: "/outside"}
	if _, err := createBackup(t.Context(), outside, nil, Profile{}); err == nil {
		t.Fatal("outside backup directory was accepted")
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
