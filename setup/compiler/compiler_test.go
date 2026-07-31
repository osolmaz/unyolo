package compiler

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/osolmaz/unyolo/deployment/component"
	"github.com/osolmaz/unyolo/deployment/profile"
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
	template := profile.Deployment{
		APIVersion: profile.APIVersion, Name: "template",
		Runtime:    profile.Runtime{Manifest: ref("manifest", '0'), Signature: ref("signature", '1'), PublicKey: ref("key", '2')},
		Agents:     []profile.Agent{{ID: "agent", ClientID: "agent", Target: profile.AgentTarget{Kind: "local_account", Isolation: "separate", AccountMode: "managed", UnixUser: "unyolo-agent", Home: "/var/lib/unyolo-agent", Shell: "/usr/sbin/nologin"}, ComponentIDs: []string{"github"}}},
		Operators:  []profile.Operator{{ID: "operator", UnixUser: "operator"}},
		Components: []profile.Component{{ID: "github", Profile: ref("component", '3')}},
	}
	first, err := compileDeployment(source, template)
	if err != nil {
		t.Fatal(err)
	}
	second, err := compileDeployment(source, template)
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

	source.Connections = nil
	serverOnly, err := compileDeployment(source, template)
	if err != nil || len(serverOnly.Agents) != 0 {
		t.Fatalf("server-only deployment = %#v, %v", serverOnly.Agents, err)
	}
}

func TestRenderComponentBuildsAuthoritativeStoresAndLocalFiles(t *testing.T) {
	t.Parallel()
	value := component.Profile{
		APIVersion: "unyolo.io/github-deployment/v1",
		Groups:     []component.Group{{Name: "gh-broker-agent", Members: []string{"unyolo-agent"}}, {Name: "gh-broker-operator", Members: []string{"operator"}}},
		Credentials: []component.Credential{
			{Slot: "provider", Destination: "/etc/gh-broker/provider", Encoding: "raw"},
			{Slot: "agent", Destination: "/etc/gh-broker/secrets", Mode: 0o600, Owner: "gh-broker", Group: "gh-broker", Encoding: "client_secret_file"},
			{Slot: "operator", Destination: "/etc/gh-broker/operators", Mode: 0o600, Owner: "gh-broker", Group: "gh-broker", Encoding: "client_secret_file"},
		},
		Clients: []component.Client{{AgentID: "agent", BrokerName: "gh-broker", EnvPrefix: "GH_BROKER", SecretSlot: "agent", Endpoint: "unix:///run/unyolo/github/agent/broker.sock"}},
	}
	if err := renderComponent(&value, "github", compilerInstallation()); err != nil {
		t.Fatal(err)
	}
	if len(value.SecretStores) != 2 || len(value.SecretStores[0].Entries) != 2 || len(value.SecretStores[1].Entries) != 1 {
		t.Fatalf("secret stores = %#v", value.SecretStores)
	}
	if len(value.Clients) != 1 || value.Clients[0].AgentID != "bob" || !slices.Equal(value.Groups[0].Members, []string{"bob"}) {
		t.Fatalf("local render = clients %#v groups %#v", value.Clients, value.Groups)
	}
	if len(value.Credentials) != 1 || value.Credentials[0].Slot != "provider" {
		t.Fatalf("raw credentials = %#v", value.Credentials)
	}
}

func TestRewriteComponentPolicyRefreshesManifestDigests(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	profilePath := filepath.Join(root, "policy-profile.json")
	policyPath := filepath.Join(root, "scope.json")
	manifestPath := filepath.Join(root, "policy-manifest.json")
	for path, body := range map[string]string{
		profilePath:  "{\n  \"clients\": [\n    \"agent\"\n  ]\n}\n",
		policyPath:   "{\n  \"rules\": [\n    {\n      \"clients\": [\n        \"agent\"\n      ]\n    }\n  ]\n}\n",
		manifestPath: `{"version":1,"profile_digest":"sha256:old","policy_digest":"sha256:old"}`,
	} {
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	files := []component.ManagedFile{
		{Source: component.Reference{Path: "policy-profile.json"}},
		{Source: component.Reference{Path: "scope.json"}},
		{Source: component.Reference{Path: "policy-manifest.json"}},
	}
	if err := rewriteComponentPolicy(root, files, []string{"alice", "bob"}); err != nil {
		t.Fatal(err)
	}
	profileData, _ := os.ReadFile(profilePath)
	policyData, _ := os.ReadFile(policyPath)
	manifestData, _ := os.ReadFile(manifestPath)
	var manifest map[string]any
	if err := json.Unmarshal(manifestData, &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest["profile_digest"] != contentDigest(profileData) || manifest["policy_digest"] != contentDigest(policyData) {
		t.Fatalf("manifest digests = %#v", manifest)
	}
	if !containsAll(string(profileData), "alice", "bob") || !containsAll(string(policyData), "alice", "bob") {
		t.Fatalf("rewritten policies = %s / %s", profileData, policyData)
	}
}

func containsAll(value string, parts ...string) bool {
	for _, part := range parts {
		if !strings.Contains(value, part) {
			return false
		}
	}
	return true
}

func ref(path string, digit byte) profile.Reference {
	return profile.Reference{Path: path, SHA256: "sha256:" + repeat(digit, 64)}
}

func repeat(value byte, count int) string {
	result := make([]byte, count)
	for index := range result {
		result[index] = value
	}
	return string(result)
}
