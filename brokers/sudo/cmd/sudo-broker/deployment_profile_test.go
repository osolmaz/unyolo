package main

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/osolmaz/unyolo/deployment/api"
	"github.com/osolmaz/unyolo/deployment/component"
	deploymentruntime "github.com/osolmaz/unyolo/deployment/runtime"
)

func TestReleaseDeploymentDefaultsMatchGeneratedClient(t *testing.T) {
	for _, path := range []string{"../../deployment/files/sudo/sudo-broker-agent.socket", "../../deployment/files/sudo/sudo-broker-operator.socket"} {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Contains(data, []byte("DirectoryMode=0711\n")) {
			t.Fatalf("%s does not allow client traversal", path)
		}
	}
	policy, err := os.ReadFile("../../deployment/files/sudo/policy.json")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(policy, []byte(`"clients": ["agent"]`)) {
		t.Fatal("default sudo policy does not authorize the generated agent client")
	}
}

func TestReleaseDeploymentStateHierarchyMatchesRuntimeTrust(t *testing.T) {
	profileData, err := os.ReadFile("../../deployment/profile.json")
	if err != nil {
		t.Fatal(err)
	}
	var profile component.Profile
	if err := json.Unmarshal(profileData, &profile); err != nil {
		t.Fatal(err)
	}
	directories := make(map[string]component.Directory, len(profile.Directories))
	for _, directory := range profile.Directories {
		directories[directory.ID] = directory
	}
	for id, expected := range map[string]component.Directory{
		"state-root":     {ID: "state-root", Destination: "/var/lib/sudo-broker", Mode: 0o750, Owner: "root", Group: "sudo-broker"},
		"frontend-state": {ID: "frontend-state", Destination: "/var/lib/sudo-broker/frontend", Mode: 0o700, Owner: "sudo-broker", Group: "sudo-broker"},
		"helper-state":   {ID: "helper-state", Destination: "/var/lib/sudo-broker/helper", Mode: 0o700, Owner: "root", Group: "root"},
	} {
		if directories[id] != expected {
			t.Fatalf("directory %q = %+v, want %+v", id, directories[id], expected)
		}
	}
}

func TestReleaseDeploymentProfileMatchesSudoAdapter(t *testing.T) {
	profileData, err := os.ReadFile("../../deployment/profile.json")
	if err != nil {
		t.Fatal(err)
	}
	profileData = []byte(strings.ReplaceAll(strings.ReplaceAll(string(profileData), "$UNYOLO_AGENT", "unyolo-agent"), "$UNYOLO_OPERATOR", "operator"))
	request := api.Request{
		APIVersion: api.APIVersion, Action: api.ActionValidate,
		DeploymentDigest: "sha256:" + strings.Repeat("a", 64), ComponentID: "sudo", Profile: profileData,
		Agents: []api.AgentBinding{{ID: "agent", ClientID: "agent", UnixUser: "unyolo-agent", Home: "/var/lib/unyolo-agent"}},
	}
	var input, output bytes.Buffer
	if err := deploymentruntime.WriteFrame(&input, request); err != nil {
		t.Fatal(err)
	}
	if err := component.Serve(t.Context(), &input, &output, sudoDeploymentConfig()); err != nil {
		t.Fatal(err)
	}
	var response api.Response
	if err := deploymentruntime.ReadFrame(&output, &response); err != nil || response.Status != "valid" {
		t.Fatalf("profile response = %+v, %v", response, err)
	}
}
