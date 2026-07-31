package main

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/osolmaz/unyolo/deployment/api"
	"github.com/osolmaz/unyolo/deployment/component"
	deploymentruntime "github.com/osolmaz/unyolo/deployment/runtime"
)

func TestReleaseSocketDirectoriesAllowClientTraversal(t *testing.T) {
	for _, path := range []string{"../../deployment/files/huggingface/hf-broker-agent.socket", "../../deployment/files/huggingface/hf-broker-operator.socket"} {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Contains(data, []byte("DirectoryMode=0711\n")) {
			t.Fatalf("%s does not allow client traversal", path)
		}
	}
}

func TestReleaseDeploymentProfileMatchesHuggingFaceAdapter(t *testing.T) {
	profileData, err := os.ReadFile("../../deployment/profile.json")
	if err != nil {
		t.Fatal(err)
	}
	profileData = []byte(strings.ReplaceAll(strings.ReplaceAll(string(profileData), "$UNYOLO_AGENT", "unyolo-agent"), "$UNYOLO_OPERATOR", "operator"))
	request := api.Request{
		APIVersion: api.APIVersion, Action: api.ActionValidate,
		DeploymentDigest: "sha256:" + strings.Repeat("a", 64), ComponentID: "huggingface", Profile: profileData,
		Agents: []api.AgentBinding{{ID: "agent", ClientID: "agent", TargetKind: "local_account", Isolation: "separate", AccountMode: "managed", UnixUser: "unyolo-agent", Home: "/var/lib/unyolo-agent"}},
	}
	var input, output bytes.Buffer
	if err := deploymentruntime.WriteFrame(&input, request); err != nil {
		t.Fatal(err)
	}
	if err := component.Serve(t.Context(), &input, &output, huggingFaceDeploymentConfig()); err != nil {
		t.Fatal(err)
	}
	var response api.Response
	if err := deploymentruntime.ReadFrame(&output, &response); err != nil || response.Status != "valid" {
		t.Fatalf("profile response = %+v, %v", response, err)
	}
}
