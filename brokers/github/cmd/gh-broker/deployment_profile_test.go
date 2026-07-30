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

func TestReleaseDeploymentProfileMatchesGitHubAdapter(t *testing.T) {
	validateReleaseDeploymentProfile(t, "../../deployment/profile.json", "github", githubDeploymentConfig())
}

func validateReleaseDeploymentProfile(t *testing.T, path, id string, config component.Config) {
	t.Helper()
	profileData, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	profileData = []byte(strings.ReplaceAll(strings.ReplaceAll(string(profileData), "$UNYOLO_AGENT", "unyolo-agent"), "$UNYOLO_OPERATOR", "operator"))
	request := api.Request{
		APIVersion: api.APIVersion, Action: api.ActionValidate,
		DeploymentDigest: "sha256:" + strings.Repeat("a", 64), ComponentID: id, Profile: profileData,
		Agents: []api.AgentBinding{{ID: "agent", ClientID: "agent", UnixUser: "unyolo-agent", Home: "/var/lib/unyolo-agent"}},
	}
	var input, output bytes.Buffer
	if err := deploymentruntime.WriteFrame(&input, request); err != nil {
		t.Fatal(err)
	}
	if err := component.Serve(t.Context(), &input, &output, config); err != nil {
		t.Fatal(err)
	}
	var response api.Response
	if err := deploymentruntime.ReadFrame(&output, &response); err != nil || response.Status != "valid" {
		t.Fatalf("profile response = %+v, %v", response, err)
	}
}
