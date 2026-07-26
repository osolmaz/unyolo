package runtime

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/osolmaz/brokerkit/deployment/api"
	"github.com/osolmaz/brokerkit/internal/host/bundle"
)

func TestRunnerAndOwnership(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	request := api.Request{
		APIVersion: api.APIVersion, Action: api.ActionPlan,
		DeploymentDigest: digestForTest("deployment"), ComponentID: "fake",
		Profile: json.RawMessage(`{"api_version":"fake/v1"}`),
	}
	response, err := (Runner{}).Run(context.Background(), Command{
		Executable: executable, Arguments: []string{"-test.run=TestAdapterHelper", "--", "planned"},
	}, request, nil)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	component := bundle.Component{Setup: &bundle.SetupAdapter{Ownership: bundle.OwnershipEnvelope{Paths: []string{"/tmp/fake"}}}}
	if err := ValidateOwnership(response, component); err != nil {
		t.Fatalf("ValidateOwnership() error = %v", err)
	}
	component.Setup.Ownership.Paths = []string{"/tmp/other"}
	if err := ValidateOwnership(response, component); err == nil {
		t.Fatal("ValidateOwnership() accepted an escaped path")
	}
}

func TestRunnerRejectsWritableSecretDescriptor(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "secret")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	request := api.Request{
		APIVersion: api.APIVersion, Action: api.ActionApply,
		DeploymentDigest: digestForTest("deployment"), PlanDigest: digestForTest("plan"),
		ComponentID: "fake", Profile: json.RawMessage(`{"api_version":"fake/v1"}`),
	}
	_, err = (Runner{}).Run(context.Background(), Command{Executable: executable, Arguments: []string{"-test.run=TestAdapterHelper", "--", "applied"}}, request, []Secret{{Name: "token", File: file}})
	if err == nil || !strings.Contains(err.Error(), "read-only") {
		t.Fatalf("Run() error = %v, want read-only rejection", err)
	}
}

func TestAdapterHelper(t *testing.T) {
	if len(os.Args) < 3 || os.Args[len(os.Args)-2] != "--" {
		return
	}
	var request api.Request
	if err := ReadFrame(os.Stdin, &request); err != nil {
		os.Exit(2)
	}
	status := os.Args[len(os.Args)-1]
	response := api.Response{
		APIVersion: api.APIVersion, ComponentID: request.ComponentID, Status: status,
		PlanDigest: digestForTest("component-plan"),
		Actions: []api.PlannedAction{{
			ID: "policy", Type: "replace", Risk: "medium",
			Resource:      api.Resource{Kind: "file", ID: "policy", Path: "/tmp/fake/policy.json"},
			DesiredDigest: digestForTest("policy"),
		}},
	}
	if err := WriteFrame(os.Stdout, response); err != nil {
		os.Exit(3)
	}
	os.Exit(0)
}

func digestForTest(value string) string {
	return fmt.Sprintf("sha256:%x", sha256.Sum256([]byte(value)))
}
