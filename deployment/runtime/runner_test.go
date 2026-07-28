package runtime

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/osolmaz/unyolo/deployment/api"
	"github.com/osolmaz/unyolo/internal/host/bundle"
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

func TestOwnershipEnvelopeCoversEveryResourceKind(t *testing.T) {
	component := bundle.Component{Setup: &bundle.SetupAdapter{Ownership: bundle.OwnershipEnvelope{
		Paths: []string{"/etc/test"}, Services: []string{"test.service"},
		Accounts: []string{"test"}, Groups: []string{"test-agent"},
	}}}
	response := api.Response{
		APIVersion: api.APIVersion, ComponentID: "test", Status: "planned", PlanDigest: digestForTest("plan"),
		Actions: []api.PlannedAction{
			{ID: "directory", Type: "create", Risk: "high", Resource: api.Resource{Kind: "directory", ID: "config", Path: "/etc/test"}},
			{ID: "file", Type: "write", Risk: "high", Resource: api.Resource{Kind: "file", ID: "config", Path: "/etc/test/config"}},
			{ID: "credential", Type: "write", Risk: "critical", Resource: api.Resource{Kind: "credential", ID: "secret", Path: "/etc/test/secret"}},
			{ID: "client", Type: "write", Risk: "critical", Resource: api.Resource{Kind: "client", ID: "client", Path: "/etc/test/client"}},
			{ID: "service", Type: "restart", Risk: "medium", Resource: api.Resource{Kind: "service", ID: "test.service"}},
			{ID: "account", Type: "create", Risk: "high", Resource: api.Resource{Kind: "account", ID: "test"}},
			{ID: "group", Type: "create", Risk: "high", Resource: api.Resource{Kind: "group", ID: "test-agent"}},
		},
	}
	if err := ValidateOwnership(response, component); err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []api.Resource{
		{Kind: "file", ID: "/outside"}, {Kind: "service", ID: "other.service"},
		{Kind: "credential", ID: "secret", Path: "/outside"}, {Kind: "account", ID: "other"},
		{Kind: "group", ID: "other"}, {Kind: "unknown", ID: "test"},
	} {
		value := response
		value.Actions = []api.PlannedAction{{ID: "invalid", Type: "write", Risk: "high", Resource: invalid}}
		if err := ValidateOwnership(value, component); err == nil {
			t.Fatalf("resource was accepted: %#v", invalid)
		}
	}
	if err := ValidateOwnership(response, bundle.Component{}); err == nil {
		t.Fatal("component without setup ownership was accepted")
	}
}

func TestBoundedBufferCapsAdapterOutput(t *testing.T) {
	buffer := &boundedBuffer{maximum: 4}
	if count, err := buffer.Write([]byte("excess")); err != nil || count != 6 || buffer.data.String() != "exce" || !buffer.overflowed {
		t.Fatalf("bounded output = %q, overflow=%v, count=%d, err=%v", buffer.data.String(), buffer.overflowed, count, err)
	}
}

func TestRunnerRejectsInvalidCommandsAndResponses(t *testing.T) {
	request := api.Request{
		APIVersion: api.APIVersion, Action: api.ActionPlan,
		DeploymentDigest: digestForTest("deployment"), ComponentID: "fake",
		Profile: json.RawMessage(`{"api_version":"fake/v1"}`),
	}
	if _, err := (Runner{}).Run(context.Background(), Command{}, request, nil); err == nil {
		t.Fatal("empty command was accepted")
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := (Runner{}).Run(context.Background(), Command{Executable: executable, Arguments: []string{"-test.run=TestAdapterHelper", "--", "bad"}}, request, nil); err == nil {
		t.Fatal("invalid adapter response was accepted")
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := (Runner{}).Run(cancelled, Command{Executable: executable}, request, nil); err == nil {
		t.Fatal("cancelled launch was accepted")
	}
}

func TestRunnerRejectsWritableSecretDescriptor(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "secret")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = file.Close() }()
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
