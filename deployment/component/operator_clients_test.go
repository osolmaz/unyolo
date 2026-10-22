package component

import (
	"bytes"
	"encoding/json"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/osolmaz/unyolo/deployment/api"
	deploymentruntime "github.com/osolmaz/unyolo/deployment/runtime"
	clientconfig "github.com/osolmaz/unyolo/internal/config/client"
)

func TestAdapterDeliversOperatorCredentialToManagedOperator(t *testing.T) {
	current, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	group, err := user.LookupGroupId(current.Gid)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	operatorHome := filepath.Join(root, "operator")
	if err := os.Mkdir(operatorHome, 0o700); err != nil {
		t.Fatal(err)
	}
	endpoint := "unix:///run/unyolo/test/operator/broker.sock"
	profile := Profile{
		APIVersion: "unyolo.io/test-deployment/v1",
		SecretStores: []SecretStore{{
			ID: "approvers", Destination: filepath.Join(root, "operator-secrets"), Mode: 0o600, Owner: current.Username, Group: group.Name,
			Entries: []SecretEntry{{Identity: "telegram", Slot: "test-approver-telegram"}},
		}},
		OperatorClients: []OperatorClient{{OperatorID: "telegram", BrokerName: "test-broker", SecretSlot: "test-approver-telegram", Endpoint: endpoint}},
	}
	profileData, err := json.Marshal(profile)
	if err != nil {
		t.Fatal(err)
	}
	config := Config{ComponentID: "test", ProfileAPI: profile.APIVersion, AllowedPaths: []string{root}, BackupDirectory: filepath.Join(root, "backups")}
	base := api.Request{
		APIVersion: api.APIVersion, DeploymentDigest: "sha256:" + strings.Repeat("a", 64), ComponentID: "test", Profile: profileData,
		Operators: []api.OperatorBinding{{ID: "telegram", UnixUser: current.Username, Home: operatorHome}},
	}
	base.Action = api.ActionPlan
	planned := runAdapter(t, base, config)
	if planned.Status != "planned" || len(planned.Actions) != 2 || planned.Actions[0].ID != "operator-client-telegram" ||
		planned.Actions[0].Resource.Kind != "client" || planned.Credentials[0].Action != "install" {
		t.Fatalf("plan = %#v", planned)
	}
	secret := strings.Repeat("t", 43)
	base.Action, base.PlanDigest = api.ActionApply, planned.PlanDigest
	base.Secrets = []api.SecretDescriptor{{Name: "test-approver-telegram", FD: secretDescriptor(t, secret)}}
	applied := runAdapter(t, base, config)
	if applied.Status != "applied" {
		t.Fatalf("apply = %#v", applied)
	}
	path, err := clientconfig.OperatorPath(operatorHome, "test-broker")
	if err != nil {
		t.Fatal(err)
	}
	uid := os.Getuid()
	loaded, err := clientconfig.ReadOperatorPath(path, uid)
	if err != nil || loaded != (clientconfig.Operator{Endpoint: endpoint, Secret: secret}) {
		t.Fatalf("operator client = %#v, %v", loaded, err)
	}
	base.Action, base.Secrets, base.PlanDigest = api.ActionVerify, nil, ""
	verified := runAdapter(t, base, config)
	if verified.Status != "verified" || !strings.Contains(strings.Join(verified.Verification, "\n"), "operator client telegram for test-broker matches") {
		t.Fatalf("verify = %#v", verified)
	}
	base.Action = api.ActionPlan
	if replanned := runAdapter(t, base, config); len(replanned.Actions) != 0 || replanned.Credentials[0].Action != "retain" {
		t.Fatalf("retained plan = %#v", replanned)
	}
	if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if repaired := runAdapter(t, base, config); len(repaired.Actions) != 1 || repaired.Actions[0].ID != "operator-client-telegram" {
		t.Fatalf("damaged operator client plan = %#v", repaired)
	}
	base.Action = api.ActionVerify
	var input, output bytes.Buffer
	if err := deploymentruntime.WriteFrame(&input, base); err != nil {
		t.Fatal(err)
	}
	if err := Serve(t.Context(), &input, &output, config); err == nil || !strings.Contains(err.Error(), "operator client") {
		t.Fatalf("damaged operator client verify = %v", err)
	}
}

func TestValidateOperatorClients(t *testing.T) {
	operators := []api.OperatorBinding{{ID: "telegram", UnixUser: "unyolo-telegram", Home: "/var/lib/unyolo-telegram"}}
	slots := map[string]bool{"github-approver-telegram": true}
	valid := OperatorClient{OperatorID: "telegram", BrokerName: "gh-broker", SecretSlot: "github-approver-telegram", Endpoint: "unix:///run/operator.sock"}
	if err := validateOperatorClients([]OperatorClient{valid}, operators, slots); err != nil {
		t.Fatal(err)
	}
	unbound, unknownSlot, noEndpoint := valid, valid, valid
	unbound.OperatorID = "person"
	unknownSlot.SecretSlot = "github-operator-secret"
	noEndpoint.Endpoint = ""
	for name, values := range map[string][]OperatorClient{
		"unbound operator": {unbound},
		"unknown slot":     {unknownSlot},
		"no endpoint":      {noEndpoint},
		"duplicate":        {valid, valid},
		"too many":         make([]OperatorClient, maxOperatorClients+1),
	} {
		if err := validateOperatorClients(values, operators, slots); err == nil {
			t.Fatalf("%s was accepted", name)
		}
	}
	state := inspected{operators: map[string]api.OperatorBinding{"telegram": {ID: "telegram", Home: "relative"}}}
	if err := inspectOperatorClients(Profile{OperatorClients: []OperatorClient{valid}}, &state); err == nil {
		t.Fatal("relative operator home was accepted")
	}
	if err := applyOperatorClients([]OperatorClient{valid}, state.operators, map[string][]byte{}); err == nil {
		t.Fatal("operator client without a credential was written")
	}
	if operatorClientCurrent("/missing", api.OperatorBinding{UnixUser: "missing-unyolo-test-user"}, valid, []byte("secret")) {
		t.Fatal("operator client of a missing account is current")
	}
}

func secretDescriptor(t *testing.T, value string) int {
	t.Helper()
	path := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = file.Close() }()
	descriptor, err := syscall.Dup(int(file.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	return descriptor
}
