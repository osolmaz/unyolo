package operations

import (
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/osolmaz/brokerkit/agentv1"
	"github.com/osolmaz/brokerkit/brokers/sudo/internal/catalog"
	"github.com/osolmaz/brokerkit/brokers/sudo/internal/executorclient"
	sudoplan "github.com/osolmaz/brokerkit/brokers/sudo/internal/plan"
	"github.com/osolmaz/brokerkit/brokers/sudo/internal/sudopolicy"
	"github.com/osolmaz/brokerkit/grants"
	"github.com/osolmaz/brokerkit/operationruntime"
)

func TestCommandAdapterResolveAndStoredPlanBinding(t *testing.T) {
	snapshot := testCatalog(t)
	registry, err := NewRegistry(snapshot, &executorclient.Client{SocketPath: "/test/helper.sock"})
	if err != nil {
		t.Fatal(err)
	}
	adapter, found := registry.Lookup(sudopolicy.OperationExecCommand)
	if !found || !adapter.(interface{ RequiresApproval() bool }).RequiresApproval() {
		t.Fatal("approval-required sudo adapter is missing")
	}
	target := json.RawMessage(`{"kind":"user","name":"root"}`)
	arguments := json.RawMessage(`{"command_id":"scale","arguments":{"replicas":2}}`)
	input, err := adapter.Decode(target, arguments)
	if err != nil {
		t.Fatal(err)
	}
	provider, err := adapter.Resolve(t.Context(), input)
	if err != nil || provider.Resolved.CommandID != "scale" || provider.Authorization.Client != "" {
		t.Fatalf("resolved plan = %+v, %v", provider, err)
	}
	request := grants.Request{Client: "bob", ClientRequestID: "op-1", Operation: sudopolicy.OperationExecCommand,
		Target: provider.Authorization.Target, Attrs: provider.Authorization.Attrs, Duration: time.Minute, MaxUses: 1}
	command, err := sudoplan.Build(request, provider.Resolved, sudoplan.Identity{Name: "root"}, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	operation := agentv1.Operation{ID: "op-1", ClientID: "bob", Operation: sudopolicy.OperationExecCommand,
		Target: target, Arguments: arguments}
	loaded, err := LoadStored(operation, command, snapshot)
	if err != nil || loaded.ExecutionID != operation.ID || loaded.Authorization.Client != "bob" {
		t.Fatalf("loaded plan = %+v, %v", loaded, err)
	}
	operation.Arguments = json.RawMessage(`{"command_id":"scale","arguments":{"replicas":3}}`)
	if _, err := LoadStored(operation, command, snapshot); err == nil {
		t.Fatal("stored plan accepted changed arguments")
	}
}

func TestCommandAdapterRejectsInvalidInputAndBindsReservation(t *testing.T) {
	adapter := commandAdapter{snapshot: testCatalog(t)}
	for _, input := range []struct{ target, arguments json.RawMessage }{
		{json.RawMessage(`{"kind":"repo","name":"root"}`), json.RawMessage(`{}`)},
		{json.RawMessage(`{"kind":"user","name":"root"}`), json.RawMessage(`{"command_id":"scale"}`)},
		{json.RawMessage(`{"kind":"user","name":"root","name":"bob"}`), json.RawMessage(`{"command_id":"scale","arguments":{}}`)},
	} {
		if _, err := adapter.Decode(input.target, input.arguments); err == nil {
			t.Fatalf("invalid input accepted: %s / %s", input.target, input.arguments)
		}
	}
	value := Plan{ExecutionID: "op-1"}
	grant := grants.Grant{ID: "grant-1", ClientRequestID: "op-1", Revision: 4, ExpiresAt: time.Now().Add(time.Minute)}
	bound, err := adapter.BindReservation(value, grant)
	if err != nil || bound.GrantID != grant.ID || bound.ReservationID != "grant-1:r4" || !bound.GrantExpiresAt.Equal(grant.ExpiresAt) {
		t.Fatalf("reservation binding = %+v, %v", bound, err)
	}
	grant.ClientRequestID = "other"
	if _, err := adapter.BindReservation(value, grant); err == nil {
		t.Fatal("mismatched reservation was accepted")
	}
}

func TestExecutionFailureClassification(t *testing.T) {
	partial := &operationruntime.PossiblePartialError{Err: errors.New("lost response")}
	if DefinitiveFailure(partial) || !DefinitiveFailure(errors.New("offline")) {
		t.Fatal("dispatch boundary classification drifted")
	}
	for _, test := range []struct {
		err  error
		code string
	}{
		{fmt.Errorf("%w: denied", errExecutionRejected), "execution_rejected"},
		{errors.New("offline"), "helper_unavailable"},
		{partial, "execution_result_unknown"},
	} {
		if failure := ExecutionFailure(test.err, nil); failure.Code != test.code {
			t.Fatalf("failure %v = %+v", test.err, failure)
		}
	}
}

func testCatalog(t *testing.T) *catalog.Snapshot {
	t.Helper()
	snapshot, err := catalog.Parse([]byte(`{"version":1,"commands":[{"id":"scale","executable":"/usr/bin/printf",
		"arguments":[{"literal":"%s"},{"slot":"replicas","type":"integer","minimum":1,"maximum":4}],
		"target_users":["root"],"working_directory":"/","timeout_seconds":5,"max_output_bytes":100,"risk":"high"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}
