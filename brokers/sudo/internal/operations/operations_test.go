package operations

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/osolmaz/brokerkit/agentv1"
	"github.com/osolmaz/brokerkit/brokers/sudo/internal/catalog"
	"github.com/osolmaz/brokerkit/brokers/sudo/internal/executorclient"
	"github.com/osolmaz/brokerkit/brokers/sudo/internal/executorprotocol"
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

func TestCommandAdapterExecuteClassifiesHelperResponses(t *testing.T) {
	t.Parallel()
	value := executablePlan()
	completed, err := commandAdapter{helper: helperClient(t, executorprotocol.NewCompleted(value.ExecutionID, executorprotocol.Outcome{
		Started: true, ExitCode: 7, Stdout: []byte("out"),
	}))}.Execute(context.Background(), value)
	if err != nil || !completed.Proven || !strings.Contains(string(completed.Result), `"exit_code":7`) {
		t.Fatalf("completed execution = %+v, %v", completed, err)
	}
	_, err = commandAdapter{helper: helperClient(t, executorprotocol.NewRejected("policy_denied"))}.Execute(context.Background(), value)
	if !errors.Is(err, errExecutionRejected) || operationruntime.IsPossiblePartial(err) {
		t.Fatalf("rejected execution err = %v", err)
	}
	_, err = commandAdapter{helper: helperClient(t, executorprotocol.NewAmbiguous(value.ExecutionID, "lost_response"))}.Execute(context.Background(), value)
	if !operationruntime.IsPossiblePartial(err) {
		t.Fatalf("ambiguous execution err = %v", err)
	}
	_, err = commandAdapter{helper: &executorclient.Client{SocketPath: "/unused", Dial: func(context.Context, string, string) (net.Conn, error) {
		client, server := net.Pipe()
		_ = server.Close()
		return client, nil
	}}}.Execute(context.Background(), value)
	if !operationruntime.IsPossiblePartial(err) {
		t.Fatalf("dispatched transport failure err = %v", err)
	}
	if _, err := (commandAdapter{}).Execute(context.Background(), Plan{}); err == nil {
		t.Fatal("incomplete execution authority was accepted")
	}
}

func helperClient(t *testing.T, response executorprotocol.Response) *executorclient.Client {
	t.Helper()
	return &executorclient.Client{SocketPath: "/unused", Dial: func(context.Context, string, string) (net.Conn, error) {
		client, server := net.Pipe()
		go func() {
			defer func() { _ = server.Close() }()
			if _, err := executorprotocol.ReadRequest(server); err != nil {
				return
			}
			_ = executorprotocol.WriteResponse(server, response)
		}()
		return client, nil
	}}
}

func executablePlan() Plan {
	now := time.Now().UTC()
	return Plan{
		ExecutionID: "op-1", GrantID: "grant-1", ReservationID: "grant-1:r1", GrantExpiresAt: now.Add(time.Minute),
		Command: sudoplan.Plan{
			Schema: sudoplan.SchemaV1, RequestID: "op-1", ClientID: "bob", Operation: sudopolicy.OperationExecCommand,
			CommandID: "scale", TargetUser: "root", TargetUID: 0, TargetGID: 0, Executable: "/usr/bin/printf",
			Arguments: []string{"%s"}, WorkingDirectory: "/", Environment: []string{"LANG=C", "LC_ALL=C"},
			TimeoutSeconds: 5, MaxOutputBytes: 100, CatalogDigest: strings.Repeat("a", 64),
			RequestedDurationSeconds: 60, RequestedMaxUses: 1, CreatedAt: now,
		},
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
