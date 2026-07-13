package routes

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/osolmaz/brokerkit/agentconformance"
	"github.com/osolmaz/brokerkit/agentops"
	"github.com/osolmaz/brokerkit/agentv1"
	"github.com/osolmaz/brokerkit/audit"
	"github.com/osolmaz/brokerkit/brokers/sudo/internal/catalog"
	"github.com/osolmaz/brokerkit/brokers/sudo/internal/executorclient"
	"github.com/osolmaz/brokerkit/brokers/sudo/internal/executorprotocol"
	"github.com/osolmaz/brokerkit/brokers/sudo/internal/plan"
	"github.com/osolmaz/brokerkit/brokers/sudo/internal/sudopolicy"
	"github.com/osolmaz/brokerkit/grants"
	"github.com/osolmaz/brokerkit/notify"
	"github.com/osolmaz/brokerkit/operatorv1"
	corepolicy "github.com/osolmaz/brokerkit/policy"
	"github.com/osolmaz/brokerkit/state"
)

const (
	testClientSecret   = "sudo-client-secret-abcdefghijklmnopqrstuvwxyz"
	testOperatorSecret = "sudo-operator-secret-abcdefghijklmnopqrstuvwxyz"
)

func TestSudoAgentV1Conformance(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "state")
	helper := &fakeHelper{status: executorprotocol.StatusCompleted}
	var current *Server
	start := func() (agentconformance.Endpoint, error) {
		database, err := state.Open(context.Background(), directory, state.Options{})
		if err != nil {
			return agentconformance.Endpoint{}, err
		}
		server, err := newTestServer(database, helper, t.TempDir())
		if err != nil {
			_ = database.Close()
			return agentconformance.Endpoint{}, err
		}
		current = server
		ctx, cancel := context.WithCancel(context.Background())
		server.Start(ctx)
		httpServer := httptest.NewServer(server.Handler())
		return agentconformance.Endpoint{BaseURL: httpServer.URL, HTTPClient: httpServer.Client(), Close: func() error {
			httpServer.Close()
			cancel()
			return server.Close()
		}}, nil
	}
	agentconformance.RunAgentV1(t, agentconformance.Fixture{Start: start, Token: testClientSecret, WaitTime: 5 * time.Second,
		Request: validSubmission("sudo-conformance"),
		Approve: func(ctx context.Context, operation agentv1.Operation) error {
			grant, err := current.grants.Get(operation.ApprovalID)
			if err != nil {
				return err
			}
			_, err = current.control.Decisions.Decide(ctx, grant.ID, operatorv1.ActionApprove, "operator", operatorv1.Decision{
				ExpectedRevision: grant.Revision, IdempotencyKey: "approve-sudo-conformance"})
			return err
		},
		Verify: func(t *testing.T, operation agentv1.Operation) {
			t.Helper()
			if operation.State != agentv1.StateSucceeded || !strings.Contains(string(operation.Result), `"stdout_base64":"c2NhbGVk"`) {
				t.Fatalf("terminal operation = %#v", operation)
			}
		},
	})
}

func TestSudoAgentValidationAndLegacyRouteRemoval(t *testing.T) {
	server, _, closeServer := testServer(t)
	defer closeServer()
	for _, request := range []agentv1.SubmitRequest{
		{IdempotencyKey: "bad-target", Operation: sudopolicy.OperationExecCommand, Target: json.RawMessage(`{"kind":"repo","name":"root"}`), Arguments: validSubmission("x").Arguments, Reason: "test"},
		{IdempotencyKey: "bad-command", Operation: sudopolicy.OperationExecCommand, Target: validSubmission("x").Target, Arguments: json.RawMessage(`{"command_id":"missing","arguments":{}}`), Reason: "test"},
		{IdempotencyKey: "bad-operation", Operation: "shell.exec", Target: validSubmission("x").Target, Arguments: validSubmission("x").Arguments, Reason: "test"},
	} {
		if _, _, err := server.submitAgentOperation(t.Context(), "bob", request); err == nil {
			t.Fatalf("invalid request accepted: %#v", request)
		}
	}
	for _, path := range []string{"/api/v1/requests", "/api/v1/executions"} {
		response := httptest.NewRecorder()
		server.Handler().ServeHTTP(response, httptest.NewRequestWithContext(t.Context(), http.MethodPost, path, http.NoBody))
		if response.Code != http.StatusNotFound {
			t.Fatalf("legacy route %s status = %d", path, response.Code)
		}
	}
}

func TestSudoAgentAmbiguousExecutionRetainsApproval(t *testing.T) {
	server, helper, closeServer := testServer(t)
	defer closeServer()
	helper.status = executorprotocol.StatusAmbiguous
	operation, _, err := server.submitAgentOperation(t.Context(), "bob", validSubmission("ambiguous"))
	if err != nil {
		t.Fatal(err)
	}
	grant, _ := server.grants.Get(operation.ApprovalID)
	_, err = server.control.Decisions.Decide(t.Context(), grant.ID, operatorv1.ActionApprove, "operator", operatorv1.Decision{
		ExpectedRevision: grant.Revision, IdempotencyKey: "approve-ambiguous"})
	if err != nil {
		t.Fatal(err)
	}
	server.advanceOperation(t.Context(), operation)
	failed, _ := server.operations.GetByID(operation.ID)
	stored, _ := server.grants.Get(grant.ID)
	if failed.State != agentv1.StateFailed || failed.Error == nil || failed.Error.Code != "execution_result_unknown" || !stored.ReservationRetained {
		t.Fatalf("operation = %#v, grant = %#v", failed, stored)
	}
}

func TestConcurrentSudoReplayCreatesOneGrant(t *testing.T) {
	server, _, closeServer := testServer(t)
	defer closeServer()
	results := make(chan agentv1.Operation, 2)
	var workers sync.WaitGroup
	for range 2 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			operation, _, _ := server.submitAgentOperation(t.Context(), "bob", validSubmission("concurrent"))
			results <- operation
		}()
	}
	workers.Wait()
	close(results)
	var id string
	for operation := range results {
		if id != "" && operation.ID != id {
			t.Fatalf("operation IDs differ: %s and %s", id, operation.ID)
		}
		id = operation.ID
	}
	values, err := server.grants.ListForClient("bob")
	if err != nil || len(values) != 1 {
		t.Fatalf("grants = %#v, %v", values, err)
	}
}

func TestReadinessAndNotificationFailure(t *testing.T) {
	server, _, closeServer := testServer(t)
	defer closeServer()
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/readyz", http.NoBody))
	if response.Code != http.StatusOK {
		t.Fatalf("readiness = %d", response.Code)
	}
	server.helper = &executorclient.Client{SocketPath: "/missing", Dial: func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("offline")
	}}
	response = httptest.NewRecorder()
	server.Handler().ServeHTTP(response, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/readyz", http.NoBody))
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("offline readiness = %d", response.Code)
	}
	server.notifier = errorNotifier{}
	server.operatorConfigured = false
	operation, _, err := server.submitAgentOperation(t.Context(), "bob", validSubmission("notify-failure"))
	if err != nil || operation.State != agentv1.StateFailed {
		t.Fatalf("notification failure = %#v, %v", operation, err)
	}
}

func TestAdvancePendingOperationAndInvalidApproval(t *testing.T) {
	server, _, closeServer := testServer(t)
	defer closeServer()
	request := validSubmission("advance-pending")
	operation, _, err := server.operations.Submit(agentops.Submit{Broker: "sudo-broker", ClientID: "bob", IdempotencyKey: request.IdempotencyKey,
		Operation: request.Operation, Target: request.Target, Arguments: request.Arguments, Reason: request.Reason,
		Presentation: agentv1.Presentation{Title: "advance"}})
	if err != nil {
		t.Fatal(err)
	}
	server.advanceOperation(t.Context(), operation)
	pending, _ := server.operations.GetByID(operation.ID)
	if pending.State != agentv1.StatePending || pending.ApprovalID == "" {
		t.Fatalf("advanced operation = %#v", pending)
	}
	invalid, _, err := server.operations.Submit(agentops.Submit{Broker: "sudo-broker", ClientID: "bob", IdempotencyKey: "invalid-approval",
		Operation: request.Operation, Target: request.Target, Arguments: request.Arguments, Reason: request.Reason,
		Presentation: agentv1.Presentation{Title: "invalid"}})
	if err != nil {
		t.Fatal(err)
	}
	invalid, err = server.operations.SetApproval(invalid.ID, "missing-grant")
	if err != nil {
		t.Fatal(err)
	}
	invalid, err = server.operations.Transition(invalid.ID, agentv1.StateApproved)
	if err != nil {
		t.Fatal(err)
	}
	invalid, err = server.operations.Transition(invalid.ID, agentv1.StateExecuting)
	if err != nil {
		t.Fatal(err)
	}
	server.executeOperation(t.Context(), invalid)
	failed, _ := server.operations.GetByID(invalid.ID)
	if failed.State != agentv1.StateFailed || failed.Error == nil || failed.Error.Code != "approval_unavailable" {
		t.Fatalf("invalid approval operation = %#v", failed)
	}
}

func TestSudoExecutionSettlementBranches(t *testing.T) {
	for _, test := range []struct {
		name        string
		status      string
		wantCode    string
		retained    bool
		preDispatch bool
	}{
		{name: "rejected", status: executorprotocol.StatusRejected, wantCode: "execution_rejected"},
		{name: "not started", status: "not-started", wantCode: "execution_rejected"},
		{name: "missing outcome", status: "missing-outcome", wantCode: "execution_result_unknown", retained: true},
		{name: "unknown", status: "unknown", wantCode: "execution_result_unknown", retained: true},
		{name: "before dispatch", wantCode: "helper_unavailable", preDispatch: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			server, helper, closeServer := testServer(t)
			defer closeServer()
			operation, grant := approvedOperation(t, server, "settle-"+strings.ReplaceAll(test.name, " ", "-"))
			if test.preDispatch {
				server.helper = &executorclient.Client{SocketPath: "/missing", Dial: func(context.Context, string, string) (net.Conn, error) {
					return nil, errors.New("offline")
				}}
			} else {
				helper.status = test.status
			}
			server.executeOperation(t.Context(), operation)
			failed, _ := server.operations.GetByID(operation.ID)
			stored, _ := server.grants.Get(grant.ID)
			if failed.State != agentv1.StateFailed || failed.Error == nil || failed.Error.Code != test.wantCode || stored.ReservationRetained != test.retained {
				t.Fatalf("operation = %#v, grant = %#v", failed, stored)
			}
		})
	}
}

func TestSudoApprovalTransitionsAndRecovery(t *testing.T) {
	server, _, closeServer := testServer(t)
	defer closeServer()
	operation, _, err := server.submitAgentOperation(t.Context(), "bob", validSubmission("deny"))
	if err != nil {
		t.Fatal(err)
	}
	grant, _ := server.grants.Get(operation.ApprovalID)
	if _, err := server.control.Decisions.Decide(t.Context(), grant.ID, operatorv1.ActionDeny, "operator", operatorv1.Decision{
		ExpectedRevision: grant.Revision, IdempotencyKey: "deny-operation"}); err != nil {
		t.Fatal(err)
	}
	if denied := server.syncOperationApproval(operation); denied.State != agentv1.StateDenied {
		t.Fatalf("denied operation = %#v", denied)
	}
	executing, _, err := server.operations.Submit(agentops.Submit{Broker: "sudo-broker", ClientID: "bob", IdempotencyKey: "recover",
		Operation: sudopolicy.OperationExecCommand, Target: validSubmission("x").Target, Arguments: validSubmission("x").Arguments,
		Reason: "recover", Presentation: agentv1.Presentation{Title: "recover"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := server.operations.Transition(executing.ID, agentv1.StateApproved); err != nil {
		t.Fatal(err)
	}
	executing, err = server.operations.Transition(executing.ID, agentv1.StateExecuting)
	if err != nil {
		t.Fatal(err)
	}
	server.recoverOperations(t.Context())
	recovered, _ := server.operations.GetByID(executing.ID)
	if recovered.State != agentv1.StateFailed || recovered.Error == nil || recovered.Error.Code != "execution_interrupted" {
		t.Fatalf("recovered operation = %#v", recovered)
	}
	if server.OperatorHandler() == nil {
		t.Fatal("operator handler is nil")
	}
}

func TestSudoTelegramNotificationIsIdempotent(t *testing.T) {
	server, _, closeServer := testServer(t)
	defer closeServer()
	memory := &notify.Memory{}
	server.notifier = memory
	first, _, err := server.submitAgentOperation(t.Context(), "bob", validSubmission("notified"))
	if err != nil || first.ApprovalID == "" || len(memory.Messages) != 1 {
		t.Fatalf("notified operation = %#v, messages = %d, %v", first, len(memory.Messages), err)
	}
	second, _, err := server.submitAgentOperation(t.Context(), "bob", validSubmission("notified"))
	if err != nil || second.ID != first.ID || len(memory.Messages) != 1 {
		t.Fatalf("replay = %#v, messages = %d, %v", second, len(memory.Messages), err)
	}
}

func TestSudoNotificationFallbackAndPolicyBounds(t *testing.T) {
	server, _, closeServer := testServer(t)
	defer closeServer()
	server.notifier = errorNotifier{}
	operation, _, err := server.submitAgentOperation(t.Context(), "bob", validSubmission("operator-fallback"))
	if err != nil || operation.State != agentv1.StatePending || operation.ApprovalID == "" {
		t.Fatalf("operator fallback = %#v, %v", operation, err)
	}
	grant, err := server.grants.Get(operation.ApprovalID)
	if err != nil || grant.NotificationClaimedAt.IsZero() {
		t.Fatalf("retained notification = %#v, %v", grant, err)
	}
	for _, bounds := range []*corepolicy.GrantPolicy{
		{Mode: string(corepolicy.GrantModeWindow), DefaultMaxUses: 1, MaxUses: 1},
		{Mode: string(corepolicy.GrantModeExecution), DefaultMinutes: 2, MaxMinutes: 1, RequestTTLMinutes: 1, DefaultMaxUses: 1, MaxUses: 1},
		{Mode: string(corepolicy.GrantModeExecution), DefaultMinutes: 1, MaxMinutes: 1, RequestTTLMinutes: 1, DefaultMaxUses: 2, MaxUses: 2},
	} {
		if _, _, err := grantBounds(bounds, 0); err == nil {
			t.Fatalf("invalid bounds accepted: %#v", bounds)
		}
	}
}

func TestServerStartPollsDecisions(t *testing.T) {
	server, _, closeServer := testServer(t)
	defer closeServer()
	poller := &fakePoller{called: make(chan struct{}, 1)}
	server.poller = poller
	ctx, cancel := context.WithCancel(t.Context())
	server.Start(ctx)
	select {
	case <-poller.called:
	case <-time.After(time.Second):
		t.Fatal("decision poller did not start")
	}
	cancel()
}

func approvedOperation(t *testing.T, server *Server, key string) (agentv1.Operation, grants.Grant) {
	t.Helper()
	operation, _, err := server.submitAgentOperation(t.Context(), "bob", validSubmission(key))
	if err != nil {
		t.Fatal(err)
	}
	grant, err := server.grants.Get(operation.ApprovalID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := server.control.Decisions.Decide(t.Context(), grant.ID, operatorv1.ActionApprove, "operator", operatorv1.Decision{
		ExpectedRevision: grant.Revision, IdempotencyKey: "approve-" + key}); err != nil {
		t.Fatal(err)
	}
	operation = server.syncOperationApproval(operation)
	operation, err = server.operations.Transition(operation.ID, agentv1.StateExecuting)
	if err != nil {
		t.Fatal(err)
	}
	return operation, grant
}

func validSubmission(key string) agentv1.SubmitRequest {
	return agentv1.SubmitRequest{IdempotencyKey: key, Operation: sudopolicy.OperationExecCommand,
		Target:    json.RawMessage(`{"kind":"user","name":"root"}`),
		Arguments: json.RawMessage(`{"command_id":"scale","arguments":{"replicas":2}}`), Reason: "scale release"}
}

func testServer(t *testing.T) (*Server, *fakeHelper, func()) {
	t.Helper()
	database, err := state.Open(t.Context(), t.TempDir(), state.Options{})
	if err != nil {
		t.Fatal(err)
	}
	helper := &fakeHelper{status: executorprotocol.StatusCompleted}
	server, err := newTestServer(database, helper, t.TempDir())
	if err != nil {
		_ = database.Close()
		t.Fatal(err)
	}
	return server, helper, func() { _ = server.Close() }
}

func newTestServer(database *state.Database, helper *fakeHelper, directory string) (*Server, error) {
	snapshot, err := catalog.Parse([]byte(fmt.Sprintf(`{"version":1,"commands":[{
		"id":"scale","executable":"/usr/bin/printf","arguments":[{"literal":"%%s"},{"slot":"replicas","type":"integer","minimum":1,"maximum":4}],
		"target_users":["root"],"working_directory":%q,"timeout_seconds":5,"max_output_bytes":100,"risk":"high"}]}`, directory)))
	if err != nil {
		return nil, err
	}
	policyDocument := `{"rules":[{"id":"request-scale","effect":"request","clients":["bob"],"operations":["exec.command"],
		"targets":[{"kind":"user","name":"root"}],"attrs":{"command_id":["scale"],"argument.replicas":["2"]},
		"grant_policy":{"mode":"execution","default_minutes":2,"max_minutes":5,"request_ttl_minutes":2,"default_max_uses":1,"max_uses":1}}]}`
	brokerPolicy, err := corepolicy.Parse([]byte(policyDocument), sudopolicy.Registry(snapshot))
	if err != nil {
		return nil, err
	}
	client := &executorclient.Client{SocketPath: "/fake/helper.sock", Dial: helper.dial}
	return New(Options{Policy: brokerPolicy, Catalog: snapshot, Database: database, Identities: fakeIdentities{}, Helper: client,
		ClientSecrets: map[string]string{"bob": testClientSecret}, OperatorSecrets: map[string]string{"operator": testOperatorSecret},
		Audit: audit.New(&bytes.Buffer{}), Now: time.Now, OperatorConfigured: true})
}

type fakeIdentities struct{}

func (fakeIdentities) Lookup(string) (plan.Identity, error) {
	return plan.Identity{Name: "root", UID: 0, GID: 0}, nil
}

type fakeHelper struct {
	mu         sync.Mutex
	status     string
	executions int
}

func (f *fakeHelper) dial(_ context.Context, _, _ string) (net.Conn, error) {
	client, server := net.Pipe()
	go func() {
		defer func() { _ = server.Close() }()
		request, err := executorprotocol.ReadRequest(server)
		if err != nil {
			return
		}
		if request.Type == executorprotocol.TypePing {
			_ = executorprotocol.WriteResponse(server, executorprotocol.Response{Version: executorprotocol.Version, Status: executorprotocol.StatusReady})
			return
		}
		f.mu.Lock()
		f.executions++
		status := f.status
		f.mu.Unlock()
		if status == executorprotocol.StatusAmbiguous {
			_ = executorprotocol.WriteResponse(server, executorprotocol.NewAmbiguous(request.ExecutionID, "lost_result"))
			return
		}
		if status == executorprotocol.StatusRejected {
			_ = executorprotocol.WriteResponse(server, executorprotocol.NewRejected("plan_drift"))
			return
		}
		if status == "not-started" {
			_ = executorprotocol.WriteResponse(server, executorprotocol.NewCompleted(request.ExecutionID, executorprotocol.Outcome{}))
			return
		}
		if status == "missing-outcome" || status == "unknown" {
			_ = executorprotocol.WriteResponse(server, executorprotocol.Response{Version: executorprotocol.Version, ExecutionID: request.ExecutionID, Status: status})
			return
		}
		_ = executorprotocol.WriteResponse(server, executorprotocol.NewCompleted(request.ExecutionID,
			executorprotocol.Outcome{Started: true, ExitCode: 0, Stdout: []byte("scaled")}))
	}()
	return client, nil
}

type errorNotifier struct{}

func (errorNotifier) SendApproval(context.Context, notify.ApprovalMessage) (notify.MessageRef, error) {
	return notify.MessageRef{}, errors.New("offline")
}
func (errorNotifier) UpdateStatus(context.Context, notify.MessageRef, string) error { return nil }

type fakePoller struct{ called chan struct{} }

func (p *fakePoller) Poll(ctx context.Context, _ func(context.Context, notify.Decision) notify.DecisionResult) {
	p.called <- struct{}{}
	<-ctx.Done()
}
