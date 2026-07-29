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

	"github.com/osolmaz/unyolo/agent/conformance"
	"github.com/osolmaz/unyolo/agent/runtime"
	"github.com/osolmaz/unyolo/agent/v1"
	"github.com/osolmaz/unyolo/approval/notification"
	"github.com/osolmaz/unyolo/approval/notifier"
	"github.com/osolmaz/unyolo/authorization/grants"
	corepolicy "github.com/osolmaz/unyolo/authorization/policy"
	"github.com/osolmaz/unyolo/brokers/sudo/internal/catalog"
	"github.com/osolmaz/unyolo/brokers/sudo/internal/executorclient"
	"github.com/osolmaz/unyolo/brokers/sudo/internal/executorprotocol"
	"github.com/osolmaz/unyolo/brokers/sudo/internal/operations"
	"github.com/osolmaz/unyolo/brokers/sudo/internal/plan"
	"github.com/osolmaz/unyolo/brokers/sudo/internal/sudopolicy"
	"github.com/osolmaz/unyolo/internal/storage/state"
	"github.com/osolmaz/unyolo/operator/v1"
	"github.com/osolmaz/unyolo/telemetry/audit"
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

func TestSudoWindowGrantAuthorizesTwoIndependentCommands(t *testing.T) {
	database, err := state.Open(t.Context(), t.TempDir(), state.Options{})
	if err != nil {
		t.Fatal(err)
	}
	helper := &fakeHelper{status: executorprotocol.StatusCompleted}
	policyDocument := `{"rules":[{"id":"request-scale","effect":"request","clients":["bob"],"operations":["exec.command"],
		"targets":[{"kind":"user","name":"root"}],"attrs":{"command_id":["scale"],"argument.replicas":["2"]},
		"grant_policy":{"mode":"window","default_minutes":2,"max_minutes":5,"request_ttl_minutes":2,"default_max_uses":3,"max_uses":3}}]}`
	server, err := newTestServerWithPolicy(database, helper, t.TempDir(), policyDocument)
	if err != nil {
		_ = database.Close()
		t.Fatal(err)
	}
	defer func() { _ = server.Close() }()

	first, _, err := server.submitAgentOperation(t.Context(), "bob", validSubmission("window-first"))
	if err != nil || first.State != agentv1.StatePending {
		t.Fatalf("first submission = %+v, %v", first, err)
	}
	grant, err := server.grants.Get(first.ApprovalID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := server.control.Decisions.Decide(t.Context(), grant.ID, operatorv1.ActionApprove, "operator", operatorv1.Decision{
		ExpectedRevision: grant.Revision, IdempotencyKey: "approve-window",
	}); err != nil {
		t.Fatal(err)
	}
	server.operationRuntime.Advance(t.Context(), first)
	first, _ = server.operations.GetByID(first.ID)
	if first.State != agentv1.StateSucceeded {
		t.Fatalf("first operation = %+v", first)
	}

	second, _, err := server.submitAgentOperation(t.Context(), "bob", validSubmission("window-second"))
	if err != nil || second.State != agentv1.StateApproved || second.ApprovalID != grant.ID || second.PlanDigest == first.PlanDigest {
		t.Fatalf("second submission = %+v, %v", second, err)
	}
	server.operationRuntime.Advance(t.Context(), second)
	second, _ = server.operations.GetByID(second.ID)
	stored, grantErr := server.grants.Get(grant.ID)
	uses, usesErr := server.grants.ListUses(grant.ID)
	if second.State != agentv1.StateSucceeded || grantErr != nil || stored.Status != grants.StatusActive || stored.UsedCount != 2 ||
		stored.ReservedCount != 0 || usesErr != nil || len(uses) != 2 || helper.executions != 2 {
		t.Fatalf("second operation = %+v; grant=%+v, %v; uses=%+v, %v; executions=%d", second, stored, grantErr, uses, usesErr, helper.executions)
	}

	outside := validSubmission("window-outside")
	outside.Arguments = json.RawMessage(`{"command_id":"scale","arguments":{"replicas":3}}`)
	operation, _, err := server.submitAgentOperation(t.Context(), "bob", outside)
	if err != nil || operation.State != agentv1.StateDenied {
		t.Fatalf("out-of-scope submission = %+v, %v", operation, err)
	}
	if helper.executions != 2 {
		t.Fatalf("out-of-scope command reached helper: executions=%d", helper.executions)
	}
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
	server.operationRuntime.Advance(t.Context(), operation)
	failed, _ := server.operations.GetByID(operation.ID)
	stored, _ := server.grants.Get(grant.ID)
	if failed.State != agentv1.StateFailed || failed.Error == nil || failed.Error.Code != "execution_result_unknown" || !stored.ReservationRetained {
		t.Fatalf("operation = %#v, grant = %#v", failed, stored)
	}
}

func TestSudoAgentCancellationClosesApproval(t *testing.T) {
	for _, active := range []bool{false, true} {
		server, _, closeServer := testServer(t)
		operation, _, err := server.submitAgentOperation(t.Context(), "bob", validSubmission(fmt.Sprintf("cancel-%t", active)))
		if err != nil || operation.ApprovalID == "" {
			closeServer()
			t.Fatalf("submit active=%t: %#v, %v", active, operation, err)
		}
		grant, _ := server.grants.Get(operation.ApprovalID)
		if active {
			_, err = server.control.Decisions.Decide(t.Context(), grant.ID, operatorv1.ActionApprove, "operator", operatorv1.Decision{
				ExpectedRevision: grant.Revision, IdempotencyKey: "approve-before-cancel",
			})
			if err != nil {
				closeServer()
				t.Fatal(err)
			}
		}
		canceled, err := server.cancelAgentOperation(t.Context(), "bob", operation.ID)
		closed, getErr := server.grants.Get(operation.ApprovalID)
		want := grants.StatusCanceled
		if active {
			want = grants.StatusRevoked
		}
		closeServer()
		if err != nil || getErr != nil || canceled.State != agentv1.StateCanceled || closed.Status != want {
			t.Fatalf("cancel active=%t: operation=%#v grant=%#v err=%v/%v", active, canceled, closed, err, getErr)
		}
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
	resetOperationRuntime(t, server)
	operation, _, err := server.submitAgentOperation(t.Context(), "bob", validSubmission("notify-failure"))
	if err != nil || operation.State != agentv1.StateFailed {
		t.Fatalf("notification failure = %#v, %v", operation, err)
	}
	server.notifier = nil
	resetOperationRuntime(t, server)
	operation, _, err = server.submitAgentOperation(t.Context(), "bob", validSubmission("no-approval-channel"))
	if err != nil || operation.State != agentv1.StateFailed || operation.Error == nil || operation.Error.Code != "approval_channel_not_configured" {
		t.Fatalf("missing approval channel = %#v, %v", operation, err)
	}
	server.operatorConfigured = true
	resetOperationRuntime(t, server)
	server.identities = failingIdentities{}
	operation, _, err = server.submitAgentOperation(t.Context(), "bob", validSubmission("identity-failure"))
	if err != nil || operation.State != agentv1.StateFailed || operation.Error == nil || operation.Error.Code != "approval_request_failed" {
		t.Fatalf("identity failure = %#v, %v", operation, err)
	}
	server.identities = fakeIdentities{}
	operation, _, err = server.submitAgentOperation(t.Context(), "unmatched-client", validSubmission("policy-denial"))
	if err != nil || operation.State != agentv1.StateDenied || operation.Error == nil || operation.Error.Code != "operation_policy_denied" {
		t.Fatalf("policy denial = %#v, %v", operation, err)
	}
}

func TestInvalidStoredSudoApproval(t *testing.T) {
	server, _, closeServer := testServer(t)
	defer closeServer()
	request := validSubmission("invalid-approval")
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
	server.operationRuntime.Execute(t.Context(), invalid)
	failed, _ := server.operations.GetByID(invalid.ID)
	if failed.State != agentv1.StateFailed || failed.Error == nil || failed.Error.Code != "invalid_stored_operation" {
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
				helper.status = "dial-error"
			} else {
				helper.status = test.status
			}
			server.operationRuntime.Execute(t.Context(), operation)
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
	server.operationRuntime.Advance(t.Context(), operation)
	if denied, _ := server.operations.GetByID(operation.ID); denied.State != agentv1.StateDenied {
		t.Fatalf("denied operation = %#v", denied)
	}
	for _, test := range []struct {
		name   string
		close  func(grants.Grant) error
		key    string
		status agentv1.State
	}{
		{name: "canceled", key: "cancel", status: agentv1.StateCanceled, close: func(grant grants.Grant) error {
			_, err := server.grants.CancelForClient(grant.ID, grant.Client)
			return err
		}},
		{name: "revoked", key: "revoke", status: agentv1.StateCanceled, close: func(grant grants.Grant) error {
			approved, err := server.control.Decisions.Decide(t.Context(), grant.ID, operatorv1.ActionApprove, "operator", operatorv1.Decision{
				ExpectedRevision: grant.Revision, IdempotencyKey: "approve-before-revoke"})
			if err != nil {
				return err
			}
			_, err = server.grants.Revoke(approved.Grant.ID, "operator")
			return err
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			pending, _, submitErr := server.submitAgentOperation(t.Context(), "bob", validSubmission(test.key))
			if submitErr != nil {
				t.Fatal(submitErr)
			}
			pendingGrant, getErr := server.grants.Get(pending.ApprovalID)
			if getErr != nil {
				t.Fatal(getErr)
			}
			if closeErr := test.close(pendingGrant); closeErr != nil {
				t.Fatal(closeErr)
			}
			server.operationRuntime.Advance(t.Context(), pending)
			if closed, _ := server.operations.GetByID(pending.ID); closed.State != test.status {
				t.Fatalf("closed operation = %#v", closed)
			}
		})
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
	server.operationRuntime.Recover(t.Context())
	recovered, _ := server.operations.GetByID(executing.ID)
	if recovered.State != agentv1.StateFailed || recovered.Error == nil || recovered.Error.Code != "invalid_stored_operation" {
		t.Fatalf("recovered operation = %#v", recovered)
	}
	if server.OperatorHandler() == nil {
		t.Fatal("operator handler is nil")
	}
}

func TestSudoTelegramNotificationIsIdempotent(t *testing.T) {
	server, _, closeServer := testServer(t)
	defer closeServer()
	memory := &approvalnotify.Memory{}
	server.notifier = memory
	resetOperationRuntime(t, server)
	first, _, err := server.submitAgentOperation(t.Context(), "bob", validSubmission("notified"))
	if err != nil || first.ApprovalID == "" || len(memory.Messages) != 1 {
		t.Fatalf("notified operation = %#v, messages = %d, %v", first, len(memory.Messages), err)
	}
	second, _, err := server.submitAgentOperation(t.Context(), "bob", validSubmission("notified"))
	if err != nil || second.ID != first.ID || len(memory.Messages) != 1 {
		t.Fatalf("replay = %#v, messages = %d, %v", second, len(memory.Messages), err)
	}
}

func TestSudoDeliversDurableNotificationStatus(t *testing.T) {
	server, _, closeServer := testServer(t)
	defer closeServer()
	notifier := &retryStatusNotifier{}
	server.notifier = notifier
	resetOperationRuntime(t, server)
	operation, _, err := server.submitAgentOperation(t.Context(), "bob", validSubmission("durable-status"))
	if err != nil || operation.ApprovalID == "" || len(notifier.Messages) != 1 {
		t.Fatalf("submit = %#v messages=%d err=%v", operation, len(notifier.Messages), err)
	}
	grant, err := server.grants.Get(operation.ApprovalID)
	if err != nil {
		t.Fatal(err)
	}
	_, err = server.control.Decisions.Decide(t.Context(), grant.ID, operatorv1.ActionDeny, "operator:onur", operatorv1.Decision{
		ExpectedRevision: grant.Revision,
		IdempotencyKey:   "durable-status-deny",
	})
	if err != nil {
		t.Fatal(err)
	}
	server.deliverNotificationStatusUpdates(t.Context())
	server.deliverNotificationStatusUpdates(t.Context())
	if notifier.attempts != 2 || len(notifier.Statuses) != 1 || notifier.Statuses[0].Kind != notify.StatusDenied {
		t.Fatalf("notification attempts=%d statuses=%v", notifier.attempts, notifier.Statuses)
	}
	stored, err := server.grants.Get(grant.ID)
	if err != nil || stored.NotificationStatus != string(grants.StatusDenied) {
		t.Fatalf("stored grant = %#v err=%v", stored, err)
	}
}

func TestSudoNotificationSweeperStopsWithContext(t *testing.T) {
	server, _, closeServer := testServer(t)
	defer closeServer()
	server.notifier = &approvalnotify.Memory{}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	server.runNotificationSweeper(ctx)
}

type retryStatusNotifier struct {
	approvalnotify.Memory
	attempts int
}

func (n *retryStatusNotifier) UpdateStatus(ctx context.Context, ref notify.MessageRef, status notify.Status) error {
	n.attempts++
	if n.attempts == 1 {
		return errors.New("telegram unavailable")
	}
	return n.Memory.UpdateStatus(ctx, ref, status)
}

func TestSudoNotificationFallbackAndPolicyBounds(t *testing.T) {
	server, _, closeServer := testServer(t)
	defer closeServer()
	server.notifier = errorNotifier{}
	resetOperationRuntime(t, server)
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
		preparation := operations.Preparation{Decision: corepolicy.Decision{GrantPolicy: bounds}}
		if _, _, _, err := sudoRuntimeGrantBounds(preparation, corepolicy.GrantMode(bounds.Mode)); err == nil {
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

func TestServerCloseStopsPollerWithLiveStartContext(t *testing.T) {
	server, _, closeServer := testServer(t)
	defer closeServer()
	poller := &fakePoller{called: make(chan struct{}, 1), stopped: make(chan struct{})}
	server.poller = poller
	server.Start(context.Background())
	select {
	case <-poller.called:
	case <-time.After(time.Second):
		t.Fatal("decision poller did not start")
	}
	done := make(chan error, 1)
	go func() { done <- server.Close() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not join the decision poller")
	}
	select {
	case <-poller.stopped:
	default:
		t.Fatal("decision poller remained active after Close")
	}
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
	operation, err = server.operations.Transition(operation.ID, agentv1.StateApproved)
	if err != nil {
		t.Fatal(err)
	}
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

func resetOperationRuntime(t *testing.T, server *Server) {
	t.Helper()
	runtime, err := server.newOperationRuntime()
	if err != nil {
		t.Fatal(err)
	}
	server.operationRuntime = runtime
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
	policyDocument := `{"rules":[{"id":"request-scale","effect":"request","clients":["bob"],"operations":["exec.command"],
		"targets":[{"kind":"user","name":"root"}],"attrs":{"command_id":["scale"],"argument.replicas":["2"]},
		"grant_policy":{"mode":"execution","default_minutes":2,"max_minutes":5,"request_ttl_minutes":2,"default_max_uses":1,"max_uses":1}}]}`
	return newTestServerWithPolicy(database, helper, directory, policyDocument)
}

func newTestServerWithPolicy(database *state.Database, helper *fakeHelper, directory, policyDocument string) (*Server, error) {
	snapshot, err := catalog.Parse([]byte(fmt.Sprintf(`{"version":1,"commands":[{
		"id":"scale","executable":"/usr/bin/printf","arguments":[{"literal":"%%s"},{"slot":"replicas","type":"integer","minimum":1,"maximum":4}],
		"target_users":["root"],"working_directory":%q,"timeout_seconds":5,"max_output_bytes":100,"risk":"high"}]}`, directory)))
	if err != nil {
		return nil, err
	}
	brokerPolicy, err := corepolicy.Parse([]byte(policyDocument), sudopolicy.Registry(snapshot))
	if err != nil {
		return nil, err
	}
	client := &executorclient.Client{SocketPath: "/fake/helper.sock", Dial: helper.dial}
	return New(Options{Policy: brokerPolicy, Catalog: snapshot, Database: database, Identities: fakeIdentities{}, Helper: client,
		ClientSecrets: map[string]string{"bob": testClientSecret, "unmatched-client": strings.Repeat("u", 32)}, OperatorSecrets: map[string]string{"operator": testOperatorSecret},
		Audit: audit.New(&bytes.Buffer{}), Now: time.Now, OperatorConfigured: true})
}

type fakeIdentities struct{}

func (fakeIdentities) Lookup(string) (plan.Identity, error) {
	return plan.Identity{Name: "root", UID: 0, GID: 0}, nil
}

type failingIdentities struct{}

func (failingIdentities) Lookup(string) (plan.Identity, error) {
	return plan.Identity{}, errors.New("lookup failed")
}

type fakeHelper struct {
	mu         sync.Mutex
	status     string
	executions int
}

func (f *fakeHelper) dial(_ context.Context, _, _ string) (net.Conn, error) {
	f.mu.Lock()
	if f.status == "dial-error" {
		f.mu.Unlock()
		return nil, errors.New("offline")
	}
	f.mu.Unlock()
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

func (errorNotifier) SendApproval(context.Context, approvalnotify.Approval) (notify.MessageRef, error) {
	return notify.MessageRef{}, errors.New("offline")
}
func (errorNotifier) UpdateStatus(context.Context, notify.MessageRef, notify.Status) error {
	return nil
}

type fakePoller struct {
	called  chan struct{}
	stopped chan struct{}
}

func (p *fakePoller) Poll(ctx context.Context, _ func(context.Context, notify.Decision) notify.DecisionResult) {
	p.called <- struct{}{}
	<-ctx.Done()
	if p.stopped != nil {
		close(p.stopped)
	}
}
