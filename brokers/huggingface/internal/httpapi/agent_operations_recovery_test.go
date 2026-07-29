package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/osolmaz/unyolo/agent/api"
	"github.com/osolmaz/unyolo/agent/runtime"
	"github.com/osolmaz/unyolo/agent/v1"
	"github.com/osolmaz/unyolo/authorization/grants"
	"github.com/osolmaz/unyolo/brokers/huggingface/internal/config"
	"github.com/osolmaz/unyolo/brokers/huggingface/internal/hfgrant"
	"github.com/osolmaz/unyolo/brokers/huggingface/internal/hfplan"
	"github.com/osolmaz/unyolo/brokers/huggingface/internal/hubclient"
	"github.com/osolmaz/unyolo/brokers/huggingface/internal/operations"
	"github.com/osolmaz/unyolo/brokers/huggingface/internal/policy"
	"github.com/osolmaz/unyolo/telemetry/audit"
)

func TestInterruptedOperationRecoveryProvesOrRefusesResult(t *testing.T) {
	for _, test := range []struct {
		name       string
		present    bool
		wantState  agentv1.State
		wantResult bool
	}{
		{name: "proven", present: true, wantState: agentv1.StateSucceeded, wantResult: true},
		{name: "unknown", present: false, wantState: agentv1.StateFailed},
	} {
		t.Run(test.name, func(t *testing.T) {
			var present atomic.Bool
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/api/whoami-v2":
					writeJSON(w, http.StatusOK, map[string]string{"name": "alice"})
				case "/api/datasets/alice/recovery":
					if !present.Load() {
						http.NotFound(w, r)
						return
					}
					writeJSON(w, http.StatusOK, map[string]any{"id": "alice/recovery", "sha": "created", "private": true})
				default:
					http.NotFound(w, r)
				}
			}))
			defer upstream.Close()
			handler := newRecoveryTestServer(t, upstream.URL,
				`{"rules":[{"id":"create","effect":"allow","clients":["agent"],"operations":["repo.create"],"targets":[{"kind":"repo","type":"dataset","owner":"alice","name":"recovery"}],"attrs":{"visibility":"private"}}]}`)
			defer func() { _ = handler.Close() }()

			operation := seedExecutingRepoCreate(t, handler, "op_recover_"+test.name)
			present.Store(test.present)
			handler.reconcileInterruptedOperation(context.Background(), operation)
			stored, err := handler.operations.GetByID(operation.ID)
			if err != nil || stored.State != test.wantState {
				t.Fatalf("recovered operation = %#v, %v", stored, err)
			}
			if test.wantResult && !strings.Contains(string(stored.Result), `"repo_id":"alice/recovery"`) {
				t.Fatalf("result = %s", stored.Result)
			}
			if !test.wantResult && (stored.Error == nil || stored.Error.Code != "upstream_result_unknown") {
				t.Fatalf("error = %#v", stored.Error)
			}
		})
	}
}

func TestInterruptedOperationRejectsMissingPlan(t *testing.T) {
	upstream := newAbsentRepoUpstream(t, "alice", "dataset", "missing-plan")
	defer upstream.Close()
	handler := newRecoveryTestServer(t, upstream.URL, emptyPolicyJSON())
	defer func() { _ = handler.Close() }()
	operation, _, err := handler.operations.Submit(agentops.Submit{Broker: "hf-broker", ClientID: "agent", IdempotencyKey: "missing-plan",
		Operation: "repo.create", Target: []byte(`{"kind":"repo","type":"dataset","owner":"alice","name":"missing-plan"}`),
		Arguments: []byte(`{"visibility":"private"}`), Reason: "recovery test", Presentation: agentv1.Presentation{Title: "Create repository"}})
	if err != nil {
		t.Fatal(err)
	}
	operation, _ = handler.operations.Transition(operation.ID, agentv1.StateApproved)
	operation, _ = handler.operations.Transition(operation.ID, agentv1.StateExecuting)
	handler.reconcileInterruptedOperation(t.Context(), operation)
	stored, err := handler.operations.GetByID(operation.ID)
	if err != nil || stored.State != agentv1.StateFailed || stored.Error == nil || stored.Error.Code != "invalid_stored_operation" {
		t.Fatalf("operation = %#v, %v", stored, err)
	}
}

func TestPendingOperationRecoveryRebindsExactApproval(t *testing.T) {
	upstream := newAbsentRepoUpstream(t, "alice", "dataset", "rebind")
	defer upstream.Close()
	handler := newRecoveryTestServer(t, upstream.URL, emptyPolicyJSON())
	defer func() { _ = handler.Close() }()
	operation, requested := seedPendingRepoCreateGrant(t, handler, "op_rebind", "rebind")
	handler.advanceOperation(t.Context(), operation)
	stored, err := handler.operations.GetByID(operation.ID)
	if err != nil || stored.State != agentv1.StatePending || stored.ApprovalID != requested.Grant.ID {
		t.Fatalf("rebound operation = %#v, %v", stored, err)
	}
}

func TestInterruptedOperationCommitsReservedApproval(t *testing.T) {
	var present atomic.Bool
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/whoami-v2":
			writeJSON(w, http.StatusOK, map[string]string{"name": "alice"})
		case "/api/datasets/alice/reserved":
			if !present.Load() {
				http.NotFound(w, r)
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{"id": "alice/reserved", "sha": "created", "private": true})
		default:
			http.NotFound(w, r)
		}
	}))
	defer upstream.Close()
	handler := newRecoveryTestServer(t, upstream.URL, emptyPolicyJSON())
	defer func() { _ = handler.Close() }()
	operation, requested := seedPendingRepoCreateGrant(t, handler, "op_reserved", "reserved")
	operation = handler.recoverOperationApproval(operation)
	if operation.PlanDigest == "" || operation.ApprovalID != requested.Grant.ID {
		t.Fatalf("recovered binding = %+v", operation)
	}
	approved, err := handler.grants.Approve(requested.Grant.ID, requested.DecisionToken, "operator")
	if err != nil {
		t.Fatal(err)
	}
	operation, _ = handler.operations.Transition(operation.ID, agentv1.StateApproved)
	operation, _ = handler.operations.Transition(operation.ID, agentv1.StateExecuting)
	if _, err := handler.grants.ReserveUse(approved.ID, operation.ID, operation.Operation); err != nil {
		t.Fatal(err)
	}
	present.Store(true)
	handler.reconcileInterruptedOperation(t.Context(), operation)
	stored, err := handler.operations.GetByID(operation.ID)
	settled, grantErr := handler.grants.Get(approved.ID)
	if err != nil || stored.State != agentv1.StateSucceeded || grantErr != nil || settled.UsedCount != 1 || settled.ReservedCount != 0 {
		t.Fatalf("recovered operation = %#v, %v; grant = %#v, %v", stored, err, settled, grantErr)
	}
}

func TestExecutedOperationFailsClosedWhenResultCannotBeStored(t *testing.T) {
	upstream := newAbsentRepoUpstream(t, "alice", "dataset", "recovery")
	defer upstream.Close()
	handler := newRecoveryTestServer(t, upstream.URL, emptyPolicyJSON())
	defer func() { _ = handler.Close() }()
	operation := seedExecutingRepoCreate(t, handler, "op_store_failure")
	oversized := json.RawMessage(`{"value":"` + strings.Repeat("x", 2*1024*1024) + `"}`)
	handler.succeedExecutedOperation(operation, operations.Plan{}, oversized, false, "")
	stored, err := handler.operations.GetByID(operation.ID)
	if err != nil || stored.State != agentv1.StateFailed || stored.Error == nil || stored.Error.Code != "operation_store_unavailable" {
		t.Fatalf("stored operation = %+v, %v", stored, err)
	}
}

func TestNormalizedOperationResultDescribesRecoveredSuccess(t *testing.T) {
	result := normalizedOperationResult("repo.delete", nil)
	if !strings.Contains(string(result), `"operation":"repo.delete"`) || !strings.Contains(string(result), `"reconciled":true`) {
		t.Fatalf("normalized result = %s", result)
	}
}

func TestAmbiguousExecutionRetainsApprovalReservation(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/whoami-v2":
			writeJSON(w, http.StatusOK, map[string]string{"name": "alice"})
		case "/api/datasets/alice/ambiguous":
			http.NotFound(w, r)
		case "/api/repos/create":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`not-json`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer upstream.Close()
	handler := newRecoveryTestServer(t, upstream.URL, emptyPolicyJSON())
	defer func() { _ = handler.Close() }()
	operation, requested := seedPendingRepoCreateGrant(t, handler, "op_ambiguous", "ambiguous")
	operation = handler.recoverOperationApproval(operation)
	if _, err := handler.grants.Approve(requested.Grant.ID, requested.DecisionToken, "operator"); err != nil {
		t.Fatal(err)
	}
	operation, _ = handler.operations.Transition(operation.ID, agentv1.StateApproved)
	operation, _ = handler.operations.Transition(operation.ID, agentv1.StateExecuting)
	handler.executeOperation(t.Context(), operation)
	stored, err := handler.operations.GetByID(operation.ID)
	grant, grantErr := handler.grants.Get(requested.Grant.ID)
	if err != nil || grantErr != nil || stored.State != agentv1.StateFailed || stored.Error == nil || stored.Error.Code != "upstream_result_unknown" {
		t.Fatalf("operation = %+v, %v; grant error = %v", stored, err, grantErr)
	}
	if grant.UsedCount != 0 || grant.ReservedCount != 1 || !grant.ReservationRetained {
		t.Fatalf("ambiguous approval was not retained: %+v", grant)
	}
}

func TestFreshUnboundOperationWaitsForAuthorization(t *testing.T) {
	upstream := newAbsentRepoUpstream(t, "alice", "dataset", "unbound")
	defer upstream.Close()
	handler := newRecoveryTestServer(t, upstream.URL, emptyPolicyJSON())
	defer func() { _ = handler.Close() }()
	operation, _, err := handler.operations.Submit(agentops.Submit{ID: "op_unbound", Broker: "hf-broker", ClientID: "agent", IdempotencyKey: "unbound",
		Operation: "repo.create", Target: []byte(`{"kind":"repo","type":"dataset","owner":"alice","name":"unbound"}`),
		Arguments: []byte(`{"visibility":"private"}`), Reason: "authorization in progress", Presentation: agentv1.Presentation{Title: "Create repository"}})
	if err != nil {
		t.Fatal(err)
	}
	handler.advanceOperation(t.Context(), operation)
	stored, err := handler.operations.GetByID(operation.ID)
	if err != nil || stored.State != agentv1.StatePending || stored.Error != nil {
		t.Fatalf("fresh operation = %+v, %v", stored, err)
	}
	handler.now = func() time.Time { return operation.UpdatedAt.Add(operationAuthorizationGrace + time.Second) }
	handler.advanceOperation(t.Context(), operation)
	stored, err = handler.operations.GetByID(operation.ID)
	if err != nil || stored.State != agentv1.StateFailed || stored.Error == nil || stored.Error.Code != "approval_missing" {
		t.Fatalf("stale operation = %+v, %v", stored, err)
	}
}

func TestDefinitiveExecutionFailuresSkipReconciliation(t *testing.T) {
	if !definitiveExecutionFailure(errors.New("operation_precondition_failed")) ||
		!definitiveExecutionFailure(&hubclient.Error{Code: hubclient.CodeConflict}) ||
		definitiveExecutionFailure(&hubclient.Error{Code: hubclient.CodeResultUnknown, Ambiguous: true}) ||
		definitiveExecutionFailure(nil) {
		t.Fatal("execution failure classification mismatch")
	}
}

func newRecoveryTestServer(t *testing.T, upstreamURL, scopeJSON string) *Server {
	t.Helper()
	scope, err := policy.Parse([]byte(scopeJSON))
	if err != nil {
		t.Fatal(err)
	}
	handler, _, err := prepareServer(Options{Config: config.Config{
		HFToken: testToken, Clients: []config.Client{{Name: "agent", Secret: testSecret}},
		StateDir: filepath.Join(t.TempDir(), "state"), MaxPackBytes: 25 * 1024 * 1024, HFTimeout: 5 * time.Second,
	}, Scope: scope, Audit: audit.New(io.Discard), UpstreamBaseURL: upstreamURL})
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

func TestOperationSubmissionErrorMapping(t *testing.T) {
	t.Parallel()
	tests := []struct {
		err        error
		wantStatus int
		wantCode   string
	}{
		{err: &hubclient.Error{Code: hubclient.CodeNotFound}, wantStatus: http.StatusNotFound, wantCode: string(hubclient.CodeNotFound)},
		{err: &hubclient.Error{Code: hubclient.CodeUnavailable}, wantStatus: http.StatusBadGateway, wantCode: string(hubclient.CodeUnavailable)},
		{err: errors.New("repository already exists"), wantStatus: http.StatusConflict, wantCode: "operation_precondition_failed"},
		{err: errors.New("invalid input"), wantStatus: http.StatusBadRequest, wantCode: "operation_input_invalid"},
	}
	for _, test := range tests {
		var mapped *agentapi.Error
		if err := mapOperationSubmissionError(test.err); !errors.As(err, &mapped) || mapped.Status != test.wantStatus || mapped.Code != test.wantCode {
			t.Fatalf("mapOperationSubmissionError(%v) = %#v", test.err, err)
		}
	}
	operation := agentv1.Operation{ID: "op-1", Operation: "repo.delete"}
	if got := operationDebugID(operation); got != "repo.delete:op-1" {
		t.Fatalf("operationDebugID() = %q", got)
	}
}

func seedExecutingRepoCreate(t *testing.T, handler *Server, id string) agentv1.Operation {
	t.Helper()
	adapter, found := handler.operationRegistry.Lookup("repo.create")
	if !found {
		t.Fatal("repo.create adapter is unavailable")
	}
	input, err := adapter.Decode([]byte(`{"kind":"repo","type":"dataset","owner":"alice","name":"recovery"}`), []byte(`{"visibility":"private"}`))
	if err != nil {
		t.Fatal(err)
	}
	plan, err := adapter.Resolve(t.Context(), input)
	if err != nil {
		t.Fatal(err)
	}
	plan.Policy.Client = "agent"
	request, err := hfgrant.CanonicalRequest(hfgrant.Input{Client: "agent", ClientRequestID: id, Operation: "repo.create", Mode: hfgrant.ModeExecution,
		Target: operationPolicyTarget(plan.Policy), Attrs: plan.Policy.Attrs, Reason: "recovery test", RequestedDuration: time.Minute,
		PendingTimeout: time.Minute, MaxUses: 1, MaxUsesSpecified: true})
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := prepareAdapterPlan(plan, request, adapter.Present(plan), "request", []string{"request-rule"}, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	operation, _, err := handler.operations.SubmitWithPlan(agentops.Submit{ID: id, Broker: "hf-broker", ClientID: "agent", IdempotencyKey: id,
		Operation: "repo.create", Target: plan.Target, Arguments: plan.Arguments, Reason: "recovery test", Presentation: adapter.Present(plan)}, planRecord(prepared))
	if err != nil {
		t.Fatal(err)
	}
	operation, err = handler.operations.Transition(operation.ID, agentv1.StateApproved)
	if err != nil {
		t.Fatal(err)
	}
	operation, err = handler.operations.Transition(operation.ID, agentv1.StateExecuting)
	if err != nil {
		t.Fatal(err)
	}
	return operation
}

func seedPendingRepoCreateGrant(t *testing.T, handler *Server, id, name string) (agentv1.Operation, grants.RequestResult) {
	t.Helper()
	adapter, found := handler.operationRegistry.Lookup("repo.create")
	if !found {
		t.Fatal("repo.create adapter is unavailable")
	}
	target := []byte(`{"kind":"repo","type":"dataset","owner":"alice","name":"` + name + `"}`)
	input, err := adapter.Decode(target, []byte(`{"visibility":"private"}`))
	if err != nil {
		t.Fatal(err)
	}
	plan, err := adapter.Resolve(t.Context(), input)
	if err != nil {
		t.Fatal(err)
	}
	plan.Policy.Client = "agent"
	request, err := hfgrant.CanonicalRequest(hfgrant.Input{Client: "agent", ClientRequestID: id, Operation: "repo.create", Mode: hfgrant.ModeExecution,
		Target: operationPolicyTarget(plan.Policy), Attrs: plan.Policy.Attrs, Reason: "recovery test", RequestedDuration: time.Minute,
		PendingTimeout: time.Minute, MaxUses: 1, MaxUsesSpecified: true})
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := prepareAdapterPlan(plan, request, adapter.Present(plan), "request", []string{"request-rule"}, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	hfplan.BindPrepared(&request, prepared)
	requested, _, err := handler.grants.RequestWithPlan(request, prepared)
	if err != nil {
		t.Fatal(err)
	}
	operation, _, err := handler.operations.Submit(agentops.Submit{ID: id, Broker: "hf-broker", ClientID: "agent", IdempotencyKey: id,
		Operation: "repo.create", Target: plan.Target, Arguments: plan.Arguments, Reason: "recovery test", Presentation: adapter.Present(plan)})
	if err != nil {
		t.Fatal(err)
	}
	return operation, requested
}
