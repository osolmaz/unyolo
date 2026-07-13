package operationruntime

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/osolmaz/brokerkit/agentops"
	"github.com/osolmaz/brokerkit/agentv1"
	"github.com/osolmaz/brokerkit/authorization"
	"github.com/osolmaz/brokerkit/capability"
	"github.com/osolmaz/brokerkit/grants"
	"github.com/osolmaz/brokerkit/notify"
	"github.com/osolmaz/brokerkit/plandigest"
	"github.com/osolmaz/brokerkit/policy"
	"github.com/osolmaz/brokerkit/state"
)

type runtimeInput struct {
	Target    json.RawMessage
	Arguments json.RawMessage
}

type runtimePlan struct {
	Target        json.RawMessage `json:"target"`
	Arguments     json.RawMessage `json:"arguments"`
	Authorization policy.Request  `json:"authorization"`
}

type runtimeAdapter struct {
	descriptor   capability.Descriptor
	executeErr   error
	reconciled   bool
	resolveCount int
}

func (a *runtimeAdapter) Descriptor() capability.Descriptor { return a.descriptor }
func (a *runtimeAdapter) Decode(target, arguments json.RawMessage) (runtimeInput, error) {
	return runtimeInput{Target: target, Arguments: arguments}, nil
}
func (a *runtimeAdapter) Resolve(_ context.Context, input runtimeInput) (runtimePlan, error) {
	a.resolveCount++
	return runtimePlan{Target: input.Target, Arguments: input.Arguments, Authorization: policy.Request{
		Operation: a.descriptor.Name, Target: policy.Target{Kind: "repo", Fields: map[string][]string{"name": {"demo"}}},
	}}, nil
}
func (a *runtimeAdapter) Authorize(plan runtimePlan) policy.Request { return plan.Authorization }
func (a *runtimeAdapter) Present(runtimePlan) agentv1.Presentation {
	return agentv1.Presentation{Title: "Create demo"}
}
func (a *runtimeAdapter) Execute(context.Context, runtimePlan) (Outcome, error) {
	if a.executeErr != nil {
		return Outcome{}, a.executeErr
	}
	return Outcome{Proven: true, Result: json.RawMessage(`{"created":true}`)}, nil
}
func (a *runtimeAdapter) Reconcile(context.Context, runtimePlan) (Outcome, error) {
	a.reconciled = true
	return Outcome{Proven: true, Result: json.RawMessage(`{"reconciled":true}`)}, nil
}

func TestRuntimeDirectLifecycleAndIdempotentReplay(t *testing.T) {
	runtime, adapter, operations, _, closeRuntime := newRuntime(t, nil, directDecision, nil, false)
	defer closeRuntime()
	request := agentv1.SubmitRequest{IdempotencyKey: "request-1", Operation: "repo.create",
		Target: json.RawMessage(`{"name":"demo"}`), Arguments: json.RawMessage(`{"private":true}`), Reason: "create demo"}
	operation, created, err := runtime.Submit(t.Context(), "agent", request)
	if err != nil || !created || operation.State != agentv1.StateApproved || operation.PlanDigest == "" {
		t.Fatalf("submit = %+v, %v, %v", operation, created, err)
	}
	replayed, created, err := runtime.Submit(t.Context(), "agent", request)
	if err != nil || created || replayed.ID != operation.ID || adapter.resolveCount != 1 {
		t.Fatalf("replay = %+v, %v, %v; resolves=%d", replayed, created, err, adapter.resolveCount)
	}
	runtime.Advance(t.Context(), operation)
	completed, err := operations.Get("agent", operation.ID)
	if err != nil || completed.State != agentv1.StateSucceeded || string(completed.Result) != `{"created":true}` {
		t.Fatalf("completed = %+v, %v", completed, err)
	}
}

func TestRuntimeReconcilesPossiblePartialExecution(t *testing.T) {
	runtime, adapter, operations, _, closeRuntime := newRuntime(t, &PossiblePartialError{Err: errors.New("connection lost")}, directDecision, nil, false)
	defer closeRuntime()
	operation, _, err := runtime.Submit(t.Context(), "agent", agentv1.SubmitRequest{IdempotencyKey: "request-2", Operation: "repo.create",
		Target: json.RawMessage(`{"name":"demo"}`), Arguments: json.RawMessage(`{}`), Reason: "create demo"})
	if err != nil {
		t.Fatal(err)
	}
	runtime.Advance(t.Context(), operation)
	completed, err := operations.Get("agent", operation.ID)
	if err != nil || completed.State != agentv1.StateSucceeded || !adapter.reconciled {
		t.Fatalf("completed = %+v, reconciled=%v, err=%v", completed, adapter.reconciled, err)
	}
}

type captureNotifier struct {
	message notify.ApprovalMessage
	err     error
}

func (n *captureNotifier) SendApproval(_ context.Context, message notify.ApprovalMessage) (notify.MessageRef, error) {
	n.message = message
	if n.err != nil {
		return notify.MessageRef{}, n.err
	}
	return notify.MessageRef{Kind: "test", ChatID: 1, MessageID: 1}, nil
}

func (*captureNotifier) UpdateStatus(context.Context, notify.MessageRef, string) error { return nil }

func TestRuntimePendingApprovalExecuteAndCancel(t *testing.T) {
	notifier := &captureNotifier{}
	runtime, _, operations, grantStore, closeRuntime := newRuntime(t, nil, requestDecision, notifier, true)
	defer closeRuntime()
	request := agentv1.SubmitRequest{IdempotencyKey: "pending-1", Operation: "repo.create",
		Target: json.RawMessage(`{"name":"demo"}`), Arguments: json.RawMessage(`{}`), Reason: "create demo"}
	operation, created, err := runtime.Submit(t.Context(), "agent", request)
	if err != nil || !created || operation.State != agentv1.StatePending || operation.ApprovalID == "" || notifier.message.DecisionToken == "" {
		t.Fatalf("pending submit = %+v, error=%+v, %v, %v; notification=%+v", operation, operation.Error, created, err, notifier.message)
	}
	if _, err := grantStore.Approve(operation.ApprovalID, notifier.message.DecisionToken, "operator"); err != nil {
		t.Fatal(err)
	}
	runtime.AdvanceAll(t.Context())
	completed, err := operations.Get("agent", operation.ID)
	if err != nil || completed.State != agentv1.StateSucceeded {
		t.Fatalf("approved operation = %+v, %v", completed, err)
	}

	request.IdempotencyKey = "pending-2"
	operation, _, err = runtime.Submit(t.Context(), "agent", request)
	if err != nil {
		t.Fatal(err)
	}
	canceled, err := runtime.Cancel(t.Context(), "agent", operation.ID)
	if err != nil || canceled.State != agentv1.StateCanceled {
		t.Fatalf("canceled = %+v, %v", canceled, err)
	}
}

func TestRuntimeHandlesDeniedAndUnnotifiedApprovals(t *testing.T) {
	notifier := &captureNotifier{}
	runtime, _, operations, grantStore, closeRuntime := newRuntime(t, nil, requestDecision, notifier, true)
	request := agentv1.SubmitRequest{IdempotencyKey: "denied", Operation: "repo.create",
		Target: json.RawMessage(`{"name":"demo"}`), Arguments: json.RawMessage(`{}`), Reason: "create demo"}
	operation, _, err := runtime.Submit(t.Context(), "agent", request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := grantStore.Deny(operation.ApprovalID, notifier.message.DecisionToken, "operator"); err != nil {
		t.Fatal(err)
	}
	runtime.Advance(t.Context(), operation)
	denied, err := operations.Get("agent", operation.ID)
	if err != nil || denied.State != agentv1.StateDenied {
		t.Fatalf("denied = %+v, %v", denied, err)
	}
	closeRuntime()

	runtime, _, operations, _, closeRuntime = newRuntime(t, nil, requestDecision, nil, false)
	defer closeRuntime()
	request.IdempotencyKey = "unnotified"
	operation, _, err = runtime.Submit(t.Context(), "agent", request)
	if err != nil {
		t.Fatal(err)
	}
	failed, err := operations.Get("agent", operation.ID)
	if err != nil || failed.State != agentv1.StateFailed || failed.Error.Code != "approval_channel_not_configured" {
		t.Fatalf("unnotified = %+v, %v", failed, err)
	}
}

func TestRuntimeDefinitiveFailureAndRestartReconciliation(t *testing.T) {
	runtime, adapter, operations, _, closeRuntime := newRuntime(t, errors.New("rejected"), directDecision, nil, false)
	defer closeRuntime()
	request := agentv1.SubmitRequest{IdempotencyKey: "failed", Operation: "repo.create",
		Target: json.RawMessage(`{"name":"demo"}`), Arguments: json.RawMessage(`{}`), Reason: "create demo"}
	operation, _, err := runtime.Submit(t.Context(), "agent", request)
	if err != nil {
		t.Fatal(err)
	}
	runtime.Advance(t.Context(), operation)
	failed, _ := operations.Get("agent", operation.ID)
	if failed.State != agentv1.StateFailed {
		t.Fatalf("failed = %+v", failed)
	}

	adapter.executeErr = nil
	request.IdempotencyKey = "restart"
	operation, _, err = runtime.Submit(t.Context(), "agent", request)
	if err != nil {
		t.Fatal(err)
	}
	operation, _ = operations.Transition(operation.ID, agentv1.StateExecuting)
	runtime.ReconcileInterrupted(t.Context(), operation)
	reconciled, _ := operations.Get("agent", operation.ID)
	if reconciled.State != agentv1.StateSucceeded {
		t.Fatalf("reconciled = %+v", reconciled)
	}
}

func TestRuntimeWorkerRecoversApprovedOperation(t *testing.T) {
	runtime, _, operations, _, closeRuntime := newRuntime(t, nil, directDecision, nil, false)
	defer closeRuntime()
	operation, _, err := runtime.Submit(t.Context(), "agent", agentv1.SubmitRequest{IdempotencyKey: "worker", Operation: "repo.create",
		Target: json.RawMessage(`{"name":"demo"}`), Arguments: json.RawMessage(`{}`), Reason: "create demo"})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	runtime.options.WorkerInterval = time.Millisecond
	runtime.Start(ctx)
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		current, getErr := operations.Get("agent", operation.ID)
		if getErr == nil && current.State == agentv1.StateSucceeded {
			cancel()
			runtime.Wait()
			return
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	runtime.Wait()
	t.Fatal("worker did not recover the approved operation")
}

func TestRuntimeRestartCommitsReservedApproval(t *testing.T) {
	notifier := &captureNotifier{}
	runtime, _, operations, grantStore, closeRuntime := newRuntime(t, nil, requestDecision, notifier, true)
	defer closeRuntime()
	operation, _, err := runtime.Submit(t.Context(), "agent", agentv1.SubmitRequest{IdempotencyKey: "reserved", Operation: "repo.create",
		Target: json.RawMessage(`{"name":"demo"}`), Arguments: json.RawMessage(`{}`), Reason: "create demo"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := grantStore.Approve(operation.ApprovalID, notifier.message.DecisionToken, "operator"); err != nil {
		t.Fatal(err)
	}
	operation, err = operations.Transition(operation.ID, agentv1.StateApproved)
	if err != nil {
		t.Fatal(err)
	}
	operation, err = operations.Transition(operation.ID, agentv1.StateExecuting)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := grantStore.ReserveUse(operation.ApprovalID); err != nil {
		t.Fatal(err)
	}
	runtime.ReconcileInterrupted(t.Context(), operation)
	completed, _ := operations.Get("agent", operation.ID)
	grant, _ := grantStore.Get(operation.ApprovalID)
	if completed.State != agentv1.StateSucceeded || grant.UsedCount != 1 {
		t.Fatalf("completed = %+v; grant = %+v", completed, grant)
	}
}

func TestRuntimeRecoversUnboundApprovalAndPlan(t *testing.T) {
	runtime, adapter, operations, grantStore, closeRuntime := newRuntime(t, nil, requestDecision, nil, true)
	defer closeRuntime()
	id, err := operations.NewID()
	if err != nil {
		t.Fatal(err)
	}
	input, err := adapter.Decode(json.RawMessage(`{"name":"demo"}`), json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	plan, err := adapter.Resolve(t.Context(), input)
	if err != nil {
		t.Fatal(err)
	}
	plan.Authorization.Client = "agent"
	core := adapter.Authorize(plan)
	decision := requestDecision(core, policy.DecisionOptions{ForGrantRequest: true})
	intent, err := runtime.options.Prepare(Preparation[runtimePlan, policy.Request]{Plan: plan, Auth: core, Core: core,
		DescriptorName: "repo.create", Client: "agent", OperationID: id, Reason: "recover", Decision: decision, CreatedAt: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	requested, _, err := grantStore.RequestWithPlan(intent.Request, intent.Plan)
	if err != nil {
		t.Fatal(err)
	}
	operation, _, err := operations.Submit(agentops.Submit{ID: id, Broker: "test-broker", ClientID: "agent", IdempotencyKey: "recover",
		Operation: "repo.create", Target: plan.Target, Arguments: plan.Arguments, Reason: "recover", Presentation: adapter.Present(plan)})
	if err != nil {
		t.Fatal(err)
	}
	bound := runtime.RecoverApproval(operation)
	if bound.ApprovalID != requested.Grant.ID || bound.PlanDigest != intent.Plan.Digest {
		t.Fatalf("recovered = %+v", bound)
	}
	canceled, err := runtime.Cancel(t.Context(), "agent", bound.ID)
	if err != nil || canceled.State != agentv1.StateCanceled {
		t.Fatalf("canceled = %+v, %v", canceled, err)
	}
}

func TestRuntimeNotificationFailurePolicies(t *testing.T) {
	for _, operatorConfigured := range []bool{false, true} {
		t.Run(map[bool]string{false: "no operator", true: "operator inbox"}[operatorConfigured], func(t *testing.T) {
			notifier := &captureNotifier{err: errors.New("offline")}
			runtime, _, operations, _, closeRuntime := newRuntime(t, nil, requestDecision, notifier, operatorConfigured)
			defer closeRuntime()
			operation, _, err := runtime.Submit(t.Context(), "agent", agentv1.SubmitRequest{IdempotencyKey: "notify", Operation: "repo.create",
				Target: json.RawMessage(`{"name":"demo"}`), Arguments: json.RawMessage(`{}`), Reason: "create demo"})
			if err != nil {
				t.Fatal(err)
			}
			stored, err := operations.Get("agent", operation.ID)
			if err != nil {
				t.Fatal(err)
			}
			want := agentv1.StateFailed
			if operatorConfigured {
				want = agentv1.StatePending
			}
			if stored.State != want {
				t.Fatalf("stored = %+v, want %s", stored, want)
			}
		})
	}
}

func TestRuntimeRejectsUnknownAndInvalidSubmissions(t *testing.T) {
	runtime, _, _, _, closeRuntime := newRuntime(t, nil, directDecision, nil, false)
	defer closeRuntime()
	if _, _, err := runtime.Submit(t.Context(), "agent", agentv1.SubmitRequest{IdempotencyKey: "unknown", Operation: "repo.delete",
		Target: json.RawMessage(`{}`), Arguments: json.RawMessage(`{}`), Reason: "unknown"}); err == nil {
		t.Fatal("unknown operation was accepted")
	}
	if _, err := New(Options[runtimeInput, runtimePlan, policy.Request]{}); err == nil {
		t.Fatal("incomplete runtime was accepted")
	}
}

func directDecision(policy.Request, policy.DecisionOptions) policy.Decision {
	return policy.Decision{Effect: policy.EffectAllow, Allowed: true, MatchedAllowRuleIDs: []string{"allow"}}
}

func requestDecision(policy.Request, policy.DecisionOptions) policy.Decision {
	return policy.Decision{Effect: policy.EffectRequest, GrantPolicy: &policy.GrantPolicy{
		Mode: string(policy.GrantModeExecution), DefaultMinutes: 1, MaxMinutes: 2, RequestTTLMinutes: 1,
		DefaultMaxUses: 1, MaxUses: 1,
	}}
}

func newRuntime(t *testing.T, executeErr error, decide func(policy.Request, policy.DecisionOptions) policy.Decision,
	notifier notify.Notifier, operatorConfigured bool) (*Runtime[runtimeInput, runtimePlan, policy.Request], *runtimeAdapter, *agentops.Store, *grants.Store, func()) {
	t.Helper()
	database, err := state.Open(context.Background(), t.TempDir(), state.Options{})
	if err != nil {
		t.Fatal(err)
	}
	descriptor := capability.Descriptor{Name: "repo.create", OperationRevision: 1, AuthorizationMode: capability.ModeExecution}
	adapter := &runtimeAdapter{descriptor: descriptor, executeErr: executeErr}
	registry, err := NewRegistry(RegistryOptions{Provider: "test", Descriptor: func(name string) (capability.Descriptor, bool) {
		return descriptor, name == descriptor.Name
	}}, adapter)
	if err != nil {
		t.Fatal(err)
	}
	grantStore := grants.NewDatabase(database, grants.Options{PendingTimeout: time.Minute, DefaultDuration: time.Minute,
		MaxDuration: time.Hour, ReservationTimeout: time.Minute})
	policyRegistry := policy.Registry{
		Operations: map[string]policy.OperationSpec{"repo.create": {TargetKinds: []string{"repo"}, Grantable: true, GrantMode: policy.GrantModeExecution}},
		Targets:    map[string]policy.TargetSpec{"repo": {Fields: map[string]policy.FieldSpec{"name": {Required: true}}}},
	}
	coordinator, err := authorization.New(authorization.Options{Registry: policyRegistry, Decide: decide, Grants: grantStore})
	if err != nil {
		t.Fatal(err)
	}
	operationStore := agentops.New(database)
	runtime, err := New(Options[runtimeInput, runtimePlan, policy.Request]{
		Broker: "test-broker", Operations: operationStore, Registry: registry, Authorization: coordinator, Grants: grantStore,
		Decide: decide, Project: func(request policy.Request) policy.Request { return request },
		SetClient: func(plan *runtimePlan, client string) { plan.Authorization.Client = client },
		InputData: func(input runtimeInput) (json.RawMessage, json.RawMessage) { return input.Target, input.Arguments },
		PlanData:  func(plan runtimePlan) (json.RawMessage, json.RawMessage) { return plan.Target, plan.Arguments },
		Prepare: func(preparation Preparation[runtimePlan, policy.Request]) (authorization.GrantIntent, error) {
			canonical, encodeErr := json.Marshal(struct {
				OperationID string      `json:"operation_id"`
				Plan        runtimePlan `json:"plan"`
			}{OperationID: preparation.OperationID, Plan: preparation.Plan})
			plan := grants.ImmutablePlan{Digest: plandigest.Digest(canonical), SchemaName: "test.io/plan/v1", Canonical: canonical, CreatedAt: preparation.CreatedAt}
			request := grants.Request{Client: preparation.Client, ClientRequestID: preparation.OperationID, Operation: preparation.DescriptorName,
				Target: preparation.Core.Target, Attrs: preparation.Core.Attrs, Metadata: map[string]string{"test_plan_digest": plan.Digest}, Reason: preparation.Reason,
				Duration: time.Minute, PendingTimeout: time.Minute, MaxUses: 1, MaxUsesSpecified: true}
			return authorization.GrantIntent{Mode: policy.GrantModeExecution, Authorization: preparation.Core, Request: request, Plan: plan}, encodeErr
		},
		Load: func(operation agentv1.Operation, _ Adapter[runtimeInput, runtimePlan, policy.Request]) (runtimePlan, error) {
			record, loadErr := database.Plan(context.Background(), operation.PlanDigest)
			var envelope struct {
				Plan runtimePlan `json:"plan"`
			}
			if loadErr == nil {
				loadErr = json.Unmarshal(record.Canonical, &envelope)
			}
			return envelope.Plan, loadErr
		},
		PlanDigest:        func(grant grants.Grant) string { return grant.Metadata["test_plan_digest"] },
		StoredPlan:        func(digest string) (state.PlanRecord, error) { return database.Plan(context.Background(), digest) },
		ValidateExecution: func(grants.Grant) error { return nil },
		Notifier:          notifier, ApprovalMessage: func(grant grants.Grant, token string) notify.ApprovalMessage {
			return notify.ApprovalMessage{GrantID: grant.ID, DecisionToken: token, Operation: grant.Operation}
		}, OperatorConfigured: operatorConfigured,
	})
	if err != nil {
		_ = database.Close()
		t.Fatal(err)
	}
	return runtime, adapter, operationStore, grantStore, func() { _ = database.Close() }
}
