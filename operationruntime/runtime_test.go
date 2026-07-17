package operationruntime

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/osolmaz/brokerkit/admission"
	"github.com/osolmaz/brokerkit/agentapi"
	"github.com/osolmaz/brokerkit/agentops"
	"github.com/osolmaz/brokerkit/agentv1"
	"github.com/osolmaz/brokerkit/approvalnotify"
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

type runtimeObserver struct {
	submissions   []string
	executions    []string
	notifications []string
}

type runtimeDiagnostics struct {
	limit         int
	started       int
	finished      []string
	notifications []string
	retries       int
}

func (d *runtimeDiagnostics) WorkerConfigured(limit int)          { d.limit = limit }
func (d *runtimeDiagnostics) OperationStarted(_, _ string, _ int) { d.started++ }
func (d *runtimeDiagnostics) OperationFinished(_, _, result, code string, _ time.Duration) {
	d.finished = append(d.finished, result+":"+code)
}
func (d *runtimeDiagnostics) NotificationAttempt(_, result, code string) {
	d.notifications = append(d.notifications, result+":"+code)
}
func (d *runtimeDiagnostics) Retry(_, _ string) { d.retries++ }

func (o *runtimeObserver) OperationSubmitted(result string) {
	o.submissions = append(o.submissions, result)
}
func (o *runtimeObserver) OperationExecuted(result string, _ time.Duration) {
	o.executions = append(o.executions, result)
}
func (o *runtimeObserver) NotificationDelivered(result string) {
	o.notifications = append(o.notifications, result)
}

type runtimeAdapter struct {
	descriptor        capability.Descriptor
	executeErr        error
	reconciled        bool
	reconcileUnproven bool
	reconcileErr      error
	resolveCount      int
	cleanupCount      atomic.Int32
	recordedStatus    atomic.Int32
	clientErr         error
	resolveErr        error
	executeStarted    chan<- struct{}
	executeRelease    <-chan struct{}
	executeActive     atomic.Int32
	maxExecuteActive  atomic.Int32
	requiresApproval  bool
	boundGrant        grants.Grant
}

func (a *runtimeAdapter) Descriptor() capability.Descriptor { return a.descriptor }
func (a *runtimeAdapter) Decode(target, arguments json.RawMessage) (runtimeInput, error) {
	return runtimeInput{Target: target, Arguments: arguments}, nil
}
func (a *runtimeAdapter) Resolve(_ context.Context, input runtimeInput) (runtimePlan, error) {
	a.resolveCount++
	if a.resolveErr != nil {
		return runtimePlan{}, a.resolveErr
	}
	return runtimePlan{Target: input.Target, Arguments: input.Arguments, Authorization: policy.Request{
		Operation: a.descriptor.Name, Target: policy.Target{Kind: "repo", Fields: map[string][]string{"name": {"demo"}}},
	}}, nil
}
func (a *runtimeAdapter) ValidateClient(runtimeInput, string, string) error { return a.clientErr }
func (a *runtimeAdapter) Authorize(plan runtimePlan) policy.Request         { return plan.Authorization }
func (a *runtimeAdapter) RequiresApproval() bool                            { return a.requiresApproval }
func (a *runtimeAdapter) BindReservation(plan runtimePlan, grant grants.Grant) (runtimePlan, error) {
	a.boundGrant = grant
	return plan, nil
}
func (a *runtimeAdapter) Present(runtimePlan) agentv1.Presentation {
	return agentv1.Presentation{Title: "Create demo"}
}
func (a *runtimeAdapter) Execute(context.Context, runtimePlan) (Outcome, error) {
	if a.executeStarted != nil {
		active := a.executeActive.Add(1)
		defer a.executeActive.Add(-1)
		for maximum := a.maxExecuteActive.Load(); active > maximum && !a.maxExecuteActive.CompareAndSwap(maximum, active); maximum = a.maxExecuteActive.Load() {
		}
		a.executeStarted <- struct{}{}
		<-a.executeRelease
	}
	if a.executeErr != nil {
		return Outcome{}, a.executeErr
	}
	return Outcome{Proven: true, Result: json.RawMessage(`{"created":true}`), UpstreamStatus: 201}, nil
}
func (a *runtimeAdapter) Reconcile(context.Context, runtimePlan) (Outcome, error) {
	a.reconciled = true
	if a.reconcileErr != nil {
		return Outcome{}, a.reconcileErr
	}
	if a.reconcileUnproven {
		return Outcome{Proven: false}, nil
	}
	return Outcome{Proven: true, Result: json.RawMessage(`{"reconciled":true}`), UpstreamStatus: 204}, nil
}
func (a *runtimeAdapter) Cleanup(runtimePlan) error {
	a.cleanupCount.Add(1)
	return nil
}

func TestRuntimeDirectLifecycleAndIdempotentReplay(t *testing.T) {
	runtime, adapter, operations, _, closeRuntime := newRuntime(t, nil, directDecision, nil, false)
	defer closeRuntime()
	observer := &runtimeObserver{}
	runtime.options.Observer = observer
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
	if err != nil || completed.State != agentv1.StateSucceeded || string(completed.Result) != `{"created":true}` || adapter.cleanupCount.Load() != 1 || adapter.recordedStatus.Load() != 201 {
		t.Fatalf("completed = %+v cleanup=%d status=%d err=%v", completed, adapter.cleanupCount.Load(), adapter.recordedStatus.Load(), err)
	}
	if !slices.Equal(observer.submissions, []string{"created", "replayed"}) || !slices.Equal(observer.executions, []string{"succeeded"}) {
		t.Fatalf("runtime observations = %+v", observer)
	}
}

func TestRuntimeAdmissionDoesNotChargeIdempotentReplay(t *testing.T) {
	runtime, _, operations, _, closeRuntime := newRuntime(t, nil, directDecision, nil, false)
	defer closeRuntime()
	limits := admission.DefaultLimits()
	limits.RequestsPerWindow = 1
	controller, err := admission.New([]string{"agent"}, limits, operations.AdmissionUsage)
	if err != nil {
		t.Fatal(err)
	}
	runtime.options.Admission = controller
	request := agentv1.SubmitRequest{IdempotencyKey: "admitted-1", Operation: "repo.create",
		Target: json.RawMessage(`{"name":"demo"}`), Arguments: json.RawMessage(`{}`), Reason: "create demo"}
	first, created, err := runtime.Submit(t.Context(), "agent", request)
	if err != nil || !created {
		t.Fatalf("first submit = %+v, %v, %v", first, created, err)
	}
	replay, created, err := runtime.Submit(t.Context(), "agent", request)
	if err != nil || created || replay.ID != first.ID {
		t.Fatalf("replay = %+v, %v, %v", replay, created, err)
	}
	request.IdempotencyKey = "admitted-2"
	_, _, err = runtime.Submit(t.Context(), "agent", request)
	var apiErr *agentapi.Error
	if !errors.As(err, &apiErr) || apiErr.Status != 429 || apiErr.Code != "submission_rate_limited" || apiErr.RetryAfterSeconds < 1 {
		t.Fatalf("limited submit = %#v", err)
	}
}

func TestRuntimeOverloadLeavesCancellationAndApprovalAvailable(t *testing.T) {
	notifier := &captureNotifier{}
	runtime, _, operations, grantStore, closeRuntime := newRuntime(t, nil, requestDecision, notifier, true)
	defer closeRuntime()
	limits := admission.Limits{RequestsPerWindow: 10, Window: time.Minute, ClientActive: 1, ClientPending: 1, GlobalActive: 1, GlobalExecuting: 1}
	controller, err := admission.New([]string{"agent"}, limits, operations.AdmissionUsage)
	if err != nil {
		t.Fatal(err)
	}
	runtime.options.Admission = controller
	request := agentv1.SubmitRequest{IdempotencyKey: "overload-one", Operation: "repo.create",
		Target: json.RawMessage(`{"name":"demo"}`), Arguments: json.RawMessage(`{}`), Reason: "exercise recovery capacity"}
	first, _, err := runtime.Submit(t.Context(), "agent", request)
	if err != nil || first.State != agentv1.StatePending {
		t.Fatalf("first submission = %+v, %v", first, err)
	}
	request.IdempotencyKey = "overload-refused"
	if _, _, err := runtime.Submit(t.Context(), "agent", request); admissionAPIErrorCode(err) != "client_operation_limit" {
		t.Fatalf("saturated submission = %v", err)
	}
	canceled, err := runtime.Cancel(t.Context(), "agent", first.ID)
	if err != nil || canceled.State != agentv1.StateCanceled {
		t.Fatalf("overload cancellation = %+v, %v", canceled, err)
	}
	request.IdempotencyKey = "overload-approved"
	second, _, err := runtime.Submit(t.Context(), "agent", request)
	if err != nil || second.State != agentv1.StatePending {
		t.Fatalf("post-cancel submission = %+v, %v", second, err)
	}
	if _, err := grantStore.Approve(second.ApprovalID, notifier.message.DecisionToken, "operator"); err != nil {
		t.Fatalf("operator approval at capacity: %v", err)
	}
	runtime.Advance(t.Context(), second)
	completed, err := operations.Get("agent", second.ID)
	if err != nil || completed.State != agentv1.StateSucceeded {
		t.Fatalf("approved operation = %+v, %v", completed, err)
	}
}

func admissionAPIErrorCode(err error) string {
	var apiErr *agentapi.Error
	if errors.As(err, &apiErr) {
		return apiErr.Code
	}
	return ""
}

func TestRuntimeReconcilesPossiblePartialExecution(t *testing.T) {
	runtime, adapter, operations, _, closeRuntime := newRuntime(t, &PossiblePartialError{Err: errors.New("connection lost")}, directDecision, nil, false)
	defer closeRuntime()
	diagnostics := &runtimeDiagnostics{}
	runtime.options.Diagnostics = diagnostics
	operation, _, err := runtime.Submit(t.Context(), "agent", agentv1.SubmitRequest{IdempotencyKey: "request-2", Operation: "repo.create",
		Target: json.RawMessage(`{"name":"demo"}`), Arguments: json.RawMessage(`{}`), Reason: "create demo"})
	if err != nil {
		t.Fatal(err)
	}
	runtime.Advance(t.Context(), operation)
	completed, err := operations.Get("agent", operation.ID)
	if err != nil || completed.State != agentv1.StateSucceeded || !adapter.reconciled || adapter.cleanupCount.Load() != 1 || adapter.recordedStatus.Load() != 204 {
		t.Fatalf("completed = %+v, reconciled=%v cleanup=%d status=%d err=%v", completed, adapter.reconciled, adapter.cleanupCount.Load(), adapter.recordedStatus.Load(), err)
	}
	if diagnostics.started != 1 || !slices.Equal(diagnostics.finished, []string{"reconciled:"}) {
		t.Fatalf("diagnostics = %+v", diagnostics)
	}
}

type captureNotifier struct {
	message approvalnotify.Approval
	err     error
}

func (n *captureNotifier) SendApproval(_ context.Context, message approvalnotify.Approval) (notify.MessageRef, error) {
	n.message = message
	if n.err != nil {
		return notify.MessageRef{}, n.err
	}
	return notify.MessageRef{Kind: "test", ChatID: 1, MessageID: 1}, nil
}

func (*captureNotifier) UpdateStatus(context.Context, notify.MessageRef, notify.Status) error {
	return nil
}

func TestRuntimePendingApprovalExecuteAndCancel(t *testing.T) {
	notifier := &captureNotifier{}
	runtime, adapter, operations, grantStore, closeRuntime := newRuntime(t, nil, requestDecision, notifier, true)
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
	if adapter.boundGrant.ID != operation.ApprovalID || adapter.boundGrant.ReservationRevision < 1 {
		t.Fatalf("reserved grant was not bound before execution: %+v", adapter.boundGrant)
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

func TestRuntimeReleasesApprovalWhenExecutionDidNotStart(t *testing.T) {
	notifier := &captureNotifier{}
	runtime, _, operations, grantStore, closeRuntime := newRuntime(t, errors.New("not dispatched"), requestDecision, notifier, true)
	defer closeRuntime()
	runtime.options.ExecutionFailure = func(error, error) Failure {
		return Failure{Code: "provider_unavailable", Message: "Provider was unavailable", ReleaseApproval: true}
	}
	operation, _, err := runtime.Submit(t.Context(), "agent", agentv1.SubmitRequest{IdempotencyKey: "release-approval",
		Operation: "repo.create", Target: json.RawMessage(`{"name":"demo"}`), Arguments: json.RawMessage(`{}`), Reason: "create demo"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := grantStore.Approve(operation.ApprovalID, notifier.message.DecisionToken, "operator"); err != nil {
		t.Fatal(err)
	}
	runtime.AdvanceAll(t.Context())
	stored, _ := operations.Get("agent", operation.ID)
	grant, _ := grantStore.Get(operation.ApprovalID)
	if stored.State != agentv1.StateFailed || stored.Error == nil || stored.Error.Code != "provider_unavailable" ||
		grant.UsedCount != 0 || grant.ReservedCount != 0 || grant.ReservationRetained {
		t.Fatalf("operation = %+v, grant = %+v", stored, grant)
	}
}

func TestRuntimeApprovalRequiredAdapterIgnoresDirectAllow(t *testing.T) {
	notifier := &captureNotifier{}
	runtime, adapter, _, _, closeRuntime := newRuntime(t, nil, allowThenRequestDecision, notifier, true)
	defer closeRuntime()
	adapter.requiresApproval = true
	operation, _, err := runtime.Submit(t.Context(), "agent", agentv1.SubmitRequest{IdempotencyKey: "approval-required",
		Operation: "repo.create", Target: json.RawMessage(`{"name":"demo"}`), Arguments: json.RawMessage(`{}`), Reason: "create demo"})
	if err != nil || operation.State != agentv1.StatePending || operation.ApprovalID == "" || notifier.message.GrantID != operation.ApprovalID {
		t.Fatalf("approval-required submit = %+v, %v; notification=%+v", operation, err, notifier.message)
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

func TestRuntimeAdvancesOperationsWithBoundedConcurrency(t *testing.T) {
	runtime, adapter, operations, _, closeRuntime := newRuntime(t, nil, directDecision, nil, false)
	defer closeRuntime()
	runtime.options.WorkerConcurrency = 2
	started := make(chan struct{}, 3)
	release := make(chan struct{})
	released := false
	defer func() {
		if !released {
			close(release)
		}
	}()
	adapter.executeStarted = started
	adapter.executeRelease = release
	for index := 0; index < 3; index++ {
		_, _, err := runtime.Submit(t.Context(), "agent", agentv1.SubmitRequest{IdempotencyKey: "parallel-" + string(rune('a'+index)), Operation: "repo.create",
			Target: json.RawMessage(`{"name":"demo"}`), Arguments: json.RawMessage(`{}`), Reason: "create demo"})
		if err != nil {
			t.Fatal(err)
		}
	}
	done := make(chan struct{})
	go func() {
		runtime.AdvanceAll(t.Context())
		close(done)
	}()
	for range 2 {
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatal("operations did not start concurrently")
		}
	}
	select {
	case <-started:
		t.Fatal("worker concurrency bound was exceeded")
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	released = true
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("concurrent batch did not finish")
	}
	if adapter.maxExecuteActive.Load() != 2 {
		t.Fatalf("maximum concurrent executions = %d", adapter.maxExecuteActive.Load())
	}
	values, err := operations.ListUnfinished()
	if err != nil || len(values) != 0 {
		t.Fatalf("unfinished operations = %+v, %v", values, err)
	}
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
	notifier := &captureNotifier{}
	runtime, adapter, operations, grantStore, closeRuntime := newRuntime(t, nil, requestDecision, notifier, true)
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
	runtime.Advance(t.Context(), bound)
	storedGrant, err := grantStore.Get(bound.ApprovalID)
	if err != nil || notifier.message.DecisionToken == "" || storedGrant.Notification == nil {
		t.Fatalf("recovered notification = %+v, grant = %+v, %v", notifier.message, storedGrant, err)
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
			diagnostics := &runtimeDiagnostics{}
			runtime.options.Diagnostics = diagnostics
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
			if !slices.Equal(diagnostics.notifications, []string{"failed:notification_unavailable"}) {
				t.Fatalf("notification diagnostics = %+v", diagnostics)
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

func TestRuntimePolicyRefusalsAreTerminalAndCleaned(t *testing.T) {
	for name, decide := range map[string]func(policy.Request, policy.DecisionOptions) policy.Decision{
		"denied": func(policy.Request, policy.DecisionOptions) policy.Decision {
			return policy.Decision{Effect: policy.EffectDeny}
		},
		"no match": func(policy.Request, policy.DecisionOptions) policy.Decision {
			return policy.Decision{Effect: policy.EffectNoMatch}
		},
	} {
		t.Run(name, func(t *testing.T) {
			runtime, adapter, operations, _, closeRuntime := newRuntime(t, nil, decide, nil, false)
			defer closeRuntime()
			operation, created, err := runtime.Submit(t.Context(), "agent", agentv1.SubmitRequest{IdempotencyKey: strings.ReplaceAll(name, " ", "-"),
				Operation: "repo.create", Target: json.RawMessage(`{"name":"demo"}`), Arguments: json.RawMessage(`{}`), Reason: "create demo"})
			if err != nil || !created {
				t.Fatalf("submit = %+v, %t, %v", operation, created, err)
			}
			stored, err := operations.Get("agent", operation.ID)
			if err != nil || stored.State != agentv1.StateDenied || stored.Error.Code != "operation_policy_denied" || adapter.cleanupCount.Load() == 0 {
				t.Fatalf("stored = %+v cleanup=%d err=%v", stored, adapter.cleanupCount.Load(), err)
			}
		})
	}
}

type emptyRefNotifier struct{}

func (emptyRefNotifier) SendApproval(context.Context, approvalnotify.Approval) (notify.MessageRef, error) {
	return notify.MessageRef{}, nil
}
func (emptyRefNotifier) UpdateStatus(context.Context, notify.MessageRef, notify.Status) error {
	return nil
}

func TestRuntimeRejectsApprovalWithoutNotificationReference(t *testing.T) {
	runtime, adapter, operations, _, closeRuntime := newRuntime(t, nil, requestDecision, emptyRefNotifier{}, false)
	defer closeRuntime()
	operation, _, err := runtime.Submit(t.Context(), "agent", agentv1.SubmitRequest{IdempotencyKey: "empty-ref", Operation: "repo.create",
		Target: json.RawMessage(`{"name":"demo"}`), Arguments: json.RawMessage(`{}`), Reason: "create demo"})
	if err != nil {
		t.Fatal(err)
	}
	stored, err := operations.Get("agent", operation.ID)
	if err != nil || stored.State != agentv1.StateFailed || stored.Error.Code != "approval_notification_failed" || adapter.cleanupCount.Load() == 0 {
		t.Fatalf("stored = %+v cleanup=%d err=%v", stored, adapter.cleanupCount.Load(), err)
	}
}

func TestRuntimeCancelsPendingAndRevokesActiveGrants(t *testing.T) {
	notifier := &captureNotifier{}
	runtime, _, _, grantStore, closeRuntime := newRuntime(t, nil, requestDecision, notifier, true)
	defer closeRuntime()
	submit := func(key string) agentv1.Operation {
		t.Helper()
		operation, _, err := runtime.Submit(t.Context(), "agent", agentv1.SubmitRequest{IdempotencyKey: key, Operation: "repo.create",
			Target: json.RawMessage(`{"name":"demo"}`), Arguments: json.RawMessage(`{}`), Reason: "create demo"})
		if err != nil {
			t.Fatal(err)
		}
		return operation
	}
	pending := submit("cancel-pending")
	grant, err := grantStore.Get(pending.ApprovalID)
	if err != nil || runtime.CancelGrant(grant, "agent") != nil {
		t.Fatalf("cancel pending grant = %+v, %v", grant, err)
	}
	grant, _ = grantStore.Get(grant.ID)
	if grant.Status != grants.StatusCanceled {
		t.Fatalf("pending grant status = %s", grant.Status)
	}

	active := submit("revoke-active")
	if _, err := grantStore.Approve(active.ApprovalID, notifier.message.DecisionToken, "operator"); err != nil {
		t.Fatal(err)
	}
	grant, _ = grantStore.Get(active.ApprovalID)
	if err := runtime.CancelGrant(grant, "agent"); err != nil {
		t.Fatal(err)
	}
	grant, _ = grantStore.Get(grant.ID)
	if grant.Status != grants.StatusRevoked {
		t.Fatalf("active grant status = %s", grant.Status)
	}
	if err := runtime.CancelGrant(grant, "agent"); err != nil {
		t.Fatalf("terminal grant cancellation = %v", err)
	}
}

func TestRuntimeExplicitOutcomeSettlement(t *testing.T) {
	runtime, adapter, operations, _, closeRuntime := newRuntime(t, nil, directDecision, nil, false)
	defer closeRuntime()
	submitExecuting := func(key string) agentv1.Operation {
		t.Helper()
		operation, _, err := runtime.Submit(t.Context(), "agent", agentv1.SubmitRequest{IdempotencyKey: key, Operation: "repo.create",
			Target: json.RawMessage(`{"name":"demo"}`), Arguments: json.RawMessage(`{}`), Reason: "create demo"})
		if err != nil {
			t.Fatal(err)
		}
		operation, err = operations.Transition(operation.ID, agentv1.StateExecuting)
		if err != nil {
			t.Fatal(err)
		}
		return operation
	}
	succeeded := submitExecuting("explicit-success")
	runtime.Succeed(succeeded, runtimePlan{}, nil, false, "test")
	stored, _ := operations.Get("agent", succeeded.ID)
	if stored.State != agentv1.StateSucceeded || string(stored.Result) != `{"operation":"repo.create","reconciled":true}` {
		t.Fatalf("succeeded = %+v", stored)
	}

	failed := submitExecuting("explicit-failure")
	runtime.FailExecution(failed, runtimePlan{}, errors.New("upstream"), errors.New("unknown"))
	stored, _ = operations.Get("agent", failed.ID)
	if stored.State != agentv1.StateFailed || stored.Error.Code == "" || adapter.cleanupCount.Load() == 0 {
		t.Fatalf("failed = %+v cleanup=%d", stored, adapter.cleanupCount.Load())
	}
}

func TestRuntimeMissingApprovalFailsAfterRecoveryGrace(t *testing.T) {
	runtime, _, operations, _, closeRuntime := newRuntime(t, nil, requestDecision, nil, true)
	defer closeRuntime()
	id, err := operations.NewID()
	if err != nil {
		t.Fatal(err)
	}
	operation, _, err := operations.Submit(agentops.Submit{ID: id, Broker: "test-broker", ClientID: "agent", IdempotencyKey: "missing-approval",
		Operation: "repo.create", Target: json.RawMessage(`{"name":"demo"}`), Arguments: json.RawMessage(`{}`), Reason: "create demo",
		Presentation: agentv1.Presentation{Title: "Create demo"}})
	if err != nil {
		t.Fatal(err)
	}
	runtime.options.Now = func() time.Time { return operation.UpdatedAt.Add(time.Minute) }
	recovered := runtime.RecoverApproval(operation)
	if recovered.State != agentv1.StateFailed || recovered.Error.Code != "approval_missing" {
		t.Fatalf("recovered = %+v", recovered)
	}
	if _, _, err := runtime.Load(agentv1.Operation{Operation: "repo.create"}); err == nil {
		t.Fatal("operation without plan digest loaded")
	}
}

func TestRuntimeSynchronizesCanceledApprovalAndRejectsExecutingCancel(t *testing.T) {
	notifier := &captureNotifier{}
	runtime, _, operations, grantStore, closeRuntime := newRuntime(t, nil, requestDecision, notifier, true)
	defer closeRuntime()
	operation, _, err := runtime.Submit(t.Context(), "agent", agentv1.SubmitRequest{IdempotencyKey: "cancel-sync", Operation: "repo.create",
		Target: json.RawMessage(`{"name":"demo"}`), Arguments: json.RawMessage(`{}`), Reason: "create demo"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := grantStore.CancelForClient(operation.ApprovalID, "agent"); err != nil {
		t.Fatal(err)
	}
	runtime.Advance(t.Context(), operation)
	stored, _ := operations.Get("agent", operation.ID)
	if stored.State != agentv1.StateCanceled {
		t.Fatalf("canceled approval operation = %+v", stored)
	}
	if terminal, err := runtime.Cancel(t.Context(), "agent", stored.ID); err != nil || terminal.State != agentv1.StateCanceled {
		t.Fatalf("terminal cancel = %+v, %v", terminal, err)
	}

	directRuntime, _, directOperations, _, closeDirect := newRuntime(t, nil, directDecision, nil, false)
	defer closeDirect()
	executing, _, err := directRuntime.Submit(t.Context(), "agent", agentv1.SubmitRequest{IdempotencyKey: "executing", Operation: "repo.create",
		Target: json.RawMessage(`{"name":"demo"}`), Arguments: json.RawMessage(`{}`), Reason: "create demo"})
	if err != nil {
		t.Fatal(err)
	}
	executing, err = directOperations.Transition(executing.ID, agentv1.StateExecuting)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := directRuntime.Cancel(t.Context(), "agent", executing.ID); !errors.Is(err, agentops.ErrNotCancelable) {
		t.Fatalf("executing cancel = %v", err)
	}
}

func TestRuntimeAmbiguousApprovedExecutionRetainsUse(t *testing.T) {
	notifier := &captureNotifier{}
	runtime, adapter, operations, grantStore, closeRuntime := newRuntime(t, &PossiblePartialError{Err: errors.New("connection lost")}, requestDecision, notifier, true)
	defer closeRuntime()
	adapter.reconcileUnproven = true
	operation, _, err := runtime.Submit(t.Context(), "agent", agentv1.SubmitRequest{IdempotencyKey: "ambiguous", Operation: "repo.create",
		Target: json.RawMessage(`{"name":"demo"}`), Arguments: json.RawMessage(`{}`), Reason: "create demo"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := grantStore.Approve(operation.ApprovalID, notifier.message.DecisionToken, "operator"); err != nil {
		t.Fatal(err)
	}
	runtime.Advance(t.Context(), operation)
	stored, _ := operations.Get("agent", operation.ID)
	grant, _ := grantStore.Get(operation.ApprovalID)
	if stored.State != agentv1.StateFailed || grant.ReservedCount != 1 || !grant.ReservationRetained || grant.UsedCount != 0 {
		t.Fatalf("ambiguous operation = %+v grant=%+v", stored, grant)
	}
}

func TestRuntimeRestartFailsWhenOutcomeCannotBeProven(t *testing.T) {
	runtime, adapter, operations, _, closeRuntime := newRuntime(t, nil, directDecision, nil, false)
	defer closeRuntime()
	adapter.reconcileUnproven = true
	operation, _, err := runtime.Submit(t.Context(), "agent", agentv1.SubmitRequest{IdempotencyKey: "restart-unknown", Operation: "repo.create",
		Target: json.RawMessage(`{"name":"demo"}`), Arguments: json.RawMessage(`{}`), Reason: "create demo"})
	if err != nil {
		t.Fatal(err)
	}
	operation, err = operations.Transition(operation.ID, agentv1.StateExecuting)
	if err != nil {
		t.Fatal(err)
	}
	runtime.ReconcileInterrupted(t.Context(), operation)
	stored, _ := operations.Get("agent", operation.ID)
	if stored.State != agentv1.StateFailed || stored.Error.Code != "upstream_result_unknown" {
		t.Fatalf("restart outcome = %+v", stored)
	}
	adapter.reconcileUnproven = false
	adapter.reconcileErr = errors.New("offline")
	if _, err := adapter.Reconcile(t.Context(), runtimePlan{}); err == nil {
		t.Fatal("reconciliation error disappeared")
	}
}

func TestRuntimeSubmissionBoundaryFailures(t *testing.T) {
	runtime, adapter, _, _, closeRuntime := newRuntime(t, nil, directDecision, nil, false)
	defer closeRuntime()
	request := agentv1.SubmitRequest{IdempotencyKey: "boundary", Operation: "repo.create", Target: json.RawMessage(`{"name":"demo"}`),
		Arguments: json.RawMessage(`{}`), Reason: "create demo"}
	adapter.clientErr = errors.New("reference owner mismatch")
	if _, _, err := runtime.Submit(t.Context(), "agent", request); err == nil {
		t.Fatal("client-bound validation failure accepted")
	}
	adapter.clientErr = nil
	adapter.resolveErr = errors.New("resolution failed")
	if _, _, err := runtime.Submit(t.Context(), "agent", request); err == nil {
		t.Fatal("resolution failure accepted")
	}
	adapter.resolveErr = nil
	operation, _, err := runtime.Submit(t.Context(), "agent", request)
	if err != nil {
		t.Fatal(err)
	}
	request.Arguments = json.RawMessage(`{"changed":true}`)
	if _, _, err := runtime.Submit(t.Context(), "agent", request); !errors.Is(err, agentops.ErrIdempotencyConflict) {
		t.Fatalf("idempotency conflict = %v", err)
	}
	if loaded, err := runtime.options.Operations.GetByID(operation.ID); err != nil || loaded.ID != operation.ID {
		t.Fatalf("stored boundary operation = %+v, %v", loaded, err)
	}
}

func TestRuntimePlanPreparationFailuresCleanResolvedState(t *testing.T) {
	for name, decide := range map[string]func(policy.Request, policy.DecisionOptions) policy.Decision{
		"direct":   directDecision,
		"approval": requestDecision,
	} {
		t.Run(name, func(t *testing.T) {
			runtime, adapter, operations, _, closeRuntime := newRuntime(t, nil, decide, nil, true)
			defer closeRuntime()
			runtime.options.Prepare = func(Preparation[runtimePlan, policy.Request]) (authorization.GrantIntent, error) {
				return authorization.GrantIntent{}, errors.New("prepare failed")
			}
			operation, _, err := runtime.Submit(t.Context(), "agent", agentv1.SubmitRequest{IdempotencyKey: "prepare-" + name,
				Operation: "repo.create", Target: json.RawMessage(`{"name":"demo"}`), Arguments: json.RawMessage(`{}`), Reason: "create demo"})
			if name == "direct" {
				if err == nil || operation.ID != "" {
					t.Fatalf("direct preparation = %+v, %v", operation, err)
				}
			} else {
				if err != nil || operation.State != agentv1.StateFailed {
					t.Fatalf("approval preparation = %+v, %v", operation, err)
				}
				stored, getErr := operations.Get("agent", operation.ID)
				if getErr != nil || stored.State != agentv1.StateFailed {
					t.Fatalf("stored preparation = %+v, %v", stored, getErr)
				}
			}
			if adapter.cleanupCount.Load() == 0 {
				t.Fatal("failed preparation retained provider state")
			}
		})
	}
}

func TestRuntimeRestartRequiresReservedValidAuthority(t *testing.T) {
	for name, invalidate := range map[string]bool{"missing reservation": false, "invalid approval": true} {
		t.Run(name, func(t *testing.T) {
			notifier := &captureNotifier{}
			runtime, _, operations, grantStore, closeRuntime := newRuntime(t, nil, requestDecision, notifier, true)
			defer closeRuntime()
			operation, _, err := runtime.Submit(t.Context(), "agent", agentv1.SubmitRequest{IdempotencyKey: "restart-" + strings.ReplaceAll(name, " ", "-"),
				Operation: "repo.create", Target: json.RawMessage(`{"name":"demo"}`), Arguments: json.RawMessage(`{}`), Reason: "create demo"})
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
			if invalidate {
				runtime.options.ValidateExecution = func(grants.Grant) error { return errors.New("stale approval") }
			}
			runtime.ReconcileInterrupted(t.Context(), operation)
			stored, _ := operations.Get("agent", operation.ID)
			want := "approval_reservation_missing"
			if invalidate {
				want = "approval_invalid"
			}
			if stored.State != agentv1.StateFailed || stored.Error.Code != want {
				t.Fatalf("restart authority = %+v", stored)
			}
		})
	}
}

func TestRuntimeRestartRetainsUnprovenReservedAuthority(t *testing.T) {
	notifier := &captureNotifier{}
	runtime, adapter, operations, grantStore, closeRuntime := newRuntime(t, nil, requestDecision, notifier, true)
	defer closeRuntime()
	adapter.reconcileUnproven = true
	operation, _, err := runtime.Submit(t.Context(), "agent", agentv1.SubmitRequest{IdempotencyKey: "restart-unproven",
		Operation: "repo.create", Target: json.RawMessage(`{"name":"demo"}`), Arguments: json.RawMessage(`{}`), Reason: "create demo"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := grantStore.Approve(operation.ApprovalID, notifier.message.DecisionToken, "operator"); err != nil {
		t.Fatal(err)
	}
	if _, err := grantStore.ReserveUse(operation.ApprovalID); err != nil {
		t.Fatal(err)
	}
	operation, err = operations.Transition(operation.ID, agentv1.StateApproved)
	if err == nil {
		operation, err = operations.Transition(operation.ID, agentv1.StateExecuting)
	}
	if err != nil {
		t.Fatal(err)
	}
	runtime.ReconcileInterrupted(t.Context(), operation)
	stored, _ := operations.Get("agent", operation.ID)
	grant, _ := grantStore.Get(operation.ApprovalID)
	if stored.State != agentv1.StateFailed || stored.Error == nil || stored.Error.Code != "upstream_result_unknown" || !grant.ReservationRetained {
		t.Fatalf("recovered operation = %+v, grant = %+v", stored, grant)
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

func allowThenRequestDecision(_ policy.Request, options policy.DecisionOptions) policy.Decision {
	if options.ForGrantRequest {
		return requestDecision(policy.Request{}, options)
	}
	return directDecision(policy.Request{}, options)
}

func newRuntime(t *testing.T, executeErr error, decide func(policy.Request, policy.DecisionOptions) policy.Decision,
	notifier approvalnotify.Notifier, operatorConfigured bool) (*Runtime[runtimeInput, runtimePlan, policy.Request], *runtimeAdapter, *agentops.Store, *grants.Store, func()) {
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
		Notifier:          notifier, ApprovalMessage: func(_ context.Context, grant grants.Grant, token string) approvalnotify.Approval {
			return approvalnotify.Approval{GrantID: grant.ID, DecisionToken: token, Operation: grant.Operation}
		}, OperatorConfigured: operatorConfigured,
		RecordOutcome: func(_ agentv1.Operation, _ runtimePlan, _, _ string, status int) {
			adapter.recordedStatus.Store(int32(status))
		},
	})
	if err != nil {
		_ = database.Close()
		t.Fatal(err)
	}
	return runtime, adapter, operationStore, grantStore, func() { _ = database.Close() }
}
