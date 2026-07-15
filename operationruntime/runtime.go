package operationruntime

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/osolmaz/brokerkit/admission"
	"github.com/osolmaz/brokerkit/agentapi"
	"github.com/osolmaz/brokerkit/agentops"
	"github.com/osolmaz/brokerkit/agentv1"
	"github.com/osolmaz/brokerkit/authorization"
	"github.com/osolmaz/brokerkit/grants"
	"github.com/osolmaz/brokerkit/notify"
	"github.com/osolmaz/brokerkit/policy"
	"github.com/osolmaz/brokerkit/state"
)

const (
	defaultAuthorizationGrace = 30 * time.Second
	defaultWorkerInterval     = 500 * time.Millisecond
	defaultWorkerConcurrency  = 8
	defaultNotificationLease  = 2 * time.Minute
)

var errApprovalNotificationClaimed = errors.New("approval notification is already claimed")

// Preparation is the immutable provider plan context selected by the shared
// lifecycle. The provider encodes it into its v1 plan and canonical grant.
type Preparation[P, A any] struct {
	Plan           P
	Auth           A
	Core           policy.Request
	DescriptorName string
	Client         string
	OperationID    string
	Reason         string
	Decision       policy.Decision
	Direct         bool
	CreatedAt      time.Time
}

// Failure is a provider-redacted terminal execution error.
type Failure struct {
	Code    string
	Message string
}

// Observer receives bounded lifecycle outcomes without provider or target data.
type Observer interface {
	OperationSubmitted(result string)
	OperationExecuted(result string, elapsed time.Duration)
	NotificationDelivered(result string)
}

// Diagnostics receives secret-safe lifecycle context for structured logs and
// bounded dependency/capacity metrics.
type Diagnostics interface {
	WorkerConfigured(workerLimit int)
	OperationStarted(correlationID, operationClass string, workerLimit int)
	OperationFinished(correlationID, operationClass, result, errorCode string, elapsed time.Duration)
	NotificationAttempt(correlationID, result, errorCode string)
	Retry(correlationID, dependency string)
}

// Options supplies provider semantics and shared durable dependencies. The
// callbacks encode provider plans and presentation; lifecycle transitions stay
// inside Runtime.
type Options[I, P, A any] struct {
	Broker              string
	Operations          *agentops.Store
	Admission           *admission.Controller
	Registry            *Registry[I, P, A]
	Authorization       *authorization.Coordinator
	Grants              *grants.Store
	Decide              func(policy.Request, policy.DecisionOptions) policy.Decision
	Project             func(A) policy.Request
	SetClient           func(*P, string)
	InputData           func(I) (json.RawMessage, json.RawMessage)
	PlanData            func(P) (json.RawMessage, json.RawMessage)
	Prepare             func(Preparation[P, A]) (authorization.GrantIntent, error)
	Load                func(agentv1.Operation, Adapter[I, P, A]) (P, error)
	PlanDigest          func(grants.Grant) string
	StoredPlan          func(string) (state.PlanRecord, error)
	ValidateExecution   func(grants.Grant) error
	MapSubmissionError  func(error) error
	DefinitiveFailure   func(error) bool
	ExecutionFailure    func(error, error) Failure
	RecordPolicyRefusal func(agentv1.Operation, P, policy.Decision, string)
	RecordOutcome       func(agentv1.Operation, P, string, string, int)
	Notifier            notify.Notifier
	ApprovalMessage     func(grants.Grant, string) notify.ApprovalMessage
	OperatorConfigured  bool
	Now                 func() time.Time
	AuthorizationGrace  time.Duration
	WorkerInterval      time.Duration
	WorkerConcurrency   int
	NotificationLease   time.Duration
	Observer            Observer
	Diagnostics         Diagnostics
}

// Runtime drives one provider's generic Agent V1 operation lifecycle.
type Runtime[I, P, A any] struct {
	options         Options[I, P, A]
	authLocks       [64]sync.Mutex
	submissionLocks [64]sync.Mutex
	workers         sync.WaitGroup
}

// New validates and constructs a provider-neutral lifecycle runtime.
func New[I, P, A any](options Options[I, P, A]) (*Runtime[I, P, A], error) {
	if !validCoreOptions(options) || !validPlanOptions(options) || !validLifecycleOptions(options) {
		return nil, errors.New("operation runtime options are incomplete")
	}
	options = defaultOptions(options)
	if options.Diagnostics != nil {
		options.Diagnostics.WorkerConfigured(options.WorkerConcurrency)
	}
	return &Runtime[I, P, A]{options: options}, nil
}

func defaultOptions[I, P, A any](options Options[I, P, A]) Options[I, P, A] {
	options = defaultRuntimeTiming(options)
	return defaultRuntimeCallbacks(options)
}

func defaultRuntimeTiming[I, P, A any](options Options[I, P, A]) Options[I, P, A] {
	if options.Now == nil {
		options.Now = time.Now
	}
	if options.AuthorizationGrace <= 0 {
		options.AuthorizationGrace = defaultAuthorizationGrace
	}
	if options.WorkerInterval <= 0 {
		options.WorkerInterval = defaultWorkerInterval
	}
	if options.WorkerConcurrency <= 0 {
		options.WorkerConcurrency = defaultWorkerConcurrency
	}
	if options.NotificationLease <= 0 {
		options.NotificationLease = defaultNotificationLease
	}
	return options
}

func defaultRuntimeCallbacks[I, P, A any](options Options[I, P, A]) Options[I, P, A] {
	if options.MapSubmissionError == nil {
		options.MapSubmissionError = func(err error) error {
			return operationAPIError(http.StatusBadRequest, "operation_input_invalid", err.Error())
		}
	}
	if options.DefinitiveFailure == nil {
		options.DefinitiveFailure = func(err error) bool { return err != nil && !IsPossiblePartial(err) }
	}
	if options.ExecutionFailure == nil {
		options.ExecutionFailure = func(error, error) Failure {
			return Failure{Code: "upstream_result_unknown", Message: "Operation result is unknown and was not retried"}
		}
	}
	return options
}

func validCoreOptions[I, P, A any](options Options[I, P, A]) bool {
	return strings.TrimSpace(options.Broker) != "" && options.Operations != nil && options.Registry != nil &&
		options.Authorization != nil && options.Grants != nil
}

func validPlanOptions[I, P, A any](options Options[I, P, A]) bool {
	return options.Project != nil && options.SetClient != nil && options.InputData != nil && options.PlanData != nil &&
		options.Prepare != nil && options.Load != nil
}

func validLifecycleOptions[I, P, A any](options Options[I, P, A]) bool {
	return options.Decide != nil && options.PlanDigest != nil && options.StoredPlan != nil && options.ValidateExecution != nil
}

// Start recovers unfinished work and starts worker dispatch.
func (r *Runtime[I, P, A]) Start(ctx context.Context) {
	r.workers.Add(1)
	go func() {
		defer r.workers.Done()
		ticker := time.NewTicker(r.options.WorkerInterval)
		defer ticker.Stop()
		r.Recover(ctx)
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				r.AdvanceAll(ctx)
			}
		}
	}()
}

// Wait waits for lifecycle workers after their context is canceled.
func (r *Runtime[I, P, A]) Wait() { r.workers.Wait() }

// Submit validates, resolves, authorizes, and durably submits an operation.
func (r *Runtime[I, P, A]) Submit(ctx context.Context, client string, request agentv1.SubmitRequest) (operation agentv1.Operation, created bool, returnErr error) {
	defer func() { r.observeSubmission(created, returnErr) }()
	request.IdempotencyKey = strings.TrimSpace(request.IdempotencyKey)
	request.Reason = strings.TrimSpace(request.Reason)
	adapter, input, err := r.decode(request)
	if err != nil {
		return agentv1.Operation{}, false, err
	}
	lock := stripedLock("submit:"+client+":"+request.IdempotencyKey, r.submissionLocks[:])
	lock.Lock()
	defer lock.Unlock()
	if existing, found, replayErr := r.replayed(client, request, input); replayErr != nil || found {
		return existing, false, replayErr
	}
	return r.submitNew(ctx, client, request, adapter, input)
}

func (r *Runtime[I, P, A]) submitNew(ctx context.Context, client string, request agentv1.SubmitRequest,
	adapter Adapter[I, P, A], input I) (agentv1.Operation, bool, error) {
	if bound, ok := any(adapter).(ClientBoundAdapter[I]); ok {
		if err := bound.ValidateClient(input, client, request.IdempotencyKey); err != nil {
			return agentv1.Operation{}, false, operationAPIError(http.StatusBadRequest, "operation_input_invalid", err.Error())
		}
	}
	permit, err := r.admit(ctx, client)
	if err != nil {
		return agentv1.Operation{}, false, err
	}
	if permit != nil {
		defer permit.Release()
	}
	plan, err := adapter.Resolve(ctx, input)
	if err != nil {
		return agentv1.Operation{}, false, r.options.MapSubmissionError(err)
	}
	r.options.SetClient(&plan, client)
	operation, created, err := r.submitResolved(ctx, client, request, adapter, plan)
	if created && permit != nil {
		permit.Commit()
	}
	return operation, created, err
}

func (r *Runtime[I, P, A]) observeSubmission(created bool, err error) {
	if r.options.Observer == nil {
		return
	}
	result := "replayed"
	if err != nil {
		result = "rejected"
	} else if created {
		result = "created"
	}
	r.options.Observer.OperationSubmitted(result)
}

func (r *Runtime[I, P, A]) admit(ctx context.Context, client string) (*admission.Permit, error) {
	if r.options.Admission == nil {
		return nil, nil
	}
	permit, err := r.options.Admission.Admit(ctx, client)
	if err == nil {
		return permit, nil
	}
	var limit *admission.LimitError
	if errors.As(err, &limit) {
		seconds := int((limit.RetryAfter + time.Second - 1) / time.Second)
		return nil, &agentapi.Error{Status: http.StatusTooManyRequests, Code: limit.Code,
			Message: "Operation admission limit reached", RetryAfterSeconds: seconds}
	}
	return nil, operationAPIError(http.StatusServiceUnavailable, "operation_store_unavailable", "Could not check operation capacity")
}

func (r *Runtime[I, P, A]) decode(request agentv1.SubmitRequest) (Adapter[I, P, A], I, error) {
	adapter, found := r.options.Registry.Lookup(request.Operation)
	if !found {
		var zero I
		return nil, zero, operationAPIError(http.StatusBadRequest, "operation_not_registered", "Operation is not registered")
	}
	input, err := adapter.Decode(request.Target, request.Arguments)
	if err != nil {
		var zero I
		return nil, zero, operationAPIError(http.StatusBadRequest, "operation_input_invalid", err.Error())
	}
	return adapter, input, nil
}

func (r *Runtime[I, P, A]) replayed(client string, request agentv1.SubmitRequest, input I) (agentv1.Operation, bool, error) {
	existing, err := r.options.Operations.GetByIdempotency(client, request.IdempotencyKey)
	if errors.Is(err, agentops.ErrNotFound) {
		return agentv1.Operation{}, false, nil
	}
	if err != nil {
		return agentv1.Operation{}, false, err
	}
	target, arguments := r.options.InputData(input)
	if existing.Operation != request.Operation || existing.Reason != request.Reason ||
		!EqualJSONObject(existing.Target, target) || !EqualJSONObject(existing.Arguments, arguments) {
		return agentv1.Operation{}, false, agentops.ErrIdempotencyConflict
	}
	return existing, true, nil
}

func (r *Runtime[I, P, A]) submitResolved(ctx context.Context, client string, request agentv1.SubmitRequest,
	adapter Adapter[I, P, A], plan P) (agentv1.Operation, bool, error) {
	id, err := r.options.Operations.NewID()
	if err != nil {
		r.cleanup(adapter, plan)
		return agentv1.Operation{}, false, err
	}
	target, arguments := r.options.PlanData(plan)
	submission := agentops.Submit{ID: id, Broker: r.options.Broker, ClientID: client, IdempotencyKey: request.IdempotencyKey,
		Operation: request.Operation, Target: target, Arguments: arguments, Reason: request.Reason, Presentation: adapter.Present(plan)}
	auth := adapter.Authorize(plan)
	core := r.options.Project(auth)
	decision := r.options.Decide(core, policy.DecisionOptions{Now: r.now()})
	if decision.Allowed && len(decision.MatchedAllowRuleIDs) > 0 && !requiresApproval(adapter) {
		intent, prepareErr := r.options.Prepare(Preparation[P, A]{Plan: plan, Auth: auth, Core: core, DescriptorName: adapter.Descriptor().Name,
			Client: client, OperationID: id, Reason: request.Reason, Decision: decision, Direct: true, CreatedAt: r.now()})
		if prepareErr != nil {
			r.cleanup(adapter, plan)
			return agentv1.Operation{}, false, prepareErr
		}
		operation, created, submitErr := r.options.Operations.SubmitApprovedWithPlan(submission, PlanRecord(intent.Plan))
		if submitErr != nil {
			r.cleanup(adapter, plan)
		}
		return operation, created, submitErr
	}
	return r.submitPending(ctx, submission, adapter, plan, auth, core)
}

func (r *Runtime[I, P, A]) submitPending(ctx context.Context, submission agentops.Submit, adapter Adapter[I, P, A],
	plan P, auth A, core policy.Request) (agentv1.Operation, bool, error) {
	lock := r.authorizationLock(submission.ID)
	lock.Lock()
	operation, created, err := r.createPending(submission, adapter, plan)
	if err != nil || !created {
		lock.Unlock()
		return operation, created, err
	}
	var prepared grants.ImmutablePlan
	result, authErr := r.options.Authorization.RequestApproval(core, func(decision policy.Decision) (authorization.GrantIntent, error) {
		intent, prepareErr := r.options.Prepare(Preparation[P, A]{Plan: plan, Auth: auth, Core: core, DescriptorName: adapter.Descriptor().Name,
			Client: operation.ClientID, OperationID: operation.ID, Reason: operation.Reason, Decision: decision, CreatedAt: r.now()})
		prepared = intent.Plan
		return intent, prepareErr
	})
	if authErr != nil {
		_ = r.abandonApproval(result.Request.Grant.ID, operation.ClientID)
		r.cleanup(adapter, plan)
		operation = r.finishRefused(operation, plan, result, authErr)
		lock.Unlock()
		return operation, true, nil
	}
	if prepared.Digest == "" {
		r.cleanup(adapter, plan)
		operation = r.fail(operation.ID, agentv1.StateFailed, "operation_plan_invalid", "Could not prepare immutable operation plan")
		lock.Unlock()
		return operation, true, nil
	}
	bound, bindErr := r.options.Operations.BindPlan(operation.ID, PlanRecord(prepared), result.Request.Grant.ID, false)
	if bindErr != nil {
		_ = r.abandonApproval(result.Request.Grant.ID, operation.ClientID)
		r.cleanup(adapter, plan)
		operation = r.fail(operation.ID, agentv1.StateFailed, "operation_store_unavailable", "Could not bind operation plan")
		lock.Unlock()
		return operation, true, nil //nolint:nilerr // The durable operation carries the terminal storage failure.
	}
	lock.Unlock()
	return r.bindApproval(ctx, bound, result.Request.Grant), true, nil
}

func (r *Runtime[I, P, A]) createPending(submission agentops.Submit, adapter Adapter[I, P, A], plan P) (agentv1.Operation, bool, error) {
	operation, created, err := r.options.Operations.Submit(submission)
	if err != nil {
		r.cleanup(adapter, plan)
		return operation, created, err
	}
	return operation, created, nil
}

func (r *Runtime[I, P, A]) finishRefused(operation agentv1.Operation, plan P, result authorization.Result, err error) agentv1.Operation {
	code := "approval_request_failed"
	message := "Could not create approval request"
	state := agentv1.StateFailed
	if errors.Is(err, authorization.ErrDenied) || errors.Is(err, authorization.ErrNoMatch) {
		code, message, state = "operation_policy_denied", "Policy denied this operation", agentv1.StateDenied
		if errors.Is(err, authorization.ErrNoMatch) {
			message = "No policy rule allows this operation"
		}
		if r.options.RecordPolicyRefusal != nil {
			r.options.RecordPolicyRefusal(operation, plan, result.Decision, code)
		}
	}
	return r.fail(operation.ID, state, code, message)
}

// Cancel cancels a pending or approved operation and its approval authority.
func (r *Runtime[I, P, A]) Cancel(_ context.Context, client, id string) (agentv1.Operation, error) {
	lock := r.authorizationLock(id)
	lock.Lock()
	defer lock.Unlock()
	operation, err := r.options.Operations.Get(client, id)
	if err != nil || operation.State.Terminal() {
		return operation, err
	}
	if operation.State == agentv1.StateExecuting {
		return agentv1.Operation{}, agentops.ErrNotCancelable
	}
	if err := r.cancelApproval(operation, client); err != nil {
		return agentv1.Operation{}, err
	}
	operation, err = r.options.Operations.Cancel(client, operation.ID)
	if err == nil {
		r.cleanupStored(operation)
	}
	return operation, err
}

func (r *Runtime[I, P, A]) cancelApproval(operation agentv1.Operation, client string) error {
	id, found, err := r.approvalID(operation, client)
	if err != nil || !found {
		return err
	}
	grant, err := r.options.Grants.Get(id)
	if err != nil {
		return err
	}
	return r.cancelGrant(grant, client)
}

func (r *Runtime[I, P, A]) approvalID(operation agentv1.Operation, client string) (string, bool, error) {
	if operation.ApprovalID != "" {
		return operation.ApprovalID, true, nil
	}
	values, err := r.options.Grants.ListForClient(client)
	if err != nil {
		return "", false, err
	}
	grant, found := r.operationApproval(values, operation)
	return grant.ID, found, nil
}

func (r *Runtime[I, P, A]) cancelGrant(grant grants.Grant, client string) error {
	switch grant.Status {
	case grants.StatusPending:
		_, err := r.options.Grants.CancelForClient(grant.ID, client)
		return err
	case grants.StatusActive:
		_, err := r.options.Grants.RevokeForClient(grant.ID, client)
		return err
	default:
		return nil
	}
}

// CancelGrant cancels or revokes one requester-owned approval grant.
func (r *Runtime[I, P, A]) CancelGrant(grant grants.Grant, client string) error {
	return r.cancelGrant(grant, client)
}

func (r *Runtime[I, P, A]) abandonApproval(id, client string) error {
	if id == "" {
		return nil
	}
	grant, err := r.options.Grants.Get(id)
	if err != nil {
		return err
	}
	return r.cancelGrant(grant, client)
}

func (r *Runtime[I, P, A]) bindApproval(ctx context.Context, operation agentv1.Operation, grant grants.Grant) agentv1.Operation {
	if r.options.Notifier != nil && r.options.ApprovalMessage != nil {
		if err := r.notifyApproval(ctx, grant); err != nil {
			if errors.Is(err, errApprovalNotificationClaimed) || r.options.OperatorConfigured {
				return operation
			}
			return r.failUnnotified(operation, grant, "approval_notification_failed", "Could not notify the operator")
		}
		return operation
	}
	if !r.options.OperatorConfigured {
		return r.failUnnotified(operation, grant, "approval_channel_not_configured", "Approval channel is not configured")
	}
	return operation
}

func (r *Runtime[I, P, A]) notifyApproval(ctx context.Context, grant grants.Grant) error {
	r.observeNotificationRetry(grant)
	claim, done, err := r.claimNotification(grant)
	if err != nil {
		r.observeNotification(grant.ID, "claimed", "notification_claim_failed")
		return err
	}
	if done {
		r.observeNotification(grant.ID, "already_recorded", "")
		return nil
	}
	ref, err := r.options.Notifier.SendApproval(ctx, r.options.ApprovalMessage(claim.Grant, claim.DecisionToken))
	if err = validateNotificationReference(ref, err); err != nil {
		r.observeNotification(grant.ID, "failed", "notification_unavailable")
		return r.settleNotificationFailure(claim, err)
	}
	if err := r.recordNotification(claim, ref); err != nil {
		r.observeNotification(grant.ID, "failed", "notification_store_failed")
		return err
	}
	r.observeNotification(grant.ID, "delivered", "")
	return nil
}

func (r *Runtime[I, P, A]) observeNotificationRetry(grant grants.Grant) {
	if !grant.NotificationClaimedAt.IsZero() && r.options.Diagnostics != nil {
		r.options.Diagnostics.Retry(grant.ID, "notification")
	}
}

func (r *Runtime[I, P, A]) observeNotification(correlationID, result, errorCode string) {
	if r.options.Observer != nil {
		r.options.Observer.NotificationDelivered(result)
	}
	if r.options.Diagnostics != nil {
		r.options.Diagnostics.NotificationAttempt(correlationID, result, errorCode)
	}
}

func (r *Runtime[I, P, A]) claimNotification(grant grants.Grant) (grants.NotificationClaim, bool, error) {
	claim, claimed, err := r.options.Grants.ClaimNotification(grant.ID, r.options.NotificationLease)
	if err != nil {
		return grants.NotificationClaim{}, false, err
	}
	if !claimed {
		if r.notificationRecorded(grant.ID) {
			return grants.NotificationClaim{}, true, nil
		}
		return grants.NotificationClaim{}, false, errApprovalNotificationClaimed
	}
	return claim, false, nil
}

func (r *Runtime[I, P, A]) notificationRecorded(grantID string) bool {
	current, err := r.options.Grants.Get(grantID)
	return err == nil && current.Notification != nil
}

func (r *Runtime[I, P, A]) recordNotification(claim grants.NotificationClaim, ref notify.MessageRef) error {
	current, recorded, err := r.options.Grants.SetNotificationIfClaimed(claim.Grant.ID, claim.Grant.NotificationClaimedAt, ref)
	if err != nil || !recorded && current.Notification == nil {
		return r.settleNotificationFailure(claim, err)
	}
	return nil
}

func validateNotificationReference(ref notify.MessageRef, err error) error {
	if err != nil {
		return err
	}
	if ref.MessageID <= 0 {
		return errors.New("approval notification reference is invalid")
	}
	return nil
}

func (r *Runtime[I, P, A]) settleNotificationFailure(claim grants.NotificationClaim, cause error) error {
	if r.options.OperatorConfigured {
		_, _, err := r.options.Grants.RetainNotificationClaim(claim.Grant.ID, claim.Grant.NotificationClaimedAt)
		return errors.Join(cause, err)
	}
	_, _, err := r.options.Grants.CancelIfNotificationClaimed(claim.Grant.ID, claim.Grant.NotificationClaimedAt)
	return errors.Join(cause, err)
}

func (r *Runtime[I, P, A]) failUnnotified(operation agentv1.Operation, grant grants.Grant, code, message string) agentv1.Operation {
	if r.abandonApproval(grant.ID, operation.ClientID) != nil {
		return operation
	}
	return r.fail(operation.ID, agentv1.StateFailed, code, message)
}

// Recover reconciles executing operations and advances other unfinished work.
func (r *Runtime[I, P, A]) Recover(ctx context.Context) {
	values, err := r.options.Operations.ListUnfinished()
	if err != nil {
		return
	}
	r.runBatch(ctx, values, func(ctx context.Context, operation agentv1.Operation) {
		if operation.State == agentv1.StateExecuting {
			r.ReconcileInterrupted(ctx, operation)
		} else {
			r.Advance(ctx, operation)
		}
	})
}

// AdvanceAll advances every unfinished operation once.
func (r *Runtime[I, P, A]) AdvanceAll(ctx context.Context) {
	values, err := r.options.Operations.ListUnfinished()
	if err != nil {
		return
	}
	r.runBatch(ctx, values, func(ctx context.Context, operation agentv1.Operation) { r.Advance(ctx, operation) })
}

func (r *Runtime[I, P, A]) runBatch(ctx context.Context, values []agentv1.Operation, run func(context.Context, agentv1.Operation)) {
	if len(values) == 0 {
		return
	}
	workers := min(r.options.WorkerConcurrency, len(values))
	jobs := make(chan agentv1.Operation)
	var batch sync.WaitGroup
	batch.Add(workers)
	for range workers {
		go func() {
			defer batch.Done()
			for operation := range jobs {
				run(ctx, operation)
			}
		}()
	}
	for _, operation := range values {
		select {
		case jobs <- operation:
		case <-ctx.Done():
			close(jobs)
			batch.Wait()
			return
		}
	}
	close(jobs)
	batch.Wait()
}

// Advance synchronizes approval state and dispatches one approved operation.
func (r *Runtime[I, P, A]) Advance(ctx context.Context, operation agentv1.Operation) {
	lock := r.authorizationLock(operation.ID)
	lock.Lock()
	defer lock.Unlock()
	current, err := r.options.Operations.GetByID(operation.ID)
	if err != nil {
		return
	}
	current = r.advancePendingApproval(ctx, current)
	if current.State != agentv1.StateApproved {
		return
	}
	claimed, err := r.options.Operations.Transition(current.ID, agentv1.StateExecuting)
	if err == nil {
		r.Execute(ctx, claimed)
	}
}

// RecoverApproval repairs an operation interrupted between grant and plan
// binding.
func (r *Runtime[I, P, A]) RecoverApproval(operation agentv1.Operation) agentv1.Operation {
	values, err := r.options.Grants.ListForClient(operation.ClientID)
	if err != nil {
		return operation
	}
	grant, found := r.operationApproval(values, operation)
	if !found {
		if r.now().Sub(operation.UpdatedAt) < r.options.AuthorizationGrace {
			return operation
		}
		return r.fail(operation.ID, agentv1.StateFailed, "approval_missing", "Approval request is missing")
	}
	digest := r.options.PlanDigest(grant)
	plan, err := r.planRecord(digest)
	if err != nil {
		return operation
	}
	updated, err := r.options.Operations.BindPlan(operation.ID, plan, grant.ID, false)
	if err != nil {
		return operation
	}
	return updated
}

func (r *Runtime[I, P, A]) operationApproval(values []grants.Grant, operation agentv1.Operation) (grants.Grant, bool) {
	for _, grant := range values {
		digest := r.options.PlanDigest(grant)
		if grant.ClientRequestID == operation.ID && grant.Operation == operation.Operation && digest != "" &&
			(operation.PlanDigest == "" || digest == operation.PlanDigest) {
			return grant, true
		}
	}
	return grants.Grant{}, false
}

func (r *Runtime[I, P, A]) syncApproval(operation agentv1.Operation) agentv1.Operation {
	grant, err := r.options.Grants.Get(operation.ApprovalID)
	if err != nil {
		return operation
	}
	switch grant.Status {
	case grants.StatusActive:
		updated, _ := r.options.Operations.Transition(operation.ID, agentv1.StateApproved)
		return updated
	case grants.StatusDenied:
		return r.fail(operation.ID, agentv1.StateDenied, "operation_approval_denied", "Approval was denied")
	case grants.StatusExpired:
		return r.fail(operation.ID, agentv1.StateExpired, "operation_approval_expired", "Approval request expired")
	case grants.StatusCanceled, grants.StatusRevoked:
		return r.fail(operation.ID, agentv1.StateCanceled, "operation_canceled", "Request was canceled")
	default:
		return operation
	}
}

// Execute consumes authority, executes once, and reconciles ambiguity.
func (r *Runtime[I, P, A]) Execute(ctx context.Context, operation agentv1.Operation) {
	adapter, plan, err := r.Load(operation)
	if err != nil {
		r.fail(operation.ID, agentv1.StateFailed, "invalid_stored_operation", "Stored operation is invalid")
		return
	}
	grant, reserved, ok := r.reserveApproval(operation)
	if !ok {
		return
	}
	plan, ok = r.bindReservedPlan(operation, adapter, plan, grant, reserved)
	if !ok {
		return
	}
	r.executeReserved(ctx, operation, adapter, plan, reserved)
}

func (r *Runtime[I, P, A]) bindReservedPlan(operation agentv1.Operation, adapter Adapter[I, P, A], plan P,
	grant grants.Grant, reserved bool) (P, bool) {
	if !reserved {
		return plan, true
	}
	binder, bound := any(adapter).(ReservationBinder[P])
	if !bound {
		return plan, true
	}
	boundPlan, err := binder.BindReservation(plan, grant)
	if err == nil {
		return boundPlan, true
	}
	_, _ = r.options.Grants.ReleaseUse(grant.ID)
	r.fail(operation.ID, agentv1.StateFailed, "approval_invalid", "Approved operation binding is invalid")
	return plan, false
}

func (r *Runtime[I, P, A]) executeReserved(ctx context.Context, operation agentv1.Operation, adapter Adapter[I, P, A], plan P, reserved bool) {
	started := time.Now()
	result, errorCode := "ambiguous", "upstream_result_unknown"
	operationClass := string(adapter.Descriptor().Risk)
	if r.options.Diagnostics != nil {
		r.options.Diagnostics.OperationStarted(operation.ID, operationClass, r.options.WorkerConcurrency)
	}
	defer func() {
		if r.options.Observer != nil {
			r.options.Observer.OperationExecuted(result, time.Since(started))
		}
		if r.options.Diagnostics != nil {
			r.options.Diagnostics.OperationFinished(operation.ID, operationClass, result, errorCode, time.Since(started))
		}
	}()
	execution, executionErr := adapter.Execute(ctx, plan)
	if executionErr == nil && execution.Proven {
		result, errorCode = "succeeded", ""
		r.succeed(operation, plan, execution.Result, reserved, "", execution.UpstreamStatus)
		return
	}
	if r.options.DefinitiveFailure(executionErr) {
		result = "failed"
		if r.settleApproval(operation, reserved, false) {
			errorCode = r.failExecution(operation, plan, executionErr, nil).Code
		}
		return
	}
	result, errorCode = r.reconcileExecution(ctx, operation, adapter, plan, reserved, execution, executionErr)
}

func (r *Runtime[I, P, A]) reconcileExecution(ctx context.Context, operation agentv1.Operation, adapter Adapter[I, P, A], plan P,
	reserved bool, execution Outcome, executionErr error) (string, string) {
	outcome, reconcileErr := adapter.Reconcile(ctx, plan)
	if reconcileErr == nil && outcome.Proven {
		if len(outcome.Result) == 0 {
			outcome.Result = execution.Result
		}
		if outcome.UpstreamStatus == 0 {
			outcome.UpstreamStatus = execution.UpstreamStatus
		}
		r.succeed(operation, plan, outcome.Result, reserved, "", outcome.UpstreamStatus)
		return "reconciled", ""
	}
	failure := r.options.ExecutionFailure(executionErr, reconcileErr)
	if r.settleApproval(operation, reserved, true) {
		failure = r.failExecution(operation, plan, executionErr, reconcileErr)
	}
	return "ambiguous", failure.Code
}

func (r *Runtime[I, P, A]) succeed(operation agentv1.Operation, plan P, result json.RawMessage, reserved bool, detail string, upstreamStatus int) {
	result = NormalizedResult(operation.Operation, result)
	if !r.settleApproval(operation, reserved, false) {
		return
	}
	if _, err := r.options.Operations.Succeed(operation.ID, result); err != nil {
		r.fail(operation.ID, agentv1.StateFailed, "operation_store_unavailable", "Operation ran but its result could not be stored")
		return
	}
	r.cleanupStored(operation)
	if r.options.RecordOutcome != nil {
		r.options.RecordOutcome(operation, plan, "allowed", detail, normalizedUpstreamStatus(upstreamStatus))
	}
}

// Succeed records a proven provider result and settles reserved authority.
func (r *Runtime[I, P, A]) Succeed(operation agentv1.Operation, plan P, result json.RawMessage, reserved bool, detail string) {
	r.succeed(operation, plan, result, reserved, detail, http.StatusOK)
}

func (r *Runtime[I, P, A]) settleApproval(operation agentv1.Operation, reserved, retain bool) bool {
	if !reserved {
		return true
	}
	var err error
	if retain {
		_, err = r.options.Grants.RetainUse(operation.ApprovalID)
	} else {
		_, err = r.options.Grants.CommitUse(operation.ApprovalID)
	}
	if err == nil {
		return true
	}
	r.fail(operation.ID, agentv1.StateFailed, "approval_commit_failed", "Operation ran but approval accounting failed")
	return false
}

func (r *Runtime[I, P, A]) authorizationLock(id string) *sync.Mutex {
	return stripedLock(id, r.authLocks[:])
}

func stripedLock(id string, locks []sync.Mutex) *sync.Mutex {
	var hash uint64 = 14695981039346656037
	for index := 0; index < len(id); index++ {
		hash ^= uint64(id[index])
		hash *= 1099511628211
	}
	return &locks[hash%uint64(len(locks))]
}

func (r *Runtime[I, P, A]) now() time.Time { return r.options.Now().UTC() }

func (r *Runtime[I, P, A]) planRecord(digest string) (state.PlanRecord, error) {
	return r.options.StoredPlan(digest)
}

// PlanRecord converts a canonical immutable plan into the shared state row.
func PlanRecord(plan grants.ImmutablePlan) state.PlanRecord {
	return state.PlanRecord{Digest: plan.Digest, SchemaName: plan.SchemaName, Canonical: plan.Canonical, CreatedAt: plan.CreatedAt}
}

// NormalizedResult gives reconciled operations a stable non-empty result.
func NormalizedResult(operation string, result json.RawMessage) json.RawMessage {
	if len(result) > 0 {
		return result
	}
	encoded, _ := json.Marshal(map[string]any{"operation": operation, "reconciled": true})
	return encoded
}

// EqualJSONObject compares two JSON objects while preserving numeric tokens.
func EqualJSONObject(left, right []byte) bool {
	var leftValue, rightValue any
	leftDecoder := json.NewDecoder(bytes.NewReader(left))
	leftDecoder.UseNumber()
	rightDecoder := json.NewDecoder(bytes.NewReader(right))
	rightDecoder.UseNumber()
	return leftDecoder.Decode(&leftValue) == nil && rightDecoder.Decode(&rightValue) == nil && reflect.DeepEqual(leftValue, rightValue)
}

func operationAPIError(status int, code, message string) error {
	return &agentapi.Error{Status: status, Code: code, Message: message}
}
