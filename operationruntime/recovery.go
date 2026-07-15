package operationruntime

import (
	"context"
	"errors"
	"net/http"

	"github.com/osolmaz/brokerkit/agentv1"
	"github.com/osolmaz/brokerkit/grants"
)

func (r *Runtime[I, P, A]) advancePendingApproval(ctx context.Context, operation agentv1.Operation) agentv1.Operation {
	if operation.State != agentv1.StatePending {
		return operation
	}
	if operation.ApprovalID == "" {
		operation = r.RecoverApproval(operation)
	}
	if operation.State != agentv1.StatePending || operation.ApprovalID == "" {
		return operation
	}
	operation = r.recoverApprovalNotification(ctx, operation)
	if operation.State == agentv1.StatePending {
		operation = r.syncApproval(operation)
	}
	return operation
}

func (r *Runtime[I, P, A]) recoverApprovalNotification(ctx context.Context, operation agentv1.Operation) agentv1.Operation {
	if r.options.Notifier == nil || r.options.ApprovalMessage == nil {
		return operation
	}
	grant, err := r.options.Grants.Get(operation.ApprovalID)
	if err != nil || grant.Status != grants.StatusPending || grant.Notification != nil {
		return operation
	}
	return r.bindApproval(ctx, operation, grant)
}

// ReconcileInterrupted proves an executing operation after restart without
// replaying the mutation.
func (r *Runtime[I, P, A]) ReconcileInterrupted(ctx context.Context, operation agentv1.Operation) {
	adapter, plan, err := r.Load(operation)
	if err != nil {
		r.fail(operation.ID, agentv1.StateFailed, "invalid_stored_operation", "Stored operation is invalid")
		return
	}
	outcome, err := adapter.Reconcile(ctx, plan)
	if err == nil && outcome.Proven {
		if !r.settleRecoveredApproval(operation) {
			return
		}
		result := NormalizedResult(operation.Operation, outcome.Result)
		if _, succeedErr := r.options.Operations.Succeed(operation.ID, result); succeedErr != nil {
			r.fail(operation.ID, agentv1.StateFailed, "operation_store_unavailable", "Operation ran but its result could not be stored")
			return
		}
		r.cleanup(adapter, plan)
		if r.options.RecordOutcome != nil {
			r.options.RecordOutcome(operation, plan, "allowed", "reconciled after restart", normalizedUpstreamStatus(outcome.UpstreamStatus))
		}
		return
	}
	r.retainRecoveredApproval(operation)
	r.fail(operation.ID, agentv1.StateFailed, "upstream_result_unknown", "Operation result could not be proven after restart")
}

func (r *Runtime[I, P, A]) retainRecoveredApproval(operation agentv1.Operation) {
	if operation.ApprovalID == "" {
		return
	}
	grant, err := r.options.Grants.Get(operation.ApprovalID)
	if err == nil && grant.ReservedCount > 0 && !grant.ReservationRetained {
		_, _ = r.options.Grants.RetainUse(grant.ID)
	}
}

func normalizedUpstreamStatus(status int) int {
	if status >= 100 && status <= 599 {
		return status
	}
	return http.StatusOK
}

func (r *Runtime[I, P, A]) settleRecoveredApproval(operation agentv1.Operation) bool {
	if operation.ApprovalID == "" {
		return true
	}
	grant, err := r.options.Grants.Get(operation.ApprovalID)
	if err != nil || r.options.ValidateExecution(grant) != nil {
		r.fail(operation.ID, agentv1.StateFailed, "approval_invalid", "Approval no longer matches the operation")
		return false
	}
	commit, valid := RecoveredApprovalCommit(grant)
	if !valid {
		r.fail(operation.ID, agentv1.StateFailed, "approval_reservation_missing", "Approval was not reserved before execution")
		return false
	}
	if !commit {
		return true
	}
	if _, err := r.options.Grants.CommitUse(grant.ID); err != nil {
		r.fail(operation.ID, agentv1.StateFailed, "approval_commit_failed", "Operation ran but approval accounting failed")
		return false
	}
	return true
}

// RecoveredApprovalCommit reports whether restart recovery must commit a
// reserved use and whether the recorded authority state is valid.
func RecoveredApprovalCommit(grant grants.Grant) (commit, valid bool) {
	if grant.UsedCount > 0 {
		return false, true
	}
	return grant.ReservedCount > 0, grant.ReservedCount > 0
}

// Load loads and provider-validates an immutable operation plan.
func (r *Runtime[I, P, A]) Load(operation agentv1.Operation) (Adapter[I, P, A], P, error) {
	adapter, found := r.options.Registry.Lookup(operation.Operation)
	if !found || operation.PlanDigest == "" {
		var zero P
		return nil, zero, errors.New("operation adapter is unavailable")
	}
	plan, err := r.options.Load(operation, adapter)
	if err != nil {
		var zero P
		return nil, zero, err
	}
	return adapter, plan, nil
}

func (r *Runtime[I, P, A]) reserveApproval(operation agentv1.Operation) (grants.Grant, bool, bool) {
	if operation.ApprovalID == "" {
		return grants.Grant{}, false, true
	}
	grant, err := r.options.Grants.Get(operation.ApprovalID)
	if err != nil || r.options.ValidateExecution(grant) != nil {
		r.fail(operation.ID, agentv1.StateFailed, "approval_invalid", "Approval no longer matches the operation")
		return grants.Grant{}, false, false
	}
	reserved, err := r.options.Grants.ReserveUse(grant.ID)
	if err != nil {
		r.fail(operation.ID, agentv1.StateFailed, "approval_unavailable", "Approval could not be reserved")
		return grants.Grant{}, false, false
	}
	return reserved, true, true
}

func requiresApproval[I, P, A any](adapter Adapter[I, P, A]) bool {
	required, ok := any(adapter).(ApprovalRequiredAdapter)
	return ok && required.RequiresApproval()
}

func (r *Runtime[I, P, A]) failExecution(operation agentv1.Operation, plan P, executionErr, reconcileErr error) Failure {
	failure := r.options.ExecutionFailure(executionErr, reconcileErr)
	r.fail(operation.ID, agentv1.StateFailed, failure.Code, failure.Message)
	if r.options.RecordOutcome != nil {
		r.options.RecordOutcome(operation, plan, "refused", failure.Code, 0)
	}
	return failure
}

// FailExecution records one provider-redacted execution or reconciliation
// failure.
func (r *Runtime[I, P, A]) FailExecution(operation agentv1.Operation, plan P, executionErr, reconcileErr error) {
	r.failExecution(operation, plan, executionErr, reconcileErr)
}

func (r *Runtime[I, P, A]) fail(id string, state agentv1.State, code, message string) agentv1.Operation {
	operation, err := r.options.Operations.Fail(id, state, code, message)
	if err != nil {
		operation, _ = r.options.Operations.GetByID(id)
	}
	r.cleanupStored(operation)
	return operation
}

func (r *Runtime[I, P, A]) cleanup(adapter Adapter[I, P, A], plan P) {
	if cleaner, ok := any(adapter).(PlanCleaner[P]); ok {
		_ = cleaner.Cleanup(plan)
	}
}

func (r *Runtime[I, P, A]) cleanupStored(operation agentv1.Operation) {
	if operation.PlanDigest == "" {
		return
	}
	adapter, plan, err := r.Load(operation)
	if err == nil {
		r.cleanup(adapter, plan)
	}
}
