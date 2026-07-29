package routes

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/osolmaz/unyolo/agent/api"
	"github.com/osolmaz/unyolo/agent/v1"
	"github.com/osolmaz/unyolo/approval/notification"
	unyoloauthorization "github.com/osolmaz/unyolo/authorization"
	"github.com/osolmaz/unyolo/authorization/budget"
	"github.com/osolmaz/unyolo/authorization/grants"
	corepolicy "github.com/osolmaz/unyolo/authorization/policy"
	"github.com/osolmaz/unyolo/brokers/sudo/internal/operations"
	"github.com/osolmaz/unyolo/brokers/sudo/internal/plan"
	"github.com/osolmaz/unyolo/brokers/sudo/internal/presenter"
	"github.com/osolmaz/unyolo/internal/storage/state"
	"github.com/osolmaz/unyolo/operation/runtime"
)

func (s *Server) newOperationRuntime() (*operations.Runtime, error) {
	return operationruntime.New(operations.RuntimeOptions{
		Broker: "sudo-broker", Operations: s.operations, Admission: s.admission, Registry: s.operationRegistry.Registry,
		Authorization: s.authorization, Grants: s.grants, Decide: s.policy.Decide,
		Project:   func(request corepolicy.Request) corepolicy.Request { return request },
		SetClient: func(value *operations.Plan, client string) { value.Authorization.Client = client },
		InputData: func(input operations.Input) (json.RawMessage, json.RawMessage) { return input.Target, input.Arguments },
		PlanData:  func(value operations.Plan) (json.RawMessage, json.RawMessage) { return value.Target, value.Arguments },
		Prepare:   s.prepareRuntimePlan, Load: s.loadRuntimePlan,
		PlanDigest: func(grant grants.Grant) string { return grant.Metadata[plan.MetadataDigest] },
		StoredPlan: func(digest string) (state.PlanRecord, error) { return s.database.Plan(context.Background(), digest) },
		ValidateExecution: func(grant grants.Grant) error {
			_, err := s.validator.ValidateGrant(grant)
			return err
		},
		MapSubmissionError: func(err error) error {
			return &agentapi.Error{Status: http.StatusBadRequest, Code: "operation_input_invalid", Message: err.Error()}
		},
		DefinitiveFailure: operations.DefinitiveFailure, ExecutionFailure: operations.ExecutionFailure,
		RecordPolicyRefusal: s.recordRuntimePolicyRefusal, RecordOutcome: s.recordRuntimeOutcome,
		Notifier: s.notifier, ApprovalMessage: s.sudoApprovalMessage, OperatorConfigured: s.operatorConfigured,
		Observer:    s.control.Metrics,
		Diagnostics: s.control.Diagnostics,
	})
}

func (s *Server) prepareRuntimePlan(preparation operations.Preparation) (unyoloauthorization.GrantIntent, error) {
	if preparation.Direct {
		return unyoloauthorization.GrantIntent{}, errors.New("sudo operations require explicit approval")
	}
	mode, err := sudoRuntimeGrantMode(preparation)
	if err != nil {
		return unyoloauthorization.GrantIntent{}, err
	}
	duration, pending, maxUses, err := sudoRuntimeGrantBounds(preparation, mode)
	if err != nil {
		return unyoloauthorization.GrantIntent{}, err
	}
	request := grants.Request{Client: preparation.Client, ClientRequestID: preparation.OperationID,
		Operation: preparation.DescriptorName, Target: preparation.Core.Target, Attrs: preparation.Core.Attrs,
		Metadata: map[string]string{grants.MetadataMode: string(mode)}, Reason: preparation.Reason,
		Duration: duration, PendingTimeout: pending, MaxUses: maxUses, MaxUsesSpecified: true}
	identity, err := s.identities.Lookup(preparation.Plan.Resolved.TargetUser)
	if err != nil {
		return unyoloauthorization.GrantIntent{}, errors.New("target user cannot be resolved")
	}
	command, err := plan.Build(request, preparation.Plan.Resolved, identity, preparation.CreatedAt)
	if err != nil {
		return unyoloauthorization.GrantIntent{}, err
	}
	immutable, err := s.plans.PrepareBind(&request, command)
	if err != nil {
		return unyoloauthorization.GrantIntent{}, err
	}
	return unyoloauthorization.GrantIntent{Mode: mode, Authorization: preparation.Core,
		Request: request, Plan: immutable}, nil
}

func (s *Server) loadRuntimePlan(operation agentv1.Operation, _ operations.Adapter) (operations.Plan, error) {
	if operation.ApprovalID == "" {
		return operations.Plan{}, errors.New("sudo operation has no approval")
	}
	grant, err := s.grants.Get(operation.ApprovalID)
	if err != nil {
		return operations.Plan{}, errors.New("sudo approval plan binding is invalid")
	}
	command, err := s.validator.ValidateInvocation(operation.PlanDigest, grant, operation.ID)
	if err != nil {
		return operations.Plan{}, err
	}
	return operations.LoadStored(operation, command, s.catalog)
}

func (s *Server) recordRuntimePolicyRefusal(operation agentv1.Operation, value operations.Plan, decision corepolicy.Decision, code string) {
	s.record(value.Authorization, "denied", code, "", decision.MatchedDenyRuleIDs)
}

func (s *Server) recordRuntimeOutcome(operation agentv1.Operation, value operations.Plan, decision, detail string, _ int) {
	auditDecision := "executed"
	if decision != "allowed" {
		auditDecision = "rejected"
		if detail == "execution_result_unknown" {
			auditDecision = "ambiguous"
		}
	}
	s.record(value.Authorization, auditDecision, detail, operation.ApprovalID, nil)
}

func (s *Server) sudoApprovalMessage(ctx context.Context, grant grants.Grant, token string) approvalnotify.Approval {
	return approvalnotify.Project(ctx, "sudo", presenter.Presenter{Catalog: s.catalog}, grant, token)
}

func (s *Server) submitAgentOperation(ctx context.Context, client string, request agentv1.SubmitRequest) (agentv1.Operation, bool, error) {
	return s.operationRuntime.Submit(s.agentLifecycleContext(ctx), client, request)
}

func (s *Server) cancelAgentOperation(ctx context.Context, client, id string) (agentv1.Operation, error) {
	return s.operationRuntime.Cancel(ctx, client, id)
}

func (s *Server) agentLifecycleContext(fallback context.Context) context.Context {
	if s.lifecycleContext != nil {
		return s.lifecycleContext
	}
	return fallback
}

func (s *Server) startOperationRuntime(ctx context.Context) {
	s.workerOnce.Do(func() {
		workerContext, cancel := context.WithCancel(ctx)
		s.lifecycleContext, s.lifecycleCancel = workerContext, cancel
		s.operationRuntime.Start(workerContext)
	})
}

func sudoRuntimeGrantMode(preparation operations.Preparation) (corepolicy.GrantMode, error) {
	mode := corepolicy.GrantModeWindow
	if preparation.ReusedGrant != nil {
		mode = corepolicy.GrantMode(preparation.ReusedGrant.Metadata[grants.MetadataMode])
	} else if preparation.Decision.GrantPolicy != nil {
		mode = corepolicy.GrantMode(preparation.Decision.GrantPolicy.Mode)
	}
	if mode != corepolicy.GrantModeWindow && mode != corepolicy.GrantModeExecution {
		return "", errors.New("sudo command approval mode is invalid")
	}
	return mode, nil
}

func sudoRuntimeGrantBounds(preparation operations.Preparation, mode corepolicy.GrantMode) (time.Duration, time.Duration, usebudget.Limit, error) {
	if preparation.ReusedGrant != nil {
		return reusedSudoGrantBounds(*preparation.ReusedGrant, mode)
	}
	return newSudoGrantBounds(preparation.Decision.GrantPolicy, mode)
}

func reusedSudoGrantBounds(grant grants.Grant, mode corepolicy.GrantMode) (time.Duration, time.Duration, usebudget.Limit, error) {
	if mode != corepolicy.GrantModeWindow {
		return 0, 0, 0, errors.New("only sudo window grants may be reused")
	}
	duration := grant.Duration
	if duration <= 0 {
		duration = grant.RequestedDuration
	}
	return duration, grant.PendingTimeout, grant.MaxUses, nil
}

func newSudoGrantBounds(policy *corepolicy.GrantPolicy, mode corepolicy.GrantMode) (time.Duration, time.Duration, usebudget.Limit, error) {
	if policy == nil || corepolicy.GrantMode(policy.Mode) != mode {
		return 0, 0, 0, errors.New("sudo command policy approval mode is invalid")
	}
	if !validSudoPolicyDuration(policy) {
		return 0, 0, 0, errors.New("requested duration exceeds policy bounds")
	}
	if !validSudoPolicyUses(policy, mode) {
		return 0, 0, 0, errors.New("sudo execution policy must be single-use")
	}
	return time.Duration(policy.DefaultMinutes) * time.Minute, time.Duration(policy.RequestTTLMinutes) * time.Minute,
		policy.DefaultMaxUses, nil
}

func validSudoPolicyDuration(policy *corepolicy.GrantPolicy) bool {
	return policy.DefaultMinutes >= 1 && policy.DefaultMinutes <= policy.MaxMinutes
}

func validSudoPolicyUses(policy *corepolicy.GrantPolicy, mode corepolicy.GrantMode) bool {
	return mode != corepolicy.GrantModeExecution || policy.DefaultMaxUses == 1 && policy.MaxUses == 1
}
