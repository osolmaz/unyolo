package routes

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/osolmaz/brokerkit/agentapi"
	"github.com/osolmaz/brokerkit/agentv1"
	"github.com/osolmaz/brokerkit/approvalnotify"
	bkauthorization "github.com/osolmaz/brokerkit/authorization"
	"github.com/osolmaz/brokerkit/brokers/sudo/internal/operations"
	"github.com/osolmaz/brokerkit/brokers/sudo/internal/plan"
	"github.com/osolmaz/brokerkit/brokers/sudo/internal/presenter"
	"github.com/osolmaz/brokerkit/grants"
	"github.com/osolmaz/brokerkit/operationruntime"
	corepolicy "github.com/osolmaz/brokerkit/policy"
	"github.com/osolmaz/brokerkit/state"
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

func (s *Server) prepareRuntimePlan(preparation operations.Preparation) (bkauthorization.GrantIntent, error) {
	if preparation.Direct {
		return bkauthorization.GrantIntent{}, errors.New("sudo operations require explicit approval")
	}
	duration, pending, err := grantBounds(preparation.Decision.GrantPolicy, 0)
	if err != nil {
		return bkauthorization.GrantIntent{}, err
	}
	request := grants.Request{Client: preparation.Client, ClientRequestID: preparation.OperationID,
		Operation: preparation.DescriptorName, Target: preparation.Core.Target, Attrs: preparation.Core.Attrs,
		Reason: preparation.Reason, Duration: duration, PendingTimeout: pending, MaxUses: 1, MaxUsesSpecified: true}
	identity, err := s.identities.Lookup(preparation.Plan.Resolved.TargetUser)
	if err != nil {
		return bkauthorization.GrantIntent{}, errors.New("target user cannot be resolved")
	}
	command, err := plan.Build(request, preparation.Plan.Resolved, identity, preparation.CreatedAt)
	if err != nil {
		return bkauthorization.GrantIntent{}, err
	}
	immutable, err := s.plans.PrepareBind(&request, command)
	if err != nil {
		return bkauthorization.GrantIntent{}, err
	}
	return bkauthorization.GrantIntent{Mode: corepolicy.GrantModeExecution, Authorization: preparation.Core,
		Request: request, Plan: immutable}, nil
}

func (s *Server) loadRuntimePlan(operation agentv1.Operation, _ operations.Adapter) (operations.Plan, error) {
	if operation.ApprovalID == "" {
		return operations.Plan{}, errors.New("sudo operation has no approval")
	}
	grant, err := s.grants.Get(operation.ApprovalID)
	if err != nil || grant.Metadata[plan.MetadataDigest] != operation.PlanDigest {
		return operations.Plan{}, errors.New("sudo approval plan binding is invalid")
	}
	command, err := s.validator.ValidateGrant(grant)
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

func grantBounds(policy *corepolicy.GrantPolicy, minutes int) (time.Duration, time.Duration, error) {
	if policy == nil || policy.Mode != string(corepolicy.GrantModeExecution) || policy.DefaultMaxUses != 1 || policy.MaxUses != 1 {
		return 0, 0, errors.New("sudo command policy must use one-shot execution grants")
	}
	if minutes == 0 {
		minutes = policy.DefaultMinutes
	}
	if minutes < 1 || minutes > policy.MaxMinutes {
		return 0, 0, errors.New("requested duration exceeds policy bounds")
	}
	return time.Duration(minutes) * time.Minute, time.Duration(policy.RequestTTLMinutes) * time.Minute, nil
}
