// Package httpapi exposes the broker HTTP surface.
package httpapi

import (
	"time"

	"github.com/osolmaz/brokerkit/agent/v1"
	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/hfplan"
	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/operations"
	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/policy"
	"github.com/osolmaz/brokerkit/telemetry/audit"
)

func targetName(rt route) string {
	return string(rt.repoType) + "/" + rt.owner + "/" + rt.name
}

func (s *Server) recordOperationOutcome(operation agentv1.Operation, plan operations.Plan, decision, reason string, upstreamStatus int) {
	event := audit.Event{Client: operation.ClientID, Operation: operation.Operation, Target: operationPolicyTarget(plan.Policy),
		Decision: decision, Reason: reason, UpstreamStatus: upstreamStatus, PlanDigest: operation.PlanDigest}
	if operation.ApprovalID != "" {
		event.GrantID = operation.ApprovalID
		event.MatchedGrantRuleIDs = []string{operation.ApprovalID}
		if grant, err := s.grants.Get(operation.ApprovalID); err == nil {
			event.Approver = grant.DecidedBy
		}
	}
	if planPolicyEffect(plan) == "allow" {
		event.MatchedAllowRuleIDs = planPolicyRuleIDs(plan)
	} else if planPolicyEffect(plan) == "request" {
		event.MatchedRequestRuleIDs = planPolicyRuleIDs(plan)
	}
	s.recordAudit(event)
}

func planPolicyEffect(plan operations.Plan) string {
	return plan.PolicyDecision.Effect
}

func planPolicyRuleIDs(plan operations.Plan) []string {
	return append([]string(nil), plan.PolicyDecision.RuleIDs...)
}

func (s *Server) record(client, operation, target, decision, reason string, upstreamStatus int) {
	s.recordAudit(audit.Event{
		Client:         client,
		Operation:      operation,
		Target:         target,
		Decision:       decision,
		Reason:         reason,
		UpstreamStatus: upstreamStatus,
	})
}

func (s *Server) recordGrantUsed(client, operation, target string, upstreamStatus int, grantIDs []string) {
	planDigest := ""
	if len(grantIDs) > 0 {
		if grant, err := s.grants.Get(grantIDs[0]); err == nil {
			planDigest = grant.Metadata[hfplan.MetadataDigest]
		}
	}
	s.recordAudit(audit.Event{
		Client:              client,
		Operation:           operation,
		Target:              target,
		Decision:            audit.DecisionGrantUsed,
		Reason:              "operator grant used",
		UpstreamStatus:      upstreamStatus,
		MatchedGrantRuleIDs: grantIDs,
		GrantID:             firstString(grantIDs),
		PlanDigest:          planDigest,
	})
}

func (s *Server) recordPolicyDecision(client, operation, target, decision, reason string, upstreamStatus int, policyDecision policy.Decision) {
	s.recordAudit(audit.Event{
		Client:                client,
		Operation:             operation,
		Target:                target,
		Decision:              decision,
		Reason:                reason,
		UpstreamStatus:        upstreamStatus,
		MatchedDenyRuleIDs:    policyDecision.MatchedDenyRuleIDs,
		MatchedGrantRuleIDs:   policyDecision.MatchedGrantRuleIDs,
		MatchedAllowRuleIDs:   policyDecision.MatchedAllowRuleIDs,
		MatchedRequestRuleIDs: policyDecision.MatchedRequestRuleIDs,
		GrantID:               policyDecision.GrantID,
	})
}

func (s *Server) recordAudit(entry audit.Event) {
	entry.Broker = "hf-broker"
	_ = s.audit.Record(entry)
}

func firstString(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

// HealthClientTimeout is exported only for tests that need a stable
// short timeout without depending on config defaults.
const HealthClientTimeout = 2 * time.Second
