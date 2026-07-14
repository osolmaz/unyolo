package httpapi

import (
	"strings"

	"github.com/osolmaz/brokerkit/agentv1"
	bkaudit "github.com/osolmaz/brokerkit/audit"
	"github.com/osolmaz/brokerkit/brokers/github/internal/operations"
	"github.com/osolmaz/brokerkit/brokers/github/internal/policy"
)

func operationPolicyTarget(auth operations.Authorization) string {
	values := []string{auth.TargetKind, firstValue(auth.TargetFields["owner"]), firstValue(auth.TargetFields["name"])}
	if id := firstValue(auth.TargetFields["id"]); id != "" {
		values = append(values, id)
	} else if number := firstValue(auth.TargetFields["number"]); number != "" {
		values = append(values, number)
	}
	return strings.Join(nonemptyStrings(values), "/")
}

func firstValue(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

func nonemptyStrings(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			out = append(out, value)
		}
	}
	return out
}

func (s *Server) recordOperationOutcome(operation agentv1.Operation, plan operations.Plan, decision, reason string, upstreamStatus int) {
	event := bkaudit.Event{
		Broker:         "gh-broker",
		Client:         operation.ClientID,
		Operation:      operation.Operation,
		Target:         operationPolicyTarget(plan.Authorization),
		Decision:       decision,
		Reason:         reason,
		UpstreamStatus: upstreamStatus,
		PlanDigest:     operation.PlanDigest,
	}
	if operation.ApprovalID != "" {
		event.GrantID = operation.ApprovalID
		event.MatchedGrantRuleIDs = []string{operation.ApprovalID}
		if grant, err := s.grants.Get(operation.ApprovalID); err == nil {
			event.Approver = grant.DecidedBy
		}
	}
	switch plan.PolicyDecision.Effect {
	case string(policy.EffectAllow):
		event.MatchedAllowRuleIDs = append([]string(nil), plan.PolicyDecision.RuleIDs...)
	case string(policy.EffectRequest):
		event.MatchedRequestRuleIDs = append([]string(nil), plan.PolicyDecision.RuleIDs...)
	}
	s.recordOperationAudit(event)
}

func (s *Server) recordOperationPolicyDecision(client, operation, target, decision, reason string, upstreamStatus int, policyDecision policy.Decision) {
	event := bkaudit.Event{
		Broker:         "gh-broker",
		Client:         client,
		Operation:      operation,
		Target:         target,
		Decision:       decision,
		Reason:         reason,
		UpstreamStatus: upstreamStatus,
		MatchedRuleIDs: policyDecision.MatchedRuleIDs,
		GrantID:        policyDecision.GrantID,
	}
	switch policyDecision.Effect {
	case policy.EffectAllow:
		event.MatchedAllowRuleIDs = append([]string(nil), policyDecision.MatchedRuleIDs...)
	case policy.EffectRequest:
		event.MatchedRequestRuleIDs = append([]string(nil), policyDecision.MatchedRuleIDs...)
	case policy.EffectDeny:
		event.MatchedDenyRuleIDs = append([]string(nil), policyDecision.MatchedRuleIDs...)
	case policy.EffectNoMatch:
	}
	s.recordOperationAudit(event)
}

func (s *Server) recordOperationAudit(event bkaudit.Event) {
	if s.auditWriter == nil {
		return
	}
	_ = s.auditWriter.Record(event)
}
