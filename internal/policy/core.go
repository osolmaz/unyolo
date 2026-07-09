package policy

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	corepolicy "github.com/osolmaz/brokerkit/policy"
)

var errNoCompatibleTargets = errors.New("no compatible targets")

type coreDocument struct {
	Rules []coreRule `json:"rules"`
}

type coreRule struct {
	ID          string                  `json:"id"`
	Effect      Effect                  `json:"effect"`
	Clients     []string                `json:"clients"`
	Operations  []string                `json:"operations"`
	Targets     []map[string]string     `json:"targets"`
	Attrs       map[string][]string     `json:"attrs,omitempty"`
	GrantPolicy *corepolicy.GrantPolicy `json:"grant_policy,omitempty"`
}

func corePolicyJSON(scope Scope) ([]byte, error) {
	doc := coreDocument{Rules: make([]coreRule, 0, len(scope.Rules))}
	for _, rule := range scope.Rules {
		expanded, err := expandRule(rule)
		if err != nil {
			return nil, err
		}
		doc.Rules = append(doc.Rules, expanded...)
	}
	return json.Marshal(doc)
}

func expandRule(rule Rule) ([]coreRule, error) {
	ops, err := expandOperations(rule.Operations)
	if err != nil {
		return nil, err
	}
	out := make([]coreRule, 0, len(ops))
	for _, op := range ops {
		targets, err := coreTargetsForOperation(rule.Targets, op)
		if errors.Is(err, errNoCompatibleTargets) && operationWildcard(rule.Operations) {
			continue
		}
		if err != nil {
			return nil, err
		}
		attrs, err := attrsForOperation(rule.Attrs, op)
		if err != nil {
			return nil, err
		}
		out = append(out, coreRule{
			ID:          expandedRuleID(rule.ID, op, len(ops)),
			Effect:      rule.Effect,
			Clients:     rule.Clients,
			Operations:  []string{string(op)},
			Targets:     targets,
			Attrs:       attrs,
			GrantPolicy: grantPolicyForEffect(rule.Effect),
		})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("policy rule %q has no compatible operation targets", rule.ID)
	}
	return out, nil
}

func expandOperations(ops []Operation) ([]Operation, error) {
	if len(ops) == 0 {
		return nil, errors.New("policy rule operations must not be empty")
	}
	out := make([]Operation, 0, len(ops))
	seen := map[Operation]bool{}
	for _, op := range ops {
		expanded, err := expandOperation(op)
		if err != nil {
			return nil, err
		}
		for _, one := range expanded {
			if !seen[one] {
				seen[one] = true
				out = append(out, one)
			}
		}
	}
	return out, nil
}

func expandOperation(op Operation) ([]Operation, error) {
	if op == "*" {
		return allOperations(), nil
	}
	if _, ok := operationSpecs()[op]; !ok {
		return nil, fmt.Errorf("unsupported operation %q", op)
	}
	return []Operation{op}, nil
}

func coreTargetsForOperation(targets []Target, op Operation) ([]map[string]string, error) {
	if len(targets) == 0 {
		return nil, errors.New("policy rule targets must not be empty")
	}
	want := targetKindForOperation(op)
	out := make([]map[string]string, 0, len(targets))
	for _, target := range targets {
		if target.Kind != "*" && target.Kind != want {
			continue
		}
		out = append(out, coreTarget(target, want))
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%w for operation %q", errNoCompatibleTargets, op)
	}
	return out, nil
}

func coreTarget(target Target, kind string) map[string]string {
	if kind == "installation" {
		return map[string]string{"kind": "installation"}
	}
	return map[string]string{
		"kind":  "repo",
		"owner": target.Owner,
		"name":  target.Name,
	}
}

func attrsForOperation(attrs map[string][]string, op Operation) (map[string][]string, error) {
	if len(attrs) == 0 {
		return nil, nil
	}
	supported := operationAttrs(op)
	out := map[string][]string{}
	for key, values := range attrs {
		canonical, ok := canonicalAttr(key)
		if !ok {
			return nil, fmt.Errorf("unsupported attr key %q", key)
		}
		if !slices.Contains(supported, canonical) {
			return nil, fmt.Errorf("attr key %q is unsupported for operation %q", key, op)
		}
		out[canonical] = append(out[canonical], values...)
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

func canonicalAttr(key string) (string, bool) {
	switch strings.TrimSpace(key) {
	case "ref", "refs":
		return "ref", true
	case "base_ref", "base_refs":
		return "base_ref", true
	case "head_ref", "head_refs":
		return "head_ref", true
	case "path", "paths":
		return "path", true
	default:
		return "", false
	}
}

func expandedRuleID(id string, op Operation, count int) string {
	if count == 1 {
		return id
	}
	return id + "." + string(op)
}

func operationWildcard(ops []Operation) bool {
	return slices.Contains(ops, Operation("*"))
}

func grantPolicyForEffect(effect Effect) *corepolicy.GrantPolicy {
	if effect != EffectRequest {
		return nil
	}
	return &corepolicy.GrantPolicy{
		Mode:              "window",
		DefaultMinutes:    5,
		MaxMinutes:        10,
		RequestTTLMinutes: 5,
		DefaultMaxUses:    1,
		MaxUses:           1,
	}
}

func normalizeRequest(request Request) Request {
	return Request{
		Client:    strings.TrimSpace(request.Client),
		Operation: request.Operation,
		Target: Target{
			Kind:  strings.TrimSpace(request.Target.Kind),
			Owner: strings.TrimSpace(request.Target.Owner),
			Name:  strings.TrimSpace(request.Target.Name),
		},
		Attrs: normalizeRequestAttrs(request.Attrs),
	}
}

func normalizeRequestAttrs(attrs map[string]string) map[string]string {
	if len(attrs) == 0 {
		return nil
	}
	out := map[string]string{}
	for key, value := range attrs {
		canonical, ok := canonicalAttr(key)
		if ok {
			out[canonical] = value
		}
	}
	return out
}

func coreRequest(request Request) corepolicy.Request {
	return corepolicy.Request{
		Client:    request.Client,
		Operation: string(request.Operation),
		Target:    CoreTarget(request.Target),
		Attrs:     request.Attrs,
	}
}

func targetFields(target Target) map[string]string {
	if target.Kind != "repo" {
		return nil
	}
	return map[string]string{"owner": target.Owner, "name": target.Name}
}

func fromCoreDecision(decision corepolicy.Decision) Decision {
	switch decision.Effect {
	case corepolicy.EffectAllow:
		return Decision{
			Effect:         EffectAllow,
			Allowed:        true,
			Reason:         allowReason(decision),
			MatchedRuleIDs: matchedAllowIDs(decision),
			GrantID:        decision.GrantID,
		}
	case corepolicy.EffectDeny:
		if decision.Reason == "approval_required" {
			return Decision{Effect: EffectRequest, Reason: "grant required by policy", MatchedRuleIDs: originalRuleIDs(decision.MatchedRequestRuleIDs)}
		}
		return Decision{Effect: EffectDeny, Reason: denyReason(decision), MatchedRuleIDs: originalRuleIDs(decision.MatchedDenyRuleIDs)}
	case corepolicy.EffectRequest:
		return Decision{
			Effect:         EffectRequest,
			Reason:         "grant required by policy",
			MatchedRuleIDs: originalRuleIDs(decision.MatchedRequestRuleIDs),
			GrantPolicy:    decision.GrantPolicy,
		}
	default:
		return Decision{Effect: EffectNoMatch, Reason: "no matching policy rule"}
	}
}

func allowReason(decision corepolicy.Decision) string {
	if decision.GrantID != "" {
		return "allowed by grant"
	}
	return "allowed by policy"
}

func denyReason(decision corepolicy.Decision) string {
	if decision.Reason == "" || decision.Reason == "policy_denied" {
		return "denied by policy"
	}
	return decision.Reason
}

func matchedAllowIDs(decision corepolicy.Decision) []string {
	if len(decision.MatchedAllowRuleIDs) > 0 {
		return originalRuleIDs(decision.MatchedAllowRuleIDs)
	}
	return originalRuleIDs(decision.MatchedGrantRuleIDs)
}

func originalRuleIDs(ids []string) []string {
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		out = append(out, originalRuleID(id))
	}
	return out
}

func originalRuleID(id string) string {
	for _, op := range allOperations() {
		if original, ok := strings.CutSuffix(id, "."+string(op)); ok {
			return original
		}
	}
	return id
}
