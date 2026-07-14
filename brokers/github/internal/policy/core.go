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
			GrantPolicy: grantPolicyForEffect(rule.Effect, op),
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
	op = canonicalOperation(op)
	if op == "*" {
		return allOperations(), nil
	}
	if expanded, ok := expandFamilyOperation(op); ok {
		return expanded, nil
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
	result := map[string]string{"kind": kind}
	if kind == "installation" && target.ID == 0 && strings.TrimSpace(target.NodeID) == "" {
		return result
	}
	for field, values := range targetFields(target) {
		if len(values) > 0 {
			result[field] = values[0]
		}
	}
	return result
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
	case "actor_id", "actor_login", "arguments_digest", "content_digest", "credential_kind", "environment", "label", "merge_method",
		"credential_slot", "permission", "ref_change", "release_state", "resource_id", "role", "visibility", "workflow", "workflow_ref":
		return strings.TrimSpace(key), true
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

func grantPolicyForEffect(effect Effect, operation Operation) *corepolicy.GrantPolicy {
	if effect != EffectRequest {
		return nil
	}
	mode := corepolicy.GrantModeWindow
	if operationSpecs()[canonicalOperation(operation)].GrantMode == corepolicy.GrantModeExecution {
		mode = corepolicy.GrantModeExecution
	}
	return &corepolicy.GrantPolicy{
		Mode:              string(mode),
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
		Operation: canonicalOperation(request.Operation),
		Target: Target{
			Kind:   strings.TrimSpace(request.Target.Kind),
			ID:     request.Target.ID,
			NodeID: strings.TrimSpace(request.Target.NodeID),
			Owner:  strings.TrimSpace(request.Target.Owner),
			Repo:   strings.TrimSpace(request.Target.Repo),
			Name:   strings.TrimSpace(request.Target.Name),
			Number: request.Target.Number,
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
		Attrs:     corepolicy.SingletonValues(request.Attrs),
	}
}

func targetFields(target Target) map[string][]string {
	fields := map[string][]string{}
	if target.ID > 0 {
		fields["id"] = []string{fmt.Sprintf("%d", target.ID)}
	}
	if target.Number > 0 {
		fields["number"] = []string{fmt.Sprintf("%d", target.Number)}
	}
	for name, value := range map[string]string{"node_id": target.NodeID, "owner": target.Owner, "repo": target.Repo, "name": target.Name} {
		if value = strings.TrimSpace(value); value != "" {
			fields[name] = []string{value}
		}
	}
	if len(fields) == 0 {
		return nil
	}
	return fields
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

// mutate4go-manifest-begin
// {"version":1,"tested_at":"2026-07-10T06:09:36+08:00","module_hash":"71ce73884912063125b96aadefe490ab64d0dd2dd78f8d2e0026488850d92668","functions":[{"id":"func/corePolicyJSON","name":"corePolicyJSON","line":29,"end_line":39,"hash":"75ac59ebb2adea982e5b3b740fe39b12f15b18af8fbb8fc13ef24ec2186a910b"},{"id":"func/expandRule","name":"expandRule","line":41,"end_line":73,"hash":"282532352a4a2e5c8a0f68b7f84a9c33e2989aa1a0c19811e3f0afa1869afa92"},{"id":"func/expandOperations","name":"expandOperations","line":75,"end_line":94,"hash":"8c42da765c37fff933193f91cea9ef8b6f3472b2d25edc9cb6e4c30e0d995e2c"},{"id":"func/expandOperation","name":"expandOperation","line":96,"end_line":104,"hash":"8649e89ab24fb02c438e6c0502e7384abc0a31e39f86411ecc845641c6ba5454"},{"id":"func/coreTargetsForOperation","name":"coreTargetsForOperation","line":106,"end_line":122,"hash":"f57f9e7383ac55979c3a0926824bbc0652b7e9202a7c99b250c6f7f38ca8a961"},{"id":"func/coreTarget","name":"coreTarget","line":124,"end_line":133,"hash":"1e889adefd98a73631f16dcc7a0ed12bdd032574a043a012b1986eab277c86ce"},{"id":"func/attrsForOperation","name":"attrsForOperation","line":135,"end_line":155,"hash":"27c66875001d3963363da328d57a3bd1dc0e909f77bc46e46ea93a213f611ab1"},{"id":"func/canonicalAttr","name":"canonicalAttr","line":157,"end_line":170,"hash":"e8f21105411f05f8d9d26bc6deea9dbc4f370950281e78f57ac2876f62057d43"},{"id":"func/expandedRuleID","name":"expandedRuleID","line":172,"end_line":177,"hash":"377c01402199519406f09ff1639be1a423ec6503778beb7fc9d020a9a59709ee"},{"id":"func/operationWildcard","name":"operationWildcard","line":179,"end_line":181,"hash":"3eab895a279d0a539fa868a8c6ee633d605d190ddbe7a7f2f0a3c7b299eceb5c"},{"id":"func/grantPolicyForEffect","name":"grantPolicyForEffect","line":183,"end_line":195,"hash":"1072406a93b4f1409403d63b6a1bc209f7c4324efdc1bb3e1a7b3f6baf2f6380"},{"id":"func/normalizeRequest","name":"normalizeRequest","line":197,"end_line":208,"hash":"cf8a05781436b6a87fe0722309272cd195797b3df3390d48084213d667fdb668"},{"id":"func/normalizeRequestAttrs","name":"normalizeRequestAttrs","line":210,"end_line":222,"hash":"c74bb56b253f2e91274195c060d7afdccec492e20de9f4294709a1181bf3896d"},{"id":"func/coreRequest","name":"coreRequest","line":224,"end_line":231,"hash":"0cd7a6d32cb88959ab891b221cd20885ab2dcf360dfda39a53a65d1be5b99849"},{"id":"func/targetFields","name":"targetFields","line":233,"end_line":238,"hash":"f0eb1a9d86d16adff72b1b734ff0aa804f6647c599d1a6cbcf0d2c02d0ba1c09"},{"id":"func/fromCoreDecision","name":"fromCoreDecision","line":240,"end_line":265,"hash":"6bd138bb4b4ffc19f0221ed7d68ba55f194297547ebef8a4b6e9307ab71810e4"},{"id":"func/allowReason","name":"allowReason","line":267,"end_line":272,"hash":"ccce53112bd5bfd4d509744543804be5e4ea4f29a94cd0b7120498a268061166"},{"id":"func/denyReason","name":"denyReason","line":274,"end_line":279,"hash":"24dd97a41f36bb98f9a9f1eb769d44c0d165ddd2acb852a206ae6bc391957b63"},{"id":"func/matchedAllowIDs","name":"matchedAllowIDs","line":281,"end_line":286,"hash":"ea89bdb1916720e424e153543a1d1ee60c7ebd93836d5d6b1de5035770569daa"},{"id":"func/originalRuleIDs","name":"originalRuleIDs","line":288,"end_line":294,"hash":"ed65e4c61c664a260dcf16df80e7e75c143261fc3ba06aefffa29a550287b6b8"},{"id":"func/originalRuleID","name":"originalRuleID","line":296,"end_line":303,"hash":"e429a664f872c162b42c0c9812e1ce2aa37cd87b135fb7e00afe65d2396c039b"}]}
// mutate4go-manifest-end
