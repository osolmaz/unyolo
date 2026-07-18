package policy

import (
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	corepolicy "github.com/osolmaz/brokerkit/policy"
	"github.com/osolmaz/brokerkit/usebudget"
)

type coreView uint8

const (
	coreViewNormal coreView = iota
	coreViewSupport
	coreViewDiscovery
)

type corePolicies struct {
	normal    *corepolicy.Policy
	support   *corepolicy.Policy
	discovery *corepolicy.Policy
}

type coreDocument struct {
	Rules []coreRule `json:"rules"`
}

type coreRule struct {
	ID          string                  `json:"id"`
	Effect      string                  `json:"effect"`
	Clients     []string                `json:"clients"`
	Operations  []string                `json:"operations"`
	Targets     []map[string]any        `json:"targets"`
	Attrs       map[string][]string     `json:"attrs,omitempty"`
	GrantPolicy *corepolicy.GrantPolicy `json:"grant_policy,omitempty"`
}

// AuthorizationRegistry returns HF's provider-owned policy vocabulary.
func AuthorizationRegistry() corepolicy.Registry { return hfRegistry() }

// AuthorizationRequest projects an HF request into the shared policy model.
func AuthorizationRequest(request Request) corepolicy.Request {
	return coreRequestFromHF(request, coreViewNormal)
}

// DecideAuthorization evaluates a shared authorization request against HF's
// normal policy view.
func (p Policy) DecideAuthorization(request corepolicy.Request, options corepolicy.DecisionOptions) corepolicy.Decision {
	return p.coreForView(coreViewNormal).Decide(request, options)
}

// AuthorizationDecision maps a shared decision back to HF's audit model.
func (p Policy) AuthorizationDecision(decision corepolicy.Decision) Decision {
	return p.decisionFromCore(decision)
}

// AuthorizationGrants projects active HF grant rules into shared policy grants.
func AuthorizationGrants(rules []Rule) []corepolicy.Grant { return coreGrants(rules, coreViewNormal) }

func (p *Policy) initializeCore() error {
	ids := make(map[string]string)
	normal, err := p.buildCorePolicy(coreViewNormal, ids)
	if err != nil {
		return fmt.Errorf("build brokerkit policy: %w", err)
	}
	support, err := p.buildCorePolicy(coreViewSupport, ids)
	if err != nil {
		return fmt.Errorf("build brokerkit support policy: %w", err)
	}
	discovery, err := p.buildCorePolicy(coreViewDiscovery, ids)
	if err != nil {
		return fmt.Errorf("build brokerkit discovery policy: %w", err)
	}
	p.core = &corePolicies{normal: normal, support: support, discovery: discovery}
	p.coreRuleIDs = ids
	return nil
}

func (p Policy) buildCorePolicy(view coreView, ids map[string]string) (*corepolicy.Policy, error) {
	document := coreDocument{Rules: []coreRule{}}
	for _, rule := range p.rules {
		for _, operation := range rule.Operations {
			converted, ok := coreRuleForOperation(rule, operation, view)
			if !ok {
				continue
			}
			ids[converted.ID] = rule.ID
			document.Rules = append(document.Rules, converted)
		}
	}
	body, err := json.Marshal(document)
	if err != nil {
		return nil, err
	}
	return corepolicy.Parse(body, hfRegistry())
}

func coreRuleForOperation(rule Rule, operation Operation, view coreView) (coreRule, bool) {
	if view == coreViewDiscovery && operationTargetKind(operation) != KindRepo {
		return coreRule{}, false
	}
	if view == coreViewDiscovery && rule.Effect == EffectDeny && len(rule.Attrs) > 0 {
		return coreRule{}, false
	}
	targets := coreTargets(rule, operation, view)
	if len(targets) == 0 {
		return coreRule{}, false
	}
	return coreRule{
		ID:          coreRuleID(rule.ID, operation),
		Effect:      string(rule.Effect),
		Clients:     coreClientPatterns(rule.Clients),
		Operations:  []string{string(operation)},
		Targets:     targets,
		Attrs:       coreRuleAttrs(rule, view),
		GrantPolicy: coreGrantPolicyForView(rule.GrantPolicy, operation, view),
	}, true
}

func coreClientPatterns(clients []string) []string {
	out := make([]string, len(clients))
	replacer := strings.NewReplacer(`\`, `\\`, `*`, `\*`, `?`, `\?`, `[`, `\[`)
	for index, client := range clients {
		if client == "*" {
			out[index] = client
			continue
		}
		out[index] = replacer.Replace(client)
	}
	return out
}

func coreTargets(rule Rule, operation Operation, view coreView) []map[string]any {
	targets := make([]map[string]any, 0, len(rule.Targets))
	for _, target := range rule.Targets {
		if view == coreViewSupport && rule.Effect == EffectDeny && len(target.Refs) > 0 {
			continue
		}
		if view == coreViewDiscovery && !discoveryTargetEligible(rule, target) {
			continue
		}
		targets = append(targets, coreTargetMatcher(target, operation, view))
	}
	return targets
}

func discoveryTargetEligible(rule Rule, target TargetMatcher) bool {
	if target.Kind != KindRepo {
		return false
	}
	if rule.Effect != EffectDeny {
		return true
	}
	return len(target.Refs) == 0 && len(target.Paths) == 0 && len(target.Visibility) == 0
}

func coreTargetMatcher(target TargetMatcher, operation Operation, view coreView) map[string]any {
	out := map[string]any{"kind": string(target.Kind), "owner": target.Owner, "name": target.Name}
	if target.Kind == KindRepo {
		addCoreRepoMatcherFields(out, target, operation, view)
		return out
	}
	if target.Kind == KindInference {
		return out
	}
	if target.Kind == KindBucket {
		addCoreBucketMatcherFields(out, target, operation)
	}
	return out
}

func addCoreRepoMatcherFields(out map[string]any, target TargetMatcher, operation Operation, view coreView) {
	out["type"] = nonEmpty(string(target.Type), "*")
	addCoreRepoMatcherRefs(out, target, operation, view)
	if view == coreViewDiscovery {
		return
	}
	addCoreRepoMatcherMetadata(out, target)
}

func addCoreRepoMatcherRefs(out map[string]any, target TargetMatcher, operation Operation, view coreView) {
	if view == coreViewNormal && operationUsesRefs(operation) && len(target.Refs) > 0 {
		out["refs"] = target.Refs
	}
}

func addCoreRepoMatcherMetadata(out map[string]any, target TargetMatcher) {
	if len(target.Paths) > 0 {
		out["paths"] = target.Paths
	}
	if len(target.Visibility) > 0 {
		out["visibility"] = target.Visibility
	}
}

func addCoreBucketMatcherFields(out map[string]any, target TargetMatcher, operation Operation) {
	if len(target.Keys) > 0 {
		out["keys"] = target.Keys
	}
	if bucketOperationMutatesObjects(operation) && target.SnapshotPrefix != "" {
		out["mutable_keys"] = target.SnapshotPrefix
	}
}

func coreRuleAttrs(rule Rule, view coreView) map[string][]string {
	if view == coreViewDiscovery {
		return nil
	}
	out := make(map[string][]string, len(rule.Attrs))
	for key, constraint := range rule.Attrs {
		if view == coreViewSupport && rule.Effect != EffectDeny && key == "ref_change" {
			continue
		}
		if constraint.Number != nil {
			out[key] = []string{strconv.FormatInt(*constraint.Number, 10)}
		} else {
			out[key] = slices.Clone(constraint.Values)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func coreGrantPolicy(value *GrantPolicy) *corepolicy.GrantPolicy {
	if value == nil {
		return nil
	}
	return &corepolicy.GrantPolicy{
		Mode:              string(value.Mode),
		DefaultMinutes:    value.DefaultMinutes,
		MaxMinutes:        value.MaxMinutes,
		RequestTTLMinutes: value.RequestTTLMinutes,
		DefaultMaxUses:    value.DefaultMaxUses,
		MaxUses:           value.MaxUses,
	}
}

func coreGrantPolicyForView(value *GrantPolicy, operation Operation, view coreView) *corepolicy.GrantPolicy {
	if value == nil || view == coreViewNormal {
		return coreGrantPolicy(value)
	}
	mode := operations[operation].mode
	maxUses := MaxGrantUses
	if mode == GrantModeExecution {
		maxUses = 1
	}
	return &corepolicy.GrantPolicy{
		Mode:              string(mode),
		DefaultMinutes:    DefaultGrantMinutes,
		MaxMinutes:        MaxGrantMinutes,
		RequestTTLMinutes: DefaultRequestTTL,
		DefaultMaxUses:    1,
		MaxUses:           usebudget.Limit(maxUses),
	}
}

func coreRuleID(id string, operation Operation) string {
	return id + "@" + string(operation)
}

func operationUsesRefs(operation Operation) bool {
	return refScopedOperations[operation]
}

// OperationUsesRefs reports whether ref constraints participate in policy
// matching for an operation.
func OperationUsesRefs(operation Operation) bool {
	return operationUsesRefs(operation)
}

func bucketOperationMutatesObjects(operation Operation) bool {
	return operation == OpBucketObjectWrite || operation == OpBucketObjectDel ||
		operation == "bucket.batch.apply" || operation == "bucket.sync.apply" || operation == "bucket.object.delete"
}

func hfRegistry() corepolicy.Registry {
	coreOperations := make(map[string]corepolicy.OperationSpec, len(operations))
	targets := map[string]corepolicy.TargetSpec{
		string(KindRepo): {Fields: map[string]corepolicy.FieldSpec{
			"type":       {Required: true},
			"owner":      {Required: true},
			"name":       {Required: true},
			"refs":       {Match: corepolicy.MatchPathGlob},
			"paths":      {Match: corepolicy.MatchRecursivePathGlob},
			"visibility": {Match: corepolicy.MatchAnyGlob},
		}},
		string(KindBucket): {Fields: map[string]corepolicy.FieldSpec{
			"owner":        {Required: true},
			"name":         {Required: true},
			"keys":         {Match: corepolicy.MatchRecursivePathGlob},
			"mutable_keys": {Match: corepolicy.MatchPathOutsidePrefix},
		}},
		string(KindInference): {Fields: ownerNameTargetFields()},
	}
	for operation, info := range operations {
		kind := string(operationTargetKind(operation))
		if _, ok := targets[kind]; !ok {
			targets[kind] = corepolicy.TargetSpec{Fields: ownerNameTargetFields()}
		}
		spec := corepolicy.OperationSpec{
			TargetKinds: []string{kind},
			Attrs:       KnownAttributeNames(),
			Grantable:   info.mode != GrantModeNone,
		}
		if spec.Grantable {
			spec.GrantModes = []corepolicy.GrantMode{corepolicy.GrantModeWindow, corepolicy.GrantModeExecution}
		}
		if info.mode == GrantModeExecution {
			spec.GrantMode = corepolicy.GrantModeExecution
		}
		coreOperations[string(operation)] = spec
	}
	return corepolicy.Registry{
		Operations: coreOperations,
		Targets:    targets,
		Attrs:      hfAttributeSpecs(),
	}
}

func hfAttributeSpecs() map[string]corepolicy.AttrSpec {
	specs := make(map[string]corepolicy.AttrSpec, len(knownAttrs))
	for name := range knownAttrs {
		specs[name] = corepolicy.AttrSpec{GrantMatch: corepolicy.MatchAnyGlob, GrantMayOmit: true}
	}
	maximum := corepolicy.AttrSpec{Match: corepolicy.MatchIntegerMaximum, GrantMatch: corepolicy.MatchIntegerMaximum, GrantMayOmit: true}
	for _, name := range []string{"max_bytes", "max_hosts", "num_hosts", "sleep_time_seconds", "warm_up"} {
		specs[name] = maximum
	}
	return specs
}

func ownerNameTargetFields() map[string]corepolicy.FieldSpec {
	return map[string]corepolicy.FieldSpec{"owner": {Required: true}, "name": {Required: true}}
}

func (p Policy) decideCore(req Request, grants []Rule, now time.Time, grantRequest bool, view coreView) Decision {
	if _, ok := operations[req.Operation]; !ok {
		return Decision{Effect: EffectDeny, Reason: "invalid_operation"}
	}
	if err := validatePolicyRequestTarget(req); err != nil {
		return Decision{Effect: EffectDeny, Reason: "invalid_target"}
	}
	coreRequest := coreRequestFromHF(req, view)
	options := corepolicy.DecisionOptions{
		ForGrantRequest: grantRequest,
		Now:             now,
		ActiveGrants:    coreGrants(grants, view),
	}
	decision := p.coreForView(view).Decide(coreRequest, options)
	return p.decisionFromCore(decision)
}

func (p Policy) coreForView(view coreView) *corepolicy.Policy {
	switch view {
	case coreViewSupport:
		return p.core.support
	case coreViewDiscovery:
		return p.core.discovery
	default:
		return p.core.normal
	}
}

func coreRequestFromHF(req Request, view coreView) corepolicy.Request {
	return corepolicy.Request{
		Client:    req.Client,
		Operation: string(req.Operation),
		Target:    coreTargetFromHF(req.Target, req.Operation, view),
		Attrs:     coreAttrsFromHF(req.Attrs, view),
	}
}

func coreTargetFromHF(target Target, operation Operation, view coreView) corepolicy.Target {
	fields := map[string][]string{"owner": {target.Owner}, "name": {target.Name}}
	switch target.Kind {
	case KindRepo:
		addCoreRepoRequestFields(fields, target, operation, view)
	case KindBucket:
		addCoreBucketRequestFields(fields, target, operation)
	case KindInference:
	}
	return corepolicy.Target{Kind: string(target.Kind), Fields: fields}
}

func addCoreRepoRequestFields(fields map[string][]string, target Target, operation Operation, view coreView) {
	fields["type"] = []string{string(target.Type)}
	addCoreRepoRequestRefs(fields, target, operation, view)
	if view == coreViewDiscovery {
		return
	}
	addCoreRepoRequestMetadata(fields, target)
}

func addCoreRepoRequestRefs(fields map[string][]string, target Target, operation Operation, view coreView) {
	if view == coreViewNormal && operationUsesRefs(operation) && len(target.Refs) > 0 {
		fields["refs"] = slices.Clone(target.Refs)
	}
}

func addCoreRepoRequestMetadata(fields map[string][]string, target Target) {
	if len(target.Paths) > 0 {
		fields["paths"] = slices.Clone(target.Paths)
	}
	if len(target.Visibility) > 0 {
		fields["visibility"] = slices.Clone(target.Visibility)
	}
}

func addCoreBucketRequestFields(fields map[string][]string, target Target, operation Operation) {
	if len(target.Keys) == 0 {
		return
	}
	fields["keys"] = slices.Clone(target.Keys)
	if bucketOperationMutatesObjects(operation) {
		fields["mutable_keys"] = slices.Clone(target.Keys)
	}
}

func coreAttrsFromHF(attrs map[string]any, view coreView) map[string][]string {
	out := make(map[string][]string, len(attrs))
	for key, value := range attrs {
		if view != coreViewNormal && key == "ref_change" {
			continue
		}
		if canonical := canonicalCoreAttr(key, value); canonical != "" {
			out[key] = []string{canonical}
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func canonicalCoreAttr(key string, value any) string {
	switch key {
	case "max_bytes", "max_hosts", "num_hosts", "sleep_time_seconds", "warm_up":
		number, ok := int64Value(value)
		if !ok {
			return "invalid"
		}
		return strconv.FormatInt(number, 10)
	}
	if !knownAttrs[key] {
		return ""
	}
	text, ok := value.(string)
	if !ok || text == "" {
		return "invalid"
	}
	return text
}

func coreGrants(rules []Rule, view coreView) []corepolicy.Grant {
	out := make([]corepolicy.Grant, 0, len(rules))
	for _, rule := range rules {
		if !rule.Generated || rule.Effect != EffectAllow || len(rule.Operations) != 1 || len(rule.Targets) != 1 {
			continue
		}
		target := concreteTargetFromMatcher(rule.Targets[0])
		out = append(out, corepolicy.Grant{
			ID:        nonEmpty(rule.GrantID, rule.ID),
			Client:    corepolicy.FirstValue(rule.Clients),
			Operation: string(rule.Operations[0]),
			Target:    coreTargetFromHF(target, rule.Operations[0], view),
			Attrs:     coreAttrsFromConstraints(rule.Attrs, view),
			ExpiresAt: rule.ExpiresAt,
			UsesLeft:  rule.UsesLeft,
			Unlimited: rule.Unlimited,
		})
	}
	return out
}

func concreteTargetFromMatcher(target TargetMatcher) Target {
	return Target{
		Kind: target.Kind, Type: target.Type, Owner: target.Owner, Name: target.Name,
		Refs: slices.Clone(target.Refs), Paths: slices.Clone(target.Paths),
		Visibility: slices.Clone(target.Visibility), Keys: slices.Clone(target.Keys),
	}
}

func coreAttrsFromConstraints(attrs map[string]AttrConstraint, view coreView) map[string][]string {
	if view == coreViewDiscovery {
		return nil
	}
	out := make(map[string][]string, len(attrs))
	for key, constraint := range attrs {
		if view == coreViewSupport && key == "ref_change" {
			continue
		}
		if constraint.Number != nil {
			out[key] = []string{strconv.FormatInt(*constraint.Number, 10)}
		} else {
			out[key] = slices.Clone(constraint.Values)
		}
	}
	return out
}

func (p Policy) decisionFromCore(value corepolicy.Decision) Decision {
	requestRuleIDs := p.originalRuleIDs(value.MatchedRequestRuleIDs)
	return Decision{
		Effect:                Effect(value.Effect),
		Reason:                value.Reason,
		MatchedDenyRuleIDs:    p.originalRuleIDs(value.MatchedDenyRuleIDs),
		MatchedGrantRuleIDs:   slices.Clone(value.MatchedGrantRuleIDs),
		MatchedAllowRuleIDs:   p.originalRuleIDs(value.MatchedAllowRuleIDs),
		MatchedRequestRuleIDs: requestRuleIDs,
		GrantID:               value.GrantID,
		GrantPolicy:           p.originalGrantPolicy(requestRuleIDs, value.GrantPolicy),
	}
}

func (p Policy) originalGrantPolicy(ruleIDs []string, fallback *corepolicy.GrantPolicy) *GrantPolicy {
	for _, id := range ruleIDs {
		for _, rule := range p.rules {
			if rule.ID == id && rule.GrantPolicy != nil {
				policy := *rule.GrantPolicy
				return &policy
			}
		}
	}
	return grantPolicyFromCore(fallback)
}

func (p Policy) originalRuleIDs(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		original := p.coreRuleIDs[value]
		if original == "" {
			original = value
		}
		if !slices.Contains(out, original) {
			out = append(out, original)
		}
	}
	return out
}

func grantPolicyFromCore(value *corepolicy.GrantPolicy) *GrantPolicy {
	if value == nil {
		return nil
	}
	return &GrantPolicy{
		Mode:              GrantMode(value.Mode),
		DefaultMinutes:    value.DefaultMinutes,
		MaxMinutes:        value.MaxMinutes,
		RequestTTLMinutes: value.RequestTTLMinutes,
		DefaultMaxUses:    value.DefaultMaxUses,
		MaxUses:           value.MaxUses,
	}
}
