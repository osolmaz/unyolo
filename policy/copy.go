package policy

import (
	"maps"
	"slices"

	"github.com/osolmaz/brokerkit/internal/copyx"
)

func cloneRegistry(registry Registry) Registry {
	return Registry{
		Operations: cloneOperations(registry.Operations),
		Targets:    cloneTargets(registry.Targets),
		Attrs:      cloneAttrs(registry.Attrs),
	}
}

func cloneOperations(values map[string]OperationSpec) map[string]OperationSpec {
	if len(values) == 0 {
		return nil
	}
	out := make(map[string]OperationSpec, len(values))
	for name, spec := range values {
		out[name] = OperationSpec{
			TargetKinds: slices.Clone(spec.TargetKinds),
			Attrs:       slices.Clone(spec.Attrs),
			Grantable:   spec.Grantable,
			GrantMode:   spec.GrantMode,
		}
	}
	return out
}

func cloneTargets(values map[string]TargetSpec) map[string]TargetSpec {
	if len(values) == 0 {
		return nil
	}
	out := make(map[string]TargetSpec, len(values))
	for name, spec := range values {
		out[name] = TargetSpec{Fields: cloneFieldSpecs(spec.Fields)}
	}
	return out
}

func cloneFieldSpecs(values map[string]FieldSpec) map[string]FieldSpec {
	return maps.Clone(values)
}

func cloneAttrs(values map[string]AttrSpec) map[string]AttrSpec {
	return maps.Clone(values)
}

func cloneRules(rules []Rule) []Rule {
	if len(rules) == 0 {
		return nil
	}
	out := make([]Rule, len(rules))
	for index, rule := range rules {
		out[index] = cloneRule(rule)
	}
	return out
}

func cloneRule(rule Rule) Rule {
	return Rule{
		ID:          rule.ID,
		Effect:      rule.Effect,
		Clients:     slices.Clone(rule.Clients),
		Operations:  slices.Clone(rule.Operations),
		Targets:     cloneTargetMatchers(rule.Targets),
		Attrs:       clonePatternMap(rule.Attrs),
		GrantPolicy: cloneGrantPolicy(rule.GrantPolicy),
		Description: rule.Description,
	}
}

func cloneTargetMatchers(values []TargetMatcher) []TargetMatcher {
	if len(values) == 0 {
		return nil
	}
	out := make([]TargetMatcher, len(values))
	for index, matcher := range values {
		out[index] = TargetMatcher{Kind: matcher.Kind, Fields: clonePatternMap(matcher.Fields)}
	}
	return out
}

func clonePatternMap(values map[string][]string) map[string][]string {
	return copyx.StringSliceMap(values)
}

func cloneGrantPolicy(grantPolicy *GrantPolicy) *GrantPolicy {
	if grantPolicy == nil {
		return nil
	}
	cloned := *grantPolicy
	return &cloned
}
