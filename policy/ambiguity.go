package policy

import (
	"fmt"
	"path"
	"slices"
	"strings"
)

func validateRequestRuleAmbiguity(rules []Rule, registry Registry) error {
	for leftIndex, left := range rules {
		if left.Effect != EffectRequest {
			continue
		}
		if err := validateRequestRuleAgainstLaterRules(left, rules[leftIndex+1:], registry); err != nil {
			return err
		}
	}
	return nil
}

func validateRequestRuleAgainstLaterRules(left Rule, later []Rule, registry Registry) error {
	for _, right := range later {
		if right.Effect != EffectRequest || grantPoliciesEqual(left.GrantPolicy, right.GrantPolicy) {
			continue
		}
		if requestRulesMayOverlap(left, right, registry) {
			return fmt.Errorf("request rules %q and %q overlap with different grant policies", left.ID, right.ID)
		}
	}
	return nil
}

func requestRulesMayOverlap(left Rule, right Rule, registry Registry) bool {
	if !valueListsMayOverlap(left.Clients, right.Clients, patternsMayOverlap) {
		return false
	}
	for _, operation := range left.Operations {
		if slices.Contains(right.Operations, operation) &&
			targetMatchersMayOverlap(left.Targets, right.Targets, registry) &&
			attrsMayOverlap(left.Attrs, right.Attrs, registry.Operations[operation].Attrs, registry) {
			return true
		}
	}
	return false
}

func grantPoliciesEqual(left *GrantPolicy, right *GrantPolicy) bool {
	if left == nil || right == nil {
		return left == right
	}
	return *left == *right
}

func targetMatchersMayOverlap(left []TargetMatcher, right []TargetMatcher, registry Registry) bool {
	for _, leftTarget := range left {
		for _, rightTarget := range right {
			if leftTarget.Kind == rightTarget.Kind && patternMapsMayOverlap(leftTarget.Fields, rightTarget.Fields, registry.Targets[leftTarget.Kind]) {
				return true
			}
		}
	}
	return false
}

func attrsMayOverlap(left map[string][]string, right map[string][]string, relevantAttrs []string, registry Registry) bool {
	for _, attr := range relevantAttrs {
		leftValues, leftOK := left[attr]
		rightValues, rightOK := right[attr]
		if leftOK && rightOK && !matchValuesMayOverlap(leftValues, rightValues, registry.Attrs[attr].Match) {
			return false
		}
	}
	return true
}

func patternMapsMayOverlap(left map[string][]string, right map[string][]string, spec TargetSpec) bool {
	for field, leftValues := range left {
		rightValues, ok := right[field]
		if ok && !matchValuesMayOverlap(leftValues, rightValues, spec.Fields[field].Match) {
			return false
		}
	}
	return true
}

func matchValuesMayOverlap(left []string, right []string, mode MatchMode) bool {
	switch defaultedMatchMode(mode) {
	case MatchIntegerMaximum:
		return true
	case MatchPathGlob:
		return valueListsMayOverlap(left, right, pathValuesMayOverlap)
	default:
		return valueListsMayOverlap(left, right, patternsMayOverlap)
	}
}

func valueListsMayOverlap(left []string, right []string, match func(string, string) bool) bool {
	for _, leftValue := range left {
		for _, rightValue := range right {
			if match(leftValue, rightValue) {
				return true
			}
		}
	}
	return false
}

func pathValuesMayOverlap(left string, right string) bool {
	if left == right {
		return true
	}
	leftGlob := hasGlobMeta(left)
	rightGlob := hasGlobMeta(right)
	if !leftGlob {
		return pathPatternsMatch([]string{right}, left)
	}
	if !rightGlob {
		return pathPatternsMatch([]string{left}, right)
	}
	return true
}

func patternsMayOverlap(left string, right string) bool {
	if left == right {
		return true
	}
	leftGlob := hasGlobMeta(left)
	rightGlob := hasGlobMeta(right)
	if !leftGlob && !rightGlob {
		return false
	}
	if !leftGlob {
		return patternMatches(right, left)
	}
	if !rightGlob {
		return patternMatches(left, right)
	}
	return globPrefixesMayOverlap(left, right)
}

func hasGlobMeta(value string) bool {
	return strings.ContainsAny(value, `*?[\`)
}

func globPrefixesMayOverlap(left string, right string) bool {
	leftPrefix := globLiteralPrefix(left)
	rightPrefix := globLiteralPrefix(right)
	if leftPrefix == "" || rightPrefix == "" {
		return true
	}
	return strings.HasPrefix(leftPrefix, rightPrefix) || strings.HasPrefix(rightPrefix, leftPrefix)
}

func globLiteralPrefix(pattern string) string {
	var builder strings.Builder
	escaped := false
	for _, char := range pattern {
		if escaped {
			builder.WriteRune(char)
			escaped = false
			continue
		}
		if char == '\\' {
			escaped = true
			continue
		}
		if strings.ContainsRune("*?[", char) {
			break
		}
		builder.WriteRune(char)
	}
	return builder.String()
}

func patternMatches(pattern string, value string) bool {
	ok, err := path.Match(pattern, value)
	return err == nil && ok
}
