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
	if !patternListsMayOverlap(left.Clients, right.Clients) {
		return false
	}
	for _, operation := range left.Operations {
		if slices.Contains(right.Operations, operation) &&
			targetMatchersMayOverlap(left.Targets, right.Targets) &&
			attrsMayOverlap(left.Attrs, right.Attrs, registry.Operations[operation].Attrs) {
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

func targetMatchersMayOverlap(left []TargetMatcher, right []TargetMatcher) bool {
	for _, leftTarget := range left {
		for _, rightTarget := range right {
			if leftTarget.Kind == rightTarget.Kind && patternMapsMayOverlap(leftTarget.Fields, rightTarget.Fields) {
				return true
			}
		}
	}
	return false
}

func attrsMayOverlap(left map[string][]string, right map[string][]string, relevantAttrs []string) bool {
	for _, attr := range relevantAttrs {
		leftValues, leftOK := left[attr]
		rightValues, rightOK := right[attr]
		if leftOK && rightOK && !patternListsMayOverlap(leftValues, rightValues) {
			return false
		}
	}
	return true
}

func patternMapsMayOverlap(left map[string][]string, right map[string][]string) bool {
	for field, leftValues := range left {
		rightValues, ok := right[field]
		if ok && !patternListsMayOverlap(leftValues, rightValues) {
			return false
		}
	}
	return true
}

func patternListsMayOverlap(left []string, right []string) bool {
	for _, leftPattern := range left {
		for _, rightPattern := range right {
			if patternsMayOverlap(leftPattern, rightPattern) {
				return true
			}
		}
	}
	return false
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
	return strings.ContainsAny(value, "*?[")
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
