package policy

import (
	"path"
	"strconv"
	"strings"
)

func ruleMatches(registry Registry, rule Rule, request Request) bool {
	return patternsMatch(rule.Clients, request.Client) &&
		patternsMatch(rule.Operations, request.Operation) &&
		targetsMatch(registry, rule.Targets, request.Target) &&
		attrsMatch(registry, rule.Attrs, request.Operation, request.Attrs)
}

func targetsMatch(registry Registry, matchers []TargetMatcher, target Target) bool {
	for _, matcher := range matchers {
		if matcher.Kind != target.Kind {
			continue
		}
		if targetFieldsMatch(registry.Targets[target.Kind], matcher.Fields, target.Fields) {
			return true
		}
	}
	return false
}

func targetFieldsMatch(spec TargetSpec, patterns map[string][]string, fields map[string]string) bool {
	for name, allowed := range patterns {
		if !valuesMatch(spec.Fields[name].Match, allowed, fields[name]) {
			return false
		}
	}
	return true
}

func attrsMatch(registry Registry, patterns map[string][]string, operation string, attrs map[string]string) bool {
	for name, allowed := range patterns {
		if !attrRelevantToOperation(registry, name, operation) {
			continue
		}
		value, ok := attrs[name]
		if !ok || !valuesMatch(registry.Attrs[name].Match, allowed, value) {
			return false
		}
	}
	return true
}

func valuesMatch(mode MatchMode, patterns []string, value string) bool {
	switch defaultedMatchMode(mode) {
	case MatchGlob:
		return patternsMatch(patterns, value)
	case MatchPathGlob:
		return pathPatternsMatch(patterns, value)
	case MatchIntegerMaximum:
		return integerMaximumMatches(patterns, value)
	default:
		return false
	}
}

func attrRelevantToOperation(registry Registry, name string, operation string) bool {
	return slicesContains(registry.Operations[operation].Attrs, name)
}

func slicesContains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func patternsMatch(patterns []string, value string) bool {
	if strings.TrimSpace(value) == "" {
		return false
	}
	for _, patternValue := range patterns {
		if ok, err := path.Match(patternValue, value); err == nil && ok {
			return true
		}
	}
	return false
}

func pathPatternsMatch(patterns []string, value string) bool {
	if strings.TrimSpace(value) == "" {
		return false
	}
	valueSegments := strings.Split(value, "/")
	for _, patternValue := range patterns {
		if pathSegmentsMatch(strings.Split(patternValue, "/"), valueSegments) {
			return true
		}
	}
	return false
}

func pathSegmentsMatch(patterns []string, values []string) bool {
	memo := make(map[pathMatchState]pathMatchResult)
	return pathSegmentsMatchFrom(patterns, values, 0, 0, memo)
}

type pathMatchState struct {
	pattern int
	value   int
}

type pathMatchResult struct {
	matched bool
}

func pathSegmentsMatchFrom(patterns []string, values []string, patternIndex int, valueIndex int, memo map[pathMatchState]pathMatchResult) bool {
	state := pathMatchState{pattern: patternIndex, value: valueIndex}
	if result, ok := memo[state]; ok {
		return result.matched
	}
	matched := pathSegmentsMatchUncached(patterns, values, patternIndex, valueIndex, memo)
	memo[state] = pathMatchResult{matched: matched}
	return matched
}

func pathSegmentsMatchUncached(patterns []string, values []string, patternIndex int, valueIndex int, memo map[pathMatchState]pathMatchResult) bool {
	if patternIndex == len(patterns) {
		return valueIndex == len(values)
	}
	if patterns[patternIndex] == "**" {
		return pathSegmentsMatchFrom(patterns, values, patternIndex+1, valueIndex, memo) ||
			(valueIndex < len(values) && pathSegmentsMatchFrom(patterns, values, patternIndex, valueIndex+1, memo))
	}
	if valueIndex == len(values) {
		return false
	}
	matched, err := path.Match(patterns[patternIndex], values[valueIndex])
	return err == nil && matched && pathSegmentsMatchFrom(patterns, values, patternIndex+1, valueIndex+1, memo)
}

func integerMaximumMatches(ceilings []string, value string) bool {
	actual, err := strconv.ParseInt(value, 10, 64)
	if err != nil || actual < 0 {
		return false
	}
	for _, raw := range ceilings {
		ceiling, err := strconv.ParseInt(raw, 10, 64)
		if err == nil && actual <= ceiling {
			return true
		}
	}
	return false
}

func grantMatches(grant Grant, request Request) bool {
	if grant.Client != request.Client || grant.Operation != request.Operation {
		return false
	}
	if !targetEqual(grant.Target, request.Target) {
		return false
	}
	if !stringMapsEqual(grant.Attrs, request.Attrs) {
		return false
	}
	return grant.UsesLeft > 0
}

func targetEqual(left Target, right Target) bool {
	return left.Kind == right.Kind && stringMapsEqual(left.Fields, right.Fields)
}

func stringMapsEqual(left, right map[string]string) bool {
	if len(left) != len(right) {
		return false
	}
	return stringMapsContain(left, right)
}

func stringMapsContain(container, want map[string]string) bool {
	for key, value := range want {
		got, ok := container[key]
		if !ok || got != value {
			return false
		}
	}
	return true
}
