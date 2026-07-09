package policy

import (
	"path"
	"regexp"
	"strconv"
	"strings"

	"github.com/osolmaz/brokerkit/internal/copyx"
)

const (
	maxPathPatternBytes = 1024
	maxPathValueBytes   = 4096
	maxPathSegments     = 256
)

func ruleMatches(registry Registry, rule Rule, request Request) bool {
	return patternsMatch(rule.Clients, request.Client) &&
		patternsMatch(rule.Operations, request.Operation) &&
		targetsMatch(registry, rule.Effect, rule.Targets, request.Target) &&
		attrsMatch(registry, rule.Effect, rule.Attrs, request.Operation, request.Attrs)
}

func targetsMatch(registry Registry, effect Effect, matchers []TargetMatcher, target Target) bool {
	for _, matcher := range matchers {
		if matcher.Kind != target.Kind {
			continue
		}
		if targetFieldsMatch(registry.Targets[target.Kind], effect, matcher.Fields, target.Fields) {
			return true
		}
	}
	return false
}

func targetFieldsMatch(spec TargetSpec, effect Effect, patterns map[string][]string, fields map[string][]string) bool {
	for name, allowed := range patterns {
		if !effectValuesMatch(effect, spec.Fields[name].Match, allowed, fields[name]) {
			return false
		}
	}
	return true
}

func attrsMatch(registry Registry, effect Effect, patterns map[string][]string, operation string, attrs map[string][]string) bool {
	for name, allowed := range patterns {
		if !attrRelevantToOperation(registry, name, operation) {
			continue
		}
		values, ok := attrs[name]
		if !ok || !effectValuesMatch(effect, registry.Attrs[name].Match, allowed, values) {
			return false
		}
	}
	return true
}

func effectValuesMatch(effect Effect, mode MatchMode, patterns []string, values []string) bool {
	if effect == EffectDeny {
		return anyValueMatches(mode, patterns, values)
	}
	return allValuesMatch(mode, patterns, values)
}

func anyValueMatches(mode MatchMode, patterns []string, values []string) bool {
	if defaultedMatchMode(mode) == MatchRecursivePathGlob {
		return recursivePathValuesMatch(patterns, values, false)
	}
	for _, value := range values {
		if valuesMatch(mode, patterns, value) {
			return true
		}
	}
	return false
}

func allValuesMatch(mode MatchMode, patterns []string, values []string) bool {
	if len(values) == 0 {
		return false
	}
	if defaultedMatchMode(mode) == MatchRecursivePathGlob {
		return recursivePathValuesMatch(patterns, values, true)
	}
	if defaultedMatchMode(mode) == MatchAnyGlob {
		return anyValueMatches(mode, patterns, values)
	}
	for _, value := range values {
		if !valuesMatch(mode, patterns, value) {
			return false
		}
	}
	return true
}

func valuesMatch(mode MatchMode, patterns []string, value string) bool {
	switch defaultedMatchMode(mode) {
	case MatchGlob, MatchAnyGlob:
		return patternsMatch(patterns, value)
	case MatchPathGlob:
		return pathPatternsMatch(patterns, value)
	case MatchRecursivePathGlob:
		return recursivePathPatternsMatch(patterns, value)
	case MatchPathOutsidePrefix:
		return pathOutsidePrefixes(patterns, value)
	case MatchIntegerMaximum:
		return integerMaximumMatches(patterns, value)
	default:
		return false
	}
}

func recursivePathPatternsMatch(patterns []string, value string) bool {
	if !validPathValue(value) {
		return false
	}
	return compiledRecursivePathPatternsMatch(compileRecursivePathPatterns(patterns), value)
}

func recursivePathValuesMatch(patterns []string, values []string, requireAll bool) bool {
	compiled := compileRecursivePathPatterns(patterns)
	for _, value := range values {
		matched := validPathValue(value) && compiledRecursivePathPatternsMatch(compiled, value)
		if requireAll != matched {
			return !requireAll
		}
	}
	return requireAll && len(values) > 0
}

func compileRecursivePathPatterns(patterns []string) []*regexp.Regexp {
	compiled := make([]*regexp.Regexp, 0, len(patterns))
	for _, pattern := range patterns {
		expression := regexp.QuoteMeta(pattern)
		expression = strings.ReplaceAll(expression, `\*\*`, `(?s:.*)`)
		expression = strings.ReplaceAll(expression, `\*`, `[^/]*`)
		expression = strings.ReplaceAll(expression, `\?`, `[^/]`)
		if matcher, err := regexp.Compile("^" + expression + "$"); err == nil {
			compiled = append(compiled, matcher)
		}
	}
	return compiled
}

func compiledRecursivePathPatternsMatch(patterns []*regexp.Regexp, value string) bool {
	for _, pattern := range patterns {
		if pattern.MatchString(value) {
			return true
		}
	}
	return false
}

func validPathValue(value string) bool {
	return strings.TrimSpace(value) != "" && len(value) <= maxPathValueBytes && strings.Count(value, "/") < maxPathSegments
}

func pathOutsidePrefixes(prefixes []string, value string) bool {
	for _, prefix := range prefixes {
		prefix = strings.TrimSuffix(prefix, "/")
		if value == prefix || strings.HasPrefix(value, prefix+"/") {
			return false
		}
	}
	return true
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
	if strings.TrimSpace(value) == "" || len(value) > maxPathValueBytes || strings.Count(value, "/") >= maxPathSegments {
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
	states := make([]bool, len(patterns)+1)
	states[0] = true
	closeDoubleStarStates(states, patterns)
	for _, value := range values {
		states = advancePathStates(states, patterns, value)
	}
	return states[len(patterns)]
}

func advancePathStates(states []bool, patterns []string, value string) []bool {
	next := make([]bool, len(states))
	for patternIndex := range patterns {
		if !states[patternIndex] {
			continue
		}
		if patterns[patternIndex] == "**" {
			next[patternIndex] = true
			continue
		}
		matched, err := path.Match(patterns[patternIndex], value)
		if err == nil && matched {
			next[patternIndex+1] = true
		}
	}
	closeDoubleStarStates(next, patterns)
	return next
}

func closeDoubleStarStates(states []bool, patterns []string) {
	for patternIndex, pattern := range patterns {
		if states[patternIndex] && pattern == "**" {
			states[patternIndex+1] = true
		}
	}
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

func grantMatches(registry Registry, grant Grant, request Request) bool {
	if grant.Client != request.Client || grant.Operation != request.Operation {
		return false
	}
	if !targetEqual(grant.Target, request.Target) {
		return false
	}
	if !grantAttrsMatch(registry, grant.Attrs, request.Attrs) {
		return false
	}
	return grant.UsesLeft > 0
}

func grantAttrsMatch(registry Registry, constraints map[string][]string, attrs map[string][]string) bool {
	if len(constraints) != len(attrs) {
		return false
	}
	for name, allowed := range constraints {
		values, ok := attrs[name]
		if !ok {
			return false
		}
		mode := registry.Attrs[name].GrantMatch
		if mode == "" {
			if !copyx.StringSlicesEqual(allowed, values) {
				return false
			}
			continue
		}
		if !allValuesMatch(mode, allowed, values) {
			return false
		}
	}
	return true
}

func targetEqual(left Target, right Target) bool {
	return left.Kind == right.Kind && stringMapsEqual(left.Fields, right.Fields)
}

func stringMapsEqual(left, right map[string][]string) bool {
	return copyx.StringSliceMapsEqual(left, right)
}
