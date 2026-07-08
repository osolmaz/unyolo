package policy

import (
	"path"
	"strings"
)

func ruleMatches(registry Registry, rule Rule, request Request) bool {
	return patternsMatch(rule.Clients, request.Client) &&
		patternsMatch(rule.Operations, request.Operation) &&
		targetsMatch(rule.Targets, request.Target) &&
		attrsMatch(registry, rule.Attrs, request.Operation, request.Attrs)
}

func targetsMatch(matchers []TargetMatcher, target Target) bool {
	for _, matcher := range matchers {
		if matcher.Kind != target.Kind {
			continue
		}
		if targetFieldsMatch(matcher.Fields, target.Fields) {
			return true
		}
	}
	return false
}

func targetFieldsMatch(patterns map[string][]string, fields map[string]string) bool {
	for name, allowed := range patterns {
		if !patternsMatch(allowed, fields[name]) {
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
		if !ok || !patternsMatch(allowed, value) {
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
