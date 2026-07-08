package policy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"slices"
	"strings"
)

const (
	defaultGrantMode       = "window"
	defaultGrantMinutes    = 5
	defaultMaxGrantMinutes = 60
	defaultRequestTTL      = 5
	defaultGrantUses       = 1
	defaultMaxGrantUses    = 25
)

type rawPolicy struct {
	Rules []rawRule `json:"rules"`
}

type rawRule struct {
	ID          string                 `json:"id"`
	Effect      Effect                 `json:"effect"`
	Clients     []string               `json:"clients"`
	Operations  []string               `json:"operations"`
	Targets     []TargetMatcher        `json:"targets"`
	Attrs       map[string]patternList `json:"attrs,omitempty"`
	GrantPolicy *GrantPolicy           `json:"grant_policy,omitempty"`
	Description string                 `json:"description,omitempty"`
}

type patternList []string

// LoadFile reads and parses a policy file.
func LoadFile(file string, registry Registry) (*Policy, error) {
	data, err := os.ReadFile(file) // #nosec G304 -- policy file path is operator configured.
	if err != nil {
		return nil, fmt.Errorf("read policy file: %w", err)
	}
	return Parse(data, registry)
}

// Parse parses a policy document.
func Parse(data []byte, registry Registry) (*Policy, error) {
	if err := registry.validate(); err != nil {
		return nil, err
	}
	var raw rawPolicy
	if err := decodeStrict(data, &raw); err != nil {
		return nil, fmt.Errorf("parse policy: %w", err)
	}
	if len(raw.Rules) == 0 {
		return nil, errors.New("rules must not be empty")
	}
	rules, err := normalizeRules(raw.Rules, registry)
	if err != nil {
		return nil, err
	}
	return &Policy{registry: cloneRegistry(registry), rules: cloneRules(rules)}, nil
}

func decodeStrict(data []byte, out any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(out); err != nil {
		return err
	}
	var trailing struct{}
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("trailing json content")
	}
	return nil
}

func normalizeRules(rawRules []rawRule, registry Registry) ([]Rule, error) {
	ids := make(map[string]struct{}, len(rawRules))
	rules := make([]Rule, 0, len(rawRules))
	for i, raw := range rawRules {
		rule, err := normalizeRule(raw, registry)
		if err != nil {
			return nil, fmt.Errorf("rules[%d]: %w", i, err)
		}
		if _, ok := ids[rule.ID]; ok {
			return nil, fmt.Errorf("rules[%d]: duplicate rule id %q", i, rule.ID)
		}
		ids[rule.ID] = struct{}{}
		rules = append(rules, rule)
	}
	return rules, validateRequestRuleAmbiguity(rules, registry)
}

func normalizeRule(raw rawRule, registry Registry) (Rule, error) {
	id, err := normalizeRuleID(raw.ID)
	if err != nil {
		return Rule{}, err
	}
	if err := validateEffect(raw.Effect); err != nil {
		return Rule{}, err
	}
	return normalizeRuleBody(id, raw, registry)
}

func normalizeRuleBody(id string, raw rawRule, registry Registry) (Rule, error) {
	clients, err := normalizePatterns(raw.Clients, "clients")
	if err != nil {
		return Rule{}, err
	}
	operations, err := normalizeOperations(raw.Operations, registry)
	if err != nil {
		return Rule{}, err
	}
	targets, err := normalizeTargets(raw.Targets, operations, registry)
	if err != nil {
		return Rule{}, err
	}
	attrs, err := normalizeAttrs(raw.Attrs, operations, registry)
	if err != nil {
		return Rule{}, err
	}
	grantPolicy, err := normalizeGrantPolicy(raw.Effect, raw.GrantPolicy, operations, registry)
	if err != nil {
		return Rule{}, err
	}
	return Rule{
		ID:          id,
		Effect:      raw.Effect,
		Clients:     clients,
		Operations:  operations,
		Targets:     targets,
		Attrs:       attrs,
		GrantPolicy: grantPolicy,
		Description: strings.TrimSpace(raw.Description),
	}, nil
}

func normalizeRuleID(id string) (string, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return "", errors.New("id is required")
	}
	return id, nil
}

func validateEffect(effect Effect) error {
	if effect == EffectAllow || effect == EffectRequest || effect == EffectDeny {
		return nil
	}
	return fmt.Errorf("effect %q is unsupported", effect)
}

func normalizePatterns(values []string, field string) ([]string, error) {
	if len(values) == 0 {
		return nil, fmt.Errorf("%s must not be empty", field)
	}
	out := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			return nil, fmt.Errorf("%s contains an empty value", field)
		}
		if err := validateGlob(value); err != nil {
			return nil, fmt.Errorf("%s contains invalid pattern %q: %w", field, value, err)
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out, nil
}

func normalizeOperations(values []string, registry Registry) ([]string, error) {
	ops, err := normalizePatterns(values, "operations")
	if err != nil {
		return nil, err
	}
	for _, op := range ops {
		if _, ok := registry.Operations[op]; !ok {
			return nil, fmt.Errorf("unknown operation %q", op)
		}
	}
	return ops, nil
}

func normalizeTargets(values []TargetMatcher, operations []string, registry Registry) ([]TargetMatcher, error) {
	if len(values) == 0 {
		return nil, errors.New("targets must not be empty")
	}
	targets := make([]TargetMatcher, 0, len(values))
	for _, target := range values {
		if err := validateTarget(target, operations, registry); err != nil {
			return nil, err
		}
		targets = append(targets, target)
	}
	return targets, nil
}

func validateTarget(target TargetMatcher, operations []string, registry Registry) error {
	spec, ok := registry.Targets[target.Kind]
	if !ok {
		return fmt.Errorf("unknown target kind %q", target.Kind)
	}
	if err := validateTargetFields(target, spec); err != nil {
		return err
	}
	return validateTargetOperations(target.Kind, operations, registry)
}

func validateTargetFields(target TargetMatcher, spec TargetSpec) error {
	if err := validateRequiredTargetFields(target, spec); err != nil {
		return err
	}
	return validateSupportedTargetFields(target, spec)
}

func validateRequiredTargetFields(target TargetMatcher, spec TargetSpec) error {
	for field, fieldSpec := range spec.Fields {
		if fieldSpec.Required && len(target.Fields[field]) == 0 {
			return fmt.Errorf("target kind %q requires field %q", target.Kind, field)
		}
	}
	return nil
}

func validateSupportedTargetFields(target TargetMatcher, spec TargetSpec) error {
	for field, patterns := range target.Fields {
		if _, ok := spec.Fields[field]; !ok {
			return fmt.Errorf("target kind %q does not support field %q", target.Kind, field)
		}
		normalized, err := normalizePatterns(patterns, "target."+field)
		if err != nil {
			return err
		}
		target.Fields[field] = normalized
	}
	return nil
}

func validateTargetOperations(kind string, operations []string, registry Registry) error {
	for _, op := range operations {
		if !slices.Contains(registry.Operations[op].TargetKinds, kind) {
			return fmt.Errorf("operation %q does not support target kind %q", op, kind)
		}
	}
	return nil
}

func normalizeAttrs(raw map[string]patternList, operations []string, registry Registry) (map[string][]string, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	attrs := make(map[string][]string, len(raw))
	for name, values := range raw {
		if _, ok := registry.Attrs[name]; !ok {
			return nil, fmt.Errorf("unknown attr %q", name)
		}
		if unsupportedOperation, ok := attrUnsupportedOperation(name, operations, registry); ok {
			return nil, fmt.Errorf("operation %q does not support attr %q", unsupportedOperation, name)
		}
		normalized, err := normalizePatterns(values, "attrs."+name)
		if err != nil {
			return nil, err
		}
		attrs[name] = normalized
	}
	return attrs, nil
}

func attrUnsupportedOperation(name string, operations []string, registry Registry) (string, bool) {
	for _, op := range operations {
		if !slices.Contains(registry.Operations[op].Attrs, name) {
			return op, true
		}
	}
	return "", false
}

func normalizeGrantPolicy(effect Effect, raw *GrantPolicy, operations []string, registry Registry) (*GrantPolicy, error) {
	if err := validateGrantPolicyPresence(effect, raw); err != nil {
		return nil, err
	}
	if raw == nil {
		return nil, nil
	}
	for _, op := range operations {
		if !registry.Operations[op].Grantable {
			return nil, fmt.Errorf("operation %q is not grantable", op)
		}
	}
	grantPolicy := *raw
	defaultGrantPolicy(&grantPolicy)
	if err := validateGrantPolicyValues(grantPolicy); err != nil {
		return nil, err
	}
	return &grantPolicy, nil
}

func validateGrantPolicyPresence(effect Effect, raw *GrantPolicy) error {
	if effect == EffectRequest && raw == nil {
		return errors.New("request rules require grant_policy")
	}
	if effect != EffectRequest && raw != nil {
		return errors.New("grant_policy is only valid on request rules")
	}
	return nil
}

func defaultGrantPolicy(grantPolicy *GrantPolicy) {
	if grantPolicy.Mode == "" {
		grantPolicy.Mode = defaultGrantMode
	}
	if grantPolicy.DefaultMinutes == 0 {
		grantPolicy.DefaultMinutes = defaultGrantMinutes
	}
	if grantPolicy.MaxMinutes == 0 {
		grantPolicy.MaxMinutes = defaultMaxGrantMinutes
	}
	if grantPolicy.RequestTTLMinutes == 0 {
		grantPolicy.RequestTTLMinutes = defaultRequestTTL
	}
	if grantPolicy.DefaultMaxUses == 0 {
		grantPolicy.DefaultMaxUses = defaultGrantUses
	}
	if grantPolicy.MaxUses == 0 {
		grantPolicy.MaxUses = defaultMaxGrantUses
	}
}

func validateGrantPolicyValues(grantPolicy GrantPolicy) error {
	if grantPolicy.Mode != defaultGrantMode {
		return fmt.Errorf("unsupported grant mode %q", grantPolicy.Mode)
	}
	if err := validateGrantPolicyMinutes(grantPolicy); err != nil {
		return err
	}
	if err := validateGrantPolicyUses(grantPolicy); err != nil {
		return err
	}
	return nil
}

func validateGrantPolicyMinutes(grantPolicy GrantPolicy) error {
	if err := validateDefaultWithinMax("default_minutes", grantPolicy.DefaultMinutes, "max_minutes", grantPolicy.MaxMinutes, defaultMaxGrantMinutes); err != nil {
		return err
	}
	if grantPolicy.RequestTTLMinutes < 1 || grantPolicy.RequestTTLMinutes > defaultMaxGrantMinutes {
		return fmt.Errorf("request_ttl_minutes must be between 1 and %d", defaultMaxGrantMinutes)
	}
	return nil
}

func validateGrantPolicyUses(grantPolicy GrantPolicy) error {
	return validateDefaultWithinMax("default_max_uses", grantPolicy.DefaultMaxUses, "max_uses", grantPolicy.MaxUses, defaultMaxGrantUses)
}

func validateDefaultWithinMax(defaultName string, defaultValue int, maxName string, maxValue int, maxLimit int) error {
	if defaultValue < 1 || defaultValue > maxValue {
		return fmt.Errorf("%s must be between 1 and %s", defaultName, maxName)
	}
	if maxValue < 1 || maxValue > maxLimit {
		return fmt.Errorf("%s must be between 1 and %d", maxName, maxLimit)
	}
	return nil
}

func validateGlob(pattern string) error {
	if strings.Contains(pattern, "**") {
		return errors.New("** globs are not supported")
	}
	_, err := path.Match(pattern, "value")
	return err
}

// UnmarshalJSON decodes arbitrary string or string-array target fields.
func (t *TargetMatcher) UnmarshalJSON(data []byte) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	kindValue, ok := raw["kind"]
	if !ok {
		return errors.New("target kind is required")
	}
	var kind string
	if err := json.Unmarshal(kindValue, &kind); err != nil {
		return fmt.Errorf("target kind: %w", err)
	}
	delete(raw, "kind")
	fields := make(map[string][]string, len(raw))
	for name, value := range raw {
		patterns, err := decodePatternList(value)
		if err != nil {
			return fmt.Errorf("target field %q: %w", name, err)
		}
		fields[name] = patterns
	}
	t.Kind = strings.TrimSpace(kind)
	t.Fields = fields
	return nil
}

func (p *patternList) UnmarshalJSON(data []byte) error {
	values, err := decodePatternList(data)
	if err != nil {
		return err
	}
	*p = values
	return nil
}

func decodePatternList(data []byte) ([]string, error) {
	var single string
	if err := json.Unmarshal(data, &single); err == nil {
		return []string{single}, nil
	}
	var many []string
	if err := json.Unmarshal(data, &many); err != nil {
		return nil, err
	}
	if len(many) == 0 {
		return nil, errors.New("must not be empty")
	}
	return many, nil
}
