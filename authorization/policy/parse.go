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
	"strconv"
	"strings"

	"github.com/osolmaz/brokerkit/authorization/budget"
)

const (
	defaultGrantMinutes     = 5
	defaultMaxGrantMinutes  = 60
	absoluteMaxGrantMinutes = 7 * 24 * 60
	defaultRequestTTL       = 5
	defaultGrantUses        = 1
	defaultMaxGrantUses     = 25
	absoluteMaxGrantUses    = 1_000_000
)

type rawPolicy struct {
	Rules *[]rawRule `json:"rules"`
}

type rawRule struct {
	ID          string                 `json:"id"`
	Effect      Effect                 `json:"effect"`
	Clients     []string               `json:"clients"`
	Operations  []string               `json:"operations"`
	Targets     []TargetMatcher        `json:"targets"`
	Attrs       map[string]patternList `json:"attrs,omitempty"`
	GrantPolicy *rawGrantPolicy        `json:"grant_policy,omitempty"`
	Description string                 `json:"description,omitempty"`
}

type rawGrantPolicy struct {
	Mode              string             `json:"mode"`
	DefaultMinutes    int                `json:"default_minutes"`
	MaxMinutes        int                `json:"max_minutes"`
	RequestTTLMinutes int                `json:"request_ttl_minutes"`
	DefaultMaxUses    usebudget.Optional `json:"default_max_uses"`
	MaxUses           usebudget.Optional `json:"max_uses"`
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
	if raw.Rules == nil {
		return nil, errors.New("rules is required")
	}
	rules, err := normalizeRules(*raw.Rules, registry)
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
	return normalizeMatchValues(values, field, MatchGlob)
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
		fieldSpec, ok := spec.Fields[field]
		if !ok {
			return fmt.Errorf("target kind %q does not support field %q", target.Kind, field)
		}
		normalized, err := normalizeMatchValues(patterns, "target."+field, fieldSpec.Match)
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
		normalized, err := normalizeMatchValues(values, "attrs."+name, registry.Attrs[name].Match)
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

func normalizeGrantPolicy(effect Effect, raw *rawGrantPolicy, operations []string, registry Registry) (*GrantPolicy, error) {
	if err := validateGrantPolicyPresence(effect, raw); err != nil {
		return nil, err
	}
	if raw == nil {
		return nil, nil
	}
	if err := validateGrantableOperations(operations, registry); err != nil {
		return nil, err
	}
	grantPolicy := GrantPolicy{
		Mode: raw.Mode, DefaultMinutes: raw.DefaultMinutes, MaxMinutes: raw.MaxMinutes,
		RequestTTLMinutes: raw.RequestTTLMinutes, DefaultMaxUses: raw.DefaultMaxUses.Limit,
		MaxUses: raw.MaxUses.Limit,
	}
	if err := normalizeGrantPolicyMode(&grantPolicy, operations, registry); err != nil {
		return nil, err
	}
	defaultGrantPolicy(&grantPolicy, raw.DefaultMaxUses.Specified, raw.MaxUses.Specified, operations, registry)
	if err := validateGrantPolicyValues(grantPolicy); err != nil {
		return nil, err
	}
	if err := validateGrantPolicyOperationBounds(grantPolicy, operations, registry); err != nil {
		return nil, err
	}
	return &grantPolicy, nil
}

func validateGrantableOperations(operations []string, registry Registry) error {
	for _, op := range operations {
		if !registry.Operations[op].Grantable {
			return fmt.Errorf("operation %q is not grantable", op)
		}
	}
	return nil
}

func normalizeGrantPolicyMode(grantPolicy *GrantPolicy, operations []string, registry Registry) error {
	if grantPolicy.Mode == "" {
		mode, err := operationGrantMode(operations, registry)
		if err != nil {
			return err
		}
		grantPolicy.Mode = string(mode)
	}
	mode := GrantMode(grantPolicy.Mode)
	for _, operation := range operations {
		if !registry.Operations[operation].allowsGrantMode(mode) {
			return fmt.Errorf("grant mode %q is not allowed for operation %q", mode, operation)
		}
	}
	return nil
}

func operationGrantMode(operations []string, registry Registry) (GrantMode, error) {
	var mode GrantMode
	for _, operation := range operations {
		candidate := defaultedGrantMode(registry.Operations[operation].GrantMode)
		if mode != "" && candidate != mode {
			return "", errors.New("request rule operations must use the same grant mode")
		}
		mode = candidate
	}
	return mode, nil
}

func validateGrantPolicyPresence(effect Effect, raw *rawGrantPolicy) error {
	if effect == EffectRequest && raw == nil {
		return errors.New("request rules require grant_policy")
	}
	if effect != EffectRequest && raw != nil {
		return errors.New("grant_policy is only valid on request rules")
	}
	return nil
}

func defaultGrantPolicy(grantPolicy *GrantPolicy, defaultUsesSpecified, maxUsesSpecified bool, operations []string, registry Registry) {
	if grantPolicy.DefaultMinutes == 0 {
		grantPolicy.DefaultMinutes = defaultGrantMinutes
	}
	if grantPolicy.MaxMinutes == 0 {
		grantPolicy.MaxMinutes = min(defaultMaxGrantMinutes, maximumGrantMinutes(operations, registry))
	}
	if grantPolicy.RequestTTLMinutes == 0 {
		grantPolicy.RequestTTLMinutes = defaultRequestTTL
	}
	if !defaultUsesSpecified {
		grantPolicy.DefaultMaxUses = defaultGrantUses
	}
	if !maxUsesSpecified {
		if GrantMode(grantPolicy.Mode) == GrantModeExecution {
			grantPolicy.MaxUses = defaultGrantUses
		} else {
			grantPolicy.MaxUses = min(usebudget.Limit(defaultMaxGrantUses), maximumFiniteGrantUses(operations, registry))
		}
	}
}

func validateGrantPolicyValues(grantPolicy GrantPolicy) error {
	if !validGrantMode(GrantMode(grantPolicy.Mode)) {
		return fmt.Errorf("unsupported grant mode %q", grantPolicy.Mode)
	}
	if err := validateGrantPolicyMinutes(grantPolicy); err != nil {
		return err
	}
	if err := validateGrantPolicyUses(grantPolicy); err != nil {
		return err
	}
	if GrantMode(grantPolicy.Mode) == GrantModeExecution && (grantPolicy.DefaultMaxUses != 1 || grantPolicy.MaxUses != 1) {
		return errors.New("execution grants must be single-use")
	}
	return nil
}

func validateGrantPolicyMinutes(grantPolicy GrantPolicy) error {
	if err := validateDefaultWithinMax("default_minutes", grantPolicy.DefaultMinutes, "max_minutes", grantPolicy.MaxMinutes, absoluteMaxGrantMinutes); err != nil {
		return err
	}
	if grantPolicy.RequestTTLMinutes < 1 || grantPolicy.RequestTTLMinutes > defaultMaxGrantMinutes {
		return fmt.Errorf("request_ttl_minutes must be between 1 and %d", defaultMaxGrantMinutes)
	}
	return nil
}

func validateGrantPolicyUses(grantPolicy GrantPolicy) error {
	if grantPolicy.MaxUses.IsUnlimited() {
		if !grantPolicy.DefaultMaxUses.IsFinite() || grantPolicy.DefaultMaxUses > defaultMaxGrantUses {
			return fmt.Errorf("default_max_uses must be between 1 and %d", defaultMaxGrantUses)
		}
		return nil
	}
	return validateDefaultWithinMax(
		"default_max_uses", int(grantPolicy.DefaultMaxUses),
		"max_uses", int(grantPolicy.MaxUses), absoluteMaxGrantUses,
	)
}

func validateGrantPolicyOperationBounds(grantPolicy GrantPolicy, operations []string, registry Registry) error {
	for _, operation := range operations {
		spec := registry.Operations[operation]
		if grantPolicy.MaxMinutes > effectiveMaxGrantMinutes(spec) {
			return fmt.Errorf("max_minutes exceeds operation %q grant bound", operation)
		}
		if grantPolicy.MaxUses.IsUnlimited() {
			if spec.DisallowUnlimitedGrantUses || defaultedGrantMode(spec.GrantMode) == GrantModeExecution {
				return fmt.Errorf("max_uses exceeds operation %q grant bound", operation)
			}
			continue
		}
		if grantPolicy.MaxUses > effectiveMaxGrantUses(spec) {
			return fmt.Errorf("max_uses exceeds operation %q grant bound", operation)
		}
	}
	return nil
}

func maximumGrantMinutes(operations []string, registry Registry) int {
	maximum := absoluteMaxGrantMinutes
	for _, operation := range operations {
		maximum = min(maximum, effectiveMaxGrantMinutes(registry.Operations[operation]))
	}
	return maximum
}

func maximumFiniteGrantUses(operations []string, registry Registry) usebudget.Limit {
	maximum := usebudget.Limit(absoluteMaxGrantUses)
	for _, operation := range operations {
		maximum = min(maximum, effectiveMaxGrantUses(registry.Operations[operation]))
	}
	return maximum
}

func effectiveMaxGrantMinutes(spec OperationSpec) int {
	if spec.MaxGrantMinutes > 0 {
		return spec.MaxGrantMinutes
	}
	return defaultMaxGrantMinutes
}

func effectiveMaxGrantUses(spec OperationSpec) usebudget.Limit {
	if defaultedGrantMode(spec.GrantMode) == GrantModeExecution {
		return 1
	}
	if spec.MaxGrantUses > 0 {
		return spec.MaxGrantUses
	}
	return defaultMaxGrantUses
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

func normalizeMatchValues(values []string, field string, mode MatchMode) ([]string, error) {
	normalized, err := normalizePatternsWithoutValidation(values, field)
	if err != nil {
		return nil, err
	}
	mode = defaultedMatchMode(mode)
	for _, value := range normalized {
		if err := validateMatchValue(value, mode); err != nil {
			return nil, fmt.Errorf("%s contains invalid %s value %q: %w", field, mode, value, err)
		}
	}
	return normalized, nil
}

func normalizePatternsWithoutValidation(values []string, field string) ([]string, error) {
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
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out, nil
}

func validateMatchValue(value string, mode MatchMode) error {
	switch mode {
	case MatchGlob, MatchAnyGlob:
		return validateGlob(value)
	case MatchPathGlob:
		return validatePathGlob(value)
	case MatchRecursivePathGlob:
		return validateRecursivePathGlob(value)
	case MatchPathOutsidePrefix:
		return validatePathPrefix(value)
	case MatchIntegerMaximum:
		number, err := strconv.ParseInt(value, 10, 64)
		if err != nil {
			return errors.New("must be an integer")
		}
		if number < 0 {
			return errors.New("must not be negative")
		}
		return nil
	default:
		return fmt.Errorf("unsupported match mode %q", mode)
	}
}

func validateRecursivePathGlob(value string) error {
	if strings.HasPrefix(value, "/") {
		return errors.New("must be relative")
	}
	if strings.ContainsAny(value, `[]\`) {
		return errors.New("character classes and escapes are not supported")
	}
	if len(value) > maxPathPatternBytes {
		return fmt.Errorf("must not exceed %d bytes", maxPathPatternBytes)
	}
	segments := strings.Split(value, "/")
	if len(segments) > maxPathSegments {
		return fmt.Errorf("must not exceed %d segments", maxPathSegments)
	}
	for _, segment := range segments {
		if segment == "" || segment == ".." {
			return errors.New("must contain non-empty relative segments")
		}
	}
	return nil
}

func validatePathPrefix(prefix string) error {
	if strings.HasPrefix(prefix, "/") {
		return errors.New("must be relative")
	}
	if strings.ContainsAny(prefix, `*?[\`) {
		return errors.New("must be a literal prefix")
	}
	if len(prefix) > maxPathPatternBytes {
		return fmt.Errorf("must not exceed %d bytes", maxPathPatternBytes)
	}
	segments := strings.Split(strings.TrimSuffix(prefix, "/"), "/")
	if len(segments) > maxPathSegments {
		return fmt.Errorf("must not exceed %d segments", maxPathSegments)
	}
	for _, segment := range segments {
		if segment == "" || segment == ".." {
			return errors.New("must contain non-empty relative segments")
		}
	}
	return nil
}

func validatePathGlob(pattern string) error {
	if len(pattern) > maxPathPatternBytes {
		return fmt.Errorf("must not exceed %d bytes", maxPathPatternBytes)
	}
	if strings.Count(pattern, "/") >= maxPathSegments {
		return fmt.Errorf("must not exceed %d segments", maxPathSegments)
	}
	for _, segment := range strings.Split(pattern, "/") {
		if strings.Contains(segment, "**") && segment != "**" {
			return errors.New("** must be a complete path segment")
		}
		if segment == "**" {
			continue
		}
		if _, err := path.Match(segment, "value"); err != nil {
			return err
		}
	}
	return nil
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
