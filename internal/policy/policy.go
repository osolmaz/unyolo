// Package policy parses and evaluates hf-broker rule-based scope files.
package policy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"regexp"
	"slices"
	"strings"
	"time"
)

const (
	DefaultGrantMinutes    = 5
	MaxGrantMinutes        = 60
	DefaultGrantUses       = 1
	MaxGrantUses           = 25
	DefaultRequestTTL      = 5
	MaxRules               = 1000
	MaxTargetsPerRule      = 50
	MaxOperationsPerRule   = 50
	MaxClientsPerRule      = 100
	MaxGlobBytes           = 256
	MaxRuleIDBytes         = 128
	MaxPolicyFileSizeBytes = 1 << 20
)

type Operation string

const (
	OpRepoList          Operation = "repo.list"
	OpRepoMetadataRead  Operation = "repo.metadata.read"
	OpRepoContentsRead  Operation = "repo.contents.read"
	OpGitFetch          Operation = "git.fetch"
	OpGitPushAppend     Operation = "git.push.append"
	OpGitPushForce      Operation = "git.push.force"
	OpGitRefDelete      Operation = "git.ref.delete"
	OpGitTagUpdate      Operation = "git.tag.update"
	OpBucketObjectList  Operation = "bucket.object.list"
	OpBucketObjectRead  Operation = "bucket.object.read"
	OpBucketObjectWrite Operation = "bucket.object.write"
	OpBucketObjectDel   Operation = "bucket.object.delete"
)

type Effect string

const (
	EffectAllow   Effect = "allow"
	EffectRequest Effect = "request"
	EffectDeny    Effect = "deny"
	EffectNoMatch Effect = "no_match"
)

type TargetKind string

const (
	KindRepo   TargetKind = "repo"
	KindBucket TargetKind = "bucket"
)

type RepoType string

const (
	TypeModel   RepoType = "model"
	TypeDataset RepoType = "dataset"
	TypeSpace   RepoType = "space"
	TypeAny     RepoType = "*"
)

type GrantMode string

const (
	GrantModeNone      GrantMode = "none"
	GrantModeWindow    GrantMode = "window"
	GrantModeExecution GrantMode = "execution"
)

type Request struct {
	Client    string
	Operation Operation
	Target    Target
	Attrs     map[string]any
}

type Target struct {
	Kind           TargetKind
	Type           RepoType
	Owner          string
	Name           string
	Refs           []string
	Paths          []string
	Visibility     []string
	Keys           []string
	SnapshotPrefix string
}

type Policy struct {
	rules []Rule
}

type Rule struct {
	ID          string
	Effect      Effect
	Clients     []string
	Operations  []Operation
	Targets     []TargetMatcher
	Attrs       map[string]AttrConstraint
	GrantPolicy *GrantPolicy
	Description string

	Generated bool
	GrantID   string
	ExpiresAt time.Time
	UsesLeft  int
}

type TargetMatcher struct {
	Kind           TargetKind `json:"kind"`
	Type           RepoType   `json:"type,omitempty"`
	Owner          string     `json:"owner"`
	Name           string     `json:"name"`
	Refs           []string   `json:"refs,omitempty"`
	Paths          []string   `json:"paths,omitempty"`
	Visibility     []string   `json:"visibility,omitempty"`
	Keys           []string   `json:"keys,omitempty"`
	SnapshotPrefix string     `json:"snapshot_prefix,omitempty"`
}

type AttrConstraint struct {
	Values []string
	Number *int64
}

type GrantPolicy struct {
	Mode              GrantMode `json:"mode"`
	DefaultMinutes    int       `json:"default_minutes"`
	MaxMinutes        int       `json:"max_minutes"`
	RequestTTLMinutes int       `json:"request_ttl_minutes"`
	DefaultMaxUses    int       `json:"default_max_uses"`
	MaxUses           int       `json:"max_uses"`
}

type Decision struct {
	Effect                Effect
	Reason                string
	MatchedDenyRuleIDs    []string
	MatchedGrantRuleIDs   []string
	MatchedAllowRuleIDs   []string
	MatchedRequestRuleIDs []string
	GrantID               string
	GrantPolicy           *GrantPolicy
}

type rawPolicy struct {
	Rules []rawRule `json:"rules"`
}

type rawRule struct {
	ID          string                     `json:"id"`
	Effect      string                     `json:"effect"`
	Clients     []string                   `json:"clients"`
	Operations  []string                   `json:"operations"`
	Targets     []TargetMatcher            `json:"targets"`
	Attrs       map[string]json.RawMessage `json:"attrs"`
	GrantPolicy *rawGrantPolicy            `json:"grant_policy"`
	Description string                     `json:"description"`
}

type rawGrantPolicy struct {
	Mode              *string `json:"mode"`
	DefaultMinutes    *int    `json:"default_minutes"`
	MaxMinutes        *int    `json:"max_minutes"`
	RequestTTLMinutes *int    `json:"request_ttl_minutes"`
	DefaultMaxUses    *int    `json:"default_max_uses"`
	MaxUses           *int    `json:"max_uses"`
}

type operationInfo struct {
	mode GrantMode
}

var operations = map[Operation]operationInfo{
	OpRepoList:          {mode: GrantModeNone},
	OpRepoMetadataRead:  {mode: GrantModeNone},
	OpRepoContentsRead:  {mode: GrantModeWindow},
	OpGitFetch:          {mode: GrantModeWindow},
	OpGitPushAppend:     {mode: GrantModeWindow},
	OpGitPushForce:      {mode: GrantModeWindow},
	OpGitRefDelete:      {mode: GrantModeWindow},
	OpGitTagUpdate:      {mode: GrantModeWindow},
	OpBucketObjectList:  {mode: GrantModeNone},
	OpBucketObjectRead:  {mode: GrantModeWindow},
	OpBucketObjectWrite: {mode: GrantModeWindow},
	OpBucketObjectDel:   {mode: GrantModeExecution},
}

// LoadFile reads and parses a rule-based scope file.
func LoadFile(file string) (Policy, error) {
	data, err := os.ReadFile(file) // #nosec G304 -- operator-configured path from the environment.
	if err != nil {
		return Policy{}, fmt.Errorf("read scope file: %w", err)
	}
	return Parse(data)
}

// Parse parses rule-based scope.json content.
func Parse(data []byte) (Policy, error) {
	if len(data) > MaxPolicyFileSizeBytes {
		return Policy{}, fmt.Errorf("scope.json: file larger than %d bytes", MaxPolicyFileSizeBytes)
	}
	var raw rawPolicy
	if err := decodeStrict(data, &raw); err != nil {
		return Policy{}, fmt.Errorf("parse scope file: %w", err)
	}
	return buildPolicy(raw)
}

func decodeStrict(data []byte, out any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(out); err != nil {
		return err
	}
	var trailing struct{}
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return fmt.Errorf("trailing content")
	}
	return nil
}

func buildPolicy(raw rawPolicy) (Policy, error) {
	if len(raw.Rules) > MaxRules {
		return Policy{}, fmt.Errorf("scope.json rules: count exceeds %d", MaxRules)
	}
	out := Policy{rules: make([]Rule, 0, len(raw.Rules))}
	ids := map[string]bool{}
	for i, rawRule := range raw.Rules {
		rule, err := parseRule(i, rawRule)
		if err != nil {
			return Policy{}, err
		}
		if ids[rule.ID] {
			return Policy{}, fmt.Errorf("scope.json rules[%d].id: duplicate rule id %q", i, rule.ID)
		}
		ids[rule.ID] = true
		out.rules = append(out.rules, rule)
	}
	if err := validateRequestRuleOverlaps(out.rules); err != nil {
		return Policy{}, err
	}
	return out, nil
}

func parseRule(index int, raw rawRule) (Rule, error) {
	prefix := fmt.Sprintf("scope.json rules[%d]", index)
	effect, err := parseEffect(raw.Effect)
	if err != nil {
		return Rule{}, fmt.Errorf("%s.effect: %w", prefix, err)
	}
	if raw.ID == "" || len(raw.ID) > MaxRuleIDBytes {
		return Rule{}, fmt.Errorf("%s.id: must be 1-%d bytes", prefix, MaxRuleIDBytes)
	}
	clients, err := parseClients(prefix+".clients", raw.Clients)
	if err != nil {
		return Rule{}, err
	}
	ops, err := parseOperations(prefix+".operations", raw.Operations)
	if err != nil {
		return Rule{}, err
	}
	targets, err := parseTargets(prefix+".targets", raw.Targets)
	if err != nil {
		return Rule{}, err
	}
	attrs, err := parseAttrs(prefix+".attrs", raw.Attrs)
	if err != nil {
		return Rule{}, err
	}
	grantPolicy, err := parseGrantPolicy(prefix+".grant_policy", effect, ops, raw.GrantPolicy)
	if err != nil {
		return Rule{}, err
	}
	return Rule{
		ID:          raw.ID,
		Effect:      effect,
		Clients:     clients,
		Operations:  ops,
		Targets:     targets,
		Attrs:       attrs,
		GrantPolicy: grantPolicy,
		Description: raw.Description,
	}, nil
}

func parseEffect(value string) (Effect, error) {
	switch Effect(value) {
	case EffectAllow, EffectRequest, EffectDeny:
		return Effect(value), nil
	default:
		return "", fmt.Errorf("must be allow, request, or deny")
	}
}

func parseClients(path string, values []string) ([]string, error) {
	if len(values) == 0 {
		return nil, fmt.Errorf("%s: must not be empty", path)
	}
	if len(values) > MaxClientsPerRule {
		return nil, fmt.Errorf("%s: count exceeds %d", path, MaxClientsPerRule)
	}
	seen := map[string]bool{}
	for _, value := range values {
		if value == "" || strings.ContainsAny(value, " \t\r\n") {
			return nil, fmt.Errorf("%s: invalid client %q", path, value)
		}
		if seen[value] {
			return nil, fmt.Errorf("%s: duplicate client %q", path, value)
		}
		seen[value] = true
	}
	return slices.Clone(values), nil
}

func parseOperations(pathName string, values []string) ([]Operation, error) {
	if len(values) == 0 {
		return nil, fmt.Errorf("%s: must not be empty", pathName)
	}
	if len(values) > MaxOperationsPerRule {
		return nil, fmt.Errorf("%s: count exceeds %d", pathName, MaxOperationsPerRule)
	}
	seen := map[Operation]bool{}
	var out []Operation
	for _, value := range values {
		expanded, err := expandOperation(value)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", pathName, err)
		}
		for _, op := range expanded {
			if !seen[op] {
				seen[op] = true
				out = append(out, op)
			}
		}
	}
	return out, nil
}

func expandOperation(value string) ([]Operation, error) {
	if strings.HasSuffix(value, ".*") {
		return expandOperationFamily(value)
	}
	op := Operation(value)
	if _, ok := operations[op]; !ok {
		return nil, fmt.Errorf("unknown operation %q", value)
	}
	return []Operation{op}, nil
}

func expandOperationFamily(value string) ([]Operation, error) {
	switch value {
	case "repo.*", "git.*", "bucket.*":
	default:
		return nil, fmt.Errorf("invalid operation-family glob %q", value)
	}
	prefix := strings.TrimSuffix(value, "*")
	var out []Operation
	for op := range operations {
		if strings.HasPrefix(string(op), prefix) {
			out = append(out, op)
		}
	}
	slices.Sort(out)
	return out, nil
}

func parseTargets(pathName string, targets []TargetMatcher) ([]TargetMatcher, error) {
	if len(targets) == 0 {
		return nil, fmt.Errorf("%s: must not be empty", pathName)
	}
	if len(targets) > MaxTargetsPerRule {
		return nil, fmt.Errorf("%s: count exceeds %d", pathName, MaxTargetsPerRule)
	}
	for i := range targets {
		if err := validateTarget(fmt.Sprintf("%s[%d]", pathName, i), &targets[i]); err != nil {
			return nil, err
		}
	}
	return targets, nil
}

func validateTarget(pathName string, target *TargetMatcher) error {
	switch target.Kind {
	case KindRepo:
		return validateRepoTarget(pathName, target)
	case KindBucket:
		return validateBucketTarget(pathName, target)
	default:
		return fmt.Errorf("%s.kind: must be repo or bucket", pathName)
	}
}

func validateRepoTarget(pathName string, target *TargetMatcher) error {
	if !validRepoType(target.Type) {
		return fmt.Errorf("%s.type: must be model, dataset, space, or *", pathName)
	}
	if err := validateSegmentGlob(pathName+".owner", target.Owner); err != nil {
		return err
	}
	if err := validateSegmentGlob(pathName+".name", target.Name); err != nil {
		return err
	}
	if err := validateGlobList(pathName+".refs", target.Refs, false); err != nil {
		return err
	}
	if err := validateGlobList(pathName+".paths", target.Paths, true); err != nil {
		return err
	}
	for _, visibility := range target.Visibility {
		if visibility != "public" && visibility != "private" && visibility != "*" {
			return fmt.Errorf("%s.visibility: unsupported value %q", pathName, visibility)
		}
	}
	return nil
}

func validateBucketTarget(pathName string, target *TargetMatcher) error {
	if target.Type != "" {
		return fmt.Errorf("%s.type: bucket targets must not set type", pathName)
	}
	if err := validateSegmentGlob(pathName+".owner", target.Owner); err != nil {
		return err
	}
	if err := validateSegmentGlob(pathName+".name", target.Name); err != nil {
		return err
	}
	if err := validateGlobList(pathName+".keys", target.Keys, true); err != nil {
		return err
	}
	if target.SnapshotPrefix != "" && (strings.HasPrefix(target.SnapshotPrefix, "/") || strings.Contains(target.SnapshotPrefix, "..")) {
		return fmt.Errorf("%s.snapshot_prefix: must be a relative prefix", pathName)
	}
	return nil
}

func validRepoType(value RepoType) bool {
	switch value {
	case TypeModel, TypeDataset, TypeSpace, TypeAny:
		return true
	default:
		return false
	}
}

func validateSegmentGlob(pathName, value string) error {
	if value == "" || strings.Contains(value, "/") {
		return fmt.Errorf("%s: must be one non-empty segment", pathName)
	}
	return validateGlob(pathName, value, false)
}

func validateGlobList(pathName string, values []string, allowDoubleStar bool) error {
	for _, value := range values {
		if err := validateGlob(pathName, value, allowDoubleStar); err != nil {
			return err
		}
	}
	return nil
}

func validateGlob(pathName, value string, allowDoubleStar bool) error {
	if value == "" || len(value) > MaxGlobBytes || strings.Contains(value, "\x00") || strings.HasPrefix(value, "/") || strings.Contains(value, "//") {
		return fmt.Errorf("%s: malformed glob", pathName)
	}
	for _, segment := range strings.Split(value, "/") {
		if segment == "" || segment == ".." {
			return fmt.Errorf("%s: malformed glob", pathName)
		}
	}
	if strings.Contains(value, "**") && !allowDoubleStar {
		return fmt.Errorf("%s: ** is allowed only for path/key globs", pathName)
	}
	if _, err := path.Match(strings.ReplaceAll(value, "**", "*"), value); err != nil {
		return fmt.Errorf("%s: malformed glob", pathName)
	}
	return nil
}

func parseAttrs(pathName string, raw map[string]json.RawMessage) (map[string]AttrConstraint, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	out := map[string]AttrConstraint{}
	for key, value := range raw {
		if !knownAttr(key) {
			return nil, fmt.Errorf("%s.%s: unknown attribute", pathName, key)
		}
		parsed, err := parseAttrValue(value)
		if err != nil {
			return nil, fmt.Errorf("%s.%s: %w", pathName, key, err)
		}
		out[key] = parsed
	}
	return out, nil
}

func knownAttr(key string) bool {
	switch key {
	case "visibility_direction", "max_bytes", "ref_change":
		return true
	default:
		return false
	}
}

func parseAttrValue(raw json.RawMessage) (AttrConstraint, error) {
	var number int64
	if err := json.Unmarshal(raw, &number); err == nil {
		if number < 0 {
			return AttrConstraint{}, fmt.Errorf("numeric value must be non-negative")
		}
		return AttrConstraint{Number: &number}, nil
	}
	var one string
	if err := json.Unmarshal(raw, &one); err == nil {
		if one == "" {
			return AttrConstraint{}, fmt.Errorf("string value must not be empty")
		}
		return AttrConstraint{Values: []string{one}}, nil
	}
	var many []string
	if err := json.Unmarshal(raw, &many); err == nil {
		if len(many) == 0 {
			return AttrConstraint{}, fmt.Errorf("array must not be empty")
		}
		for _, value := range many {
			if value == "" {
				return AttrConstraint{}, fmt.Errorf("string value must not be empty")
			}
		}
		return AttrConstraint{Values: many}, nil
	}
	return AttrConstraint{}, fmt.Errorf("must be string, string array, or non-negative integer")
}

func parseGrantPolicy(pathName string, effect Effect, ops []Operation, raw *rawGrantPolicy) (*GrantPolicy, error) {
	if effect != EffectRequest {
		if raw != nil {
			return nil, fmt.Errorf("%s: only request rules may set grant_policy", pathName)
		}
		return nil, nil
	}
	if raw == nil {
		return nil, fmt.Errorf("%s: request rules require grant_policy", pathName)
	}
	policy, err := normalizeGrantPolicy(raw, defaultGrantMode(ops))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", pathName, err)
	}
	if policy.Mode == GrantModeNone {
		return nil, fmt.Errorf("%s.mode: operation is not grantable", pathName)
	}
	return &policy, nil
}

func defaultGrantMode(ops []Operation) GrantMode {
	mode := GrantModeNone
	for _, op := range ops {
		next := operations[op].mode
		if next == GrantModeNone {
			continue
		}
		if mode == GrantModeNone {
			mode = next
			continue
		}
		if mode != next {
			return GrantModeWindow
		}
	}
	return mode
}

func normalizeGrantPolicy(raw *rawGrantPolicy, defaultMode GrantMode) (GrantPolicy, error) {
	policy := GrantPolicy{
		Mode:              defaultMode,
		DefaultMinutes:    DefaultGrantMinutes,
		MaxMinutes:        MaxGrantMinutes,
		RequestTTLMinutes: DefaultRequestTTL,
		DefaultMaxUses:    DefaultGrantUses,
		MaxUses:           DefaultGrantUses,
	}
	if raw.Mode != nil {
		switch GrantMode(*raw.Mode) {
		case GrantModeWindow, GrantModeExecution:
			policy.Mode = GrantMode(*raw.Mode)
		default:
			return GrantPolicy{}, fmt.Errorf("mode must be window or execution")
		}
	}
	assignInt(&policy.DefaultMinutes, raw.DefaultMinutes)
	assignInt(&policy.MaxMinutes, raw.MaxMinutes)
	assignInt(&policy.RequestTTLMinutes, raw.RequestTTLMinutes)
	assignInt(&policy.DefaultMaxUses, raw.DefaultMaxUses)
	assignInt(&policy.MaxUses, raw.MaxUses)
	if policy.DefaultMinutes < 1 || policy.DefaultMinutes > MaxGrantMinutes {
		return GrantPolicy{}, fmt.Errorf("default_minutes must be between 1 and %d", MaxGrantMinutes)
	}
	if policy.MaxMinutes < policy.DefaultMinutes || policy.MaxMinutes > MaxGrantMinutes {
		return GrantPolicy{}, fmt.Errorf("max_minutes must be between default_minutes and %d", MaxGrantMinutes)
	}
	if policy.RequestTTLMinutes < 1 || policy.RequestTTLMinutes > MaxGrantMinutes {
		return GrantPolicy{}, fmt.Errorf("request_ttl_minutes must be between 1 and %d", MaxGrantMinutes)
	}
	if policy.Mode == GrantModeExecution {
		policy.DefaultMaxUses = 1
		policy.MaxUses = 1
		return policy, nil
	}
	if policy.DefaultMaxUses < 1 || policy.DefaultMaxUses > MaxGrantUses {
		return GrantPolicy{}, fmt.Errorf("default_max_uses must be between 1 and %d", MaxGrantUses)
	}
	if policy.MaxUses < policy.DefaultMaxUses || policy.MaxUses > MaxGrantUses {
		return GrantPolicy{}, fmt.Errorf("max_uses must be between default_max_uses and %d", MaxGrantUses)
	}
	return policy, nil
}

func assignInt(target *int, value *int) {
	if value != nil {
		*target = *value
	}
}

// Rules returns a copy of parsed rules for tests and diagnostics.
func (p Policy) Rules() []Rule {
	return slices.Clone(p.rules)
}

// Decide evaluates req against static rules and generated grants.
func (p Policy) Decide(req Request, grants []Rule, now time.Time, grantRequest bool) Decision {
	if _, ok := operations[req.Operation]; !ok {
		return Decision{Effect: EffectDeny, Reason: "invalid_operation"}
	}
	if err := validateRequestTarget(req.Target); err != nil {
		return Decision{Effect: EffectDeny, Reason: "invalid_target"}
	}
	denyIDs := matchingRuleIDs(p.rules, req, EffectDeny, now)
	if len(denyIDs) > 0 {
		return Decision{Effect: EffectDeny, Reason: "policy_denied", MatchedDenyRuleIDs: denyIDs}
	}
	grantIDs := matchingGeneratedGrantIDs(grants, req, now)
	if len(grantIDs) > 0 {
		return Decision{Effect: EffectAllow, Reason: "grant_allowed", MatchedGrantRuleIDs: grantIDs, GrantID: grantIDs[0]}
	}
	allowIDs := matchingRuleIDs(p.rules, req, EffectAllow, now)
	if len(allowIDs) > 0 {
		return Decision{Effect: EffectAllow, Reason: "policy_allowed", MatchedAllowRuleIDs: allowIDs}
	}
	requestRules := matchingRules(p.rules, req, EffectRequest, now)
	if len(requestRules) > 0 {
		ids := ruleIDs(requestRules)
		policy := requestRules[0].GrantPolicy
		if grantRequest {
			return Decision{Effect: EffectRequest, Reason: "requestable", MatchedRequestRuleIDs: ids, GrantPolicy: policy}
		}
		return Decision{Effect: EffectDeny, Reason: "approval_required", MatchedRequestRuleIDs: ids, GrantPolicy: policy}
	}
	return Decision{Effect: EffectNoMatch, Reason: "no_matching_rule"}
}

func validateRequestTarget(target Target) error {
	switch target.Kind {
	case KindRepo:
		if !validRepoType(target.Type) || target.Type == TypeAny || target.Owner == "" || target.Name == "" {
			return fmt.Errorf("invalid repo target")
		}
	case KindBucket:
		if target.Owner == "" || target.Name == "" {
			return fmt.Errorf("invalid bucket target")
		}
	default:
		return fmt.Errorf("invalid target kind")
	}
	return nil
}

func matchingGeneratedGrantIDs(rules []Rule, req Request, now time.Time) []string {
	var out []string
	for _, rule := range rules {
		if !rule.Generated || rule.Effect != EffectAllow {
			continue
		}
		if !rule.ExpiresAt.IsZero() && !now.Before(rule.ExpiresAt) {
			continue
		}
		if rule.UsesLeft <= 0 {
			continue
		}
		if ruleMatches(rule, req) {
			out = append(out, nonEmpty(rule.GrantID, rule.ID))
		}
	}
	return out
}

func matchingRuleIDs(rules []Rule, req Request, effect Effect, now time.Time) []string {
	return ruleIDs(matchingRules(rules, req, effect, now))
}

func matchingRules(rules []Rule, req Request, effect Effect, _ time.Time) []Rule {
	var out []Rule
	for _, rule := range rules {
		if rule.Generated || rule.Effect != effect {
			continue
		}
		if ruleMatches(rule, req) {
			out = append(out, rule)
		}
	}
	return out
}

func ruleMatches(rule Rule, req Request) bool {
	return clientMatches(rule.Clients, req.Client) &&
		operationMatches(rule.Operations, req.Operation) &&
		anyTargetMatches(rule.Targets, req.Target) &&
		attrsMatch(rule.Attrs, req.Attrs)
}

func clientMatches(patterns []string, client string) bool {
	return slices.Contains(patterns, "*") || slices.Contains(patterns, client)
}

func operationMatches(ops []Operation, op Operation) bool {
	return slices.Contains(ops, op)
}

func anyTargetMatches(targets []TargetMatcher, target Target) bool {
	for _, matcher := range targets {
		if targetMatches(matcher, target) {
			return true
		}
	}
	return false
}

func targetMatches(matcher TargetMatcher, target Target) bool {
	if matcher.Kind != target.Kind {
		return false
	}
	switch target.Kind {
	case KindRepo:
		return repoTargetMatches(matcher, target)
	case KindBucket:
		return bucketTargetMatches(matcher, target)
	default:
		return false
	}
}

func repoTargetMatches(matcher TargetMatcher, target Target) bool {
	return repoTypeMatches(matcher.Type, target.Type) &&
		globMatches(matcher.Owner, target.Owner) &&
		globMatches(matcher.Name, target.Name) &&
		optionalGlobListMatches(matcher.Refs, target.Refs) &&
		optionalGlobListMatches(matcher.Paths, target.Paths) &&
		optionalStringListMatches(matcher.Visibility, target.Visibility)
}

func bucketTargetMatches(matcher TargetMatcher, target Target) bool {
	return globMatches(matcher.Owner, target.Owner) &&
		globMatches(matcher.Name, target.Name) &&
		optionalGlobListMatches(matcher.Keys, target.Keys)
}

func repoTypeMatches(pattern RepoType, actual RepoType) bool {
	return pattern == TypeAny || pattern == actual
}

func optionalGlobListMatches(patterns, actuals []string) bool {
	if len(patterns) == 0 {
		return true
	}
	if len(actuals) == 0 {
		return false
	}
	for _, actual := range actuals {
		matched := false
		for _, pattern := range patterns {
			if globMatches(pattern, actual) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	return true
}

func optionalStringListMatches(patterns, actuals []string) bool {
	if len(patterns) == 0 || slices.Contains(patterns, "*") {
		return true
	}
	for _, actual := range actuals {
		if slices.Contains(patterns, actual) {
			return true
		}
	}
	return false
}

func attrsMatch(ruleAttrs map[string]AttrConstraint, actual map[string]any) bool {
	for key, constraint := range ruleAttrs {
		value, ok := actual[key]
		if !ok {
			return false
		}
		if !attrMatches(constraint, value) {
			return false
		}
	}
	return true
}

func attrMatches(constraint AttrConstraint, actual any) bool {
	if constraint.Number != nil {
		number, ok := int64Value(actual)
		return ok && number <= *constraint.Number
	}
	value, ok := actual.(string)
	if !ok {
		return false
	}
	return slices.Contains(constraint.Values, value)
}

func int64Value(value any) (int64, bool) {
	switch v := value.(type) {
	case int:
		return int64(v), true
	case int64:
		return v, true
	case json.Number:
		n, err := v.Int64()
		return n, err == nil
	default:
		return 0, false
	}
}

func globMatches(patternValue, value string) bool {
	if strings.Contains(patternValue, "**") {
		return doubleStarGlobMatches(patternValue, value)
	}
	matched, err := path.Match(patternValue, value)
	return err == nil && matched
}

func doubleStarGlobMatches(patternValue, value string) bool {
	expr := regexp.QuoteMeta(patternValue)
	expr = strings.ReplaceAll(expr, `\*\*`, ".*")
	expr = strings.ReplaceAll(expr, `\*`, `[^/]*`)
	expr = strings.ReplaceAll(expr, `\?`, `[^/]`)
	matched, err := regexp.MatchString("^"+expr+"$", value)
	return err == nil && matched
}

func validateRequestRuleOverlaps(rules []Rule) error {
	for i := range rules {
		if rules[i].Effect != EffectRequest {
			continue
		}
		for j := i + 1; j < len(rules); j++ {
			if rules[j].Effect != EffectRequest {
				continue
			}
			if requestRulesMayOverlap(rules[i], rules[j]) && !grantPoliciesEqual(rules[i].GrantPolicy, rules[j].GrantPolicy) {
				return fmt.Errorf("scope.json rules[%d]: request rule overlaps rule %s with different grant_policy", j, rules[i].ID)
			}
		}
	}
	return nil
}

func requestRulesMayOverlap(a, b Rule) bool {
	return stringListsMayOverlap(a.Clients, b.Clients) &&
		operationsMayOverlap(a.Operations, b.Operations) &&
		targetListsMayOverlap(a.Targets, b.Targets)
}

func stringListsMayOverlap(a, b []string) bool {
	for _, av := range a {
		for _, bv := range b {
			if av == "*" || bv == "*" || av == bv {
				return true
			}
		}
	}
	return false
}

func operationsMayOverlap(a, b []Operation) bool {
	for _, av := range a {
		if slices.Contains(b, av) {
			return true
		}
	}
	return false
}

func targetListsMayOverlap(a, b []TargetMatcher) bool {
	for _, av := range a {
		for _, bv := range b {
			if targetsMayOverlap(av, bv) {
				return true
			}
		}
	}
	return false
}

func targetsMayOverlap(a, b TargetMatcher) bool {
	if a.Kind != b.Kind {
		return false
	}
	return segmentGlobsMayOverlap(stringOr(string(a.Type), "*"), stringOr(string(b.Type), "*")) &&
		segmentGlobsMayOverlap(a.Owner, b.Owner) &&
		segmentGlobsMayOverlap(a.Name, b.Name)
}

func segmentGlobsMayOverlap(a, b string) bool {
	aWild := strings.ContainsAny(a, "*?")
	bWild := strings.ContainsAny(b, "*?")
	switch {
	case !aWild && !bWild:
		return a == b
	case aWild && !bWild:
		return globMatches(a, b)
	case !aWild && bWild:
		return globMatches(b, a)
	default:
		return true
	}
}

func grantPoliciesEqual(a, b *GrantPolicy) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

func ruleIDs(rules []Rule) []string {
	out := make([]string, 0, len(rules))
	for _, rule := range rules {
		out = append(out, rule.ID)
	}
	return out
}

func nonEmpty(value, fallback string) string {
	if value != "" {
		return value
	}
	return fallback
}

func stringOr(value, fallback string) string {
	if value != "" {
		return value
	}
	return fallback
}

// GeneratedGrantRule builds a generated allow rule for an approved grant.
func GeneratedGrantRule(id string, client string, operation Operation, target Target, expiresAt time.Time, usesLeft int) Rule {
	return Rule{
		ID:         id,
		Effect:     EffectAllow,
		Clients:    []string{client},
		Operations: []Operation{operation},
		Targets: []TargetMatcher{{
			Kind:       target.Kind,
			Type:       target.Type,
			Owner:      target.Owner,
			Name:       target.Name,
			Refs:       slices.Clone(target.Refs),
			Paths:      slices.Clone(target.Paths),
			Visibility: slices.Clone(target.Visibility),
			Keys:       slices.Clone(target.Keys),
		}},
		Generated: true,
		GrantID:   id,
		ExpiresAt: expiresAt,
		UsesLeft:  usesLeft,
	}
}
