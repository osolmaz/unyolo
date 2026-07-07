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
	Client         string
	Operation      Operation
	Target         Target
	Attrs          map[string]any
	IgnoreRepoRefs bool
}

type Target struct {
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

	typeSet           bool
	refsSet           bool
	pathsSet          bool
	visibilitySet     bool
	keysSet           bool
	snapshotPrefixSet bool
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

type targetMatcherJSON struct {
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

type operationInfo struct {
	mode GrantMode
}

type ruleFieldParser func(*Rule, string, rawRule) error

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

var operationFamilyPrefixes = map[string]string{
	"repo.*":   "repo.",
	"git.*":    "git.",
	"bucket.*": "bucket.",
}

var refScopedOperations = map[Operation]bool{
	OpGitPushAppend: true,
	OpGitPushForce:  true,
	OpGitRefDelete:  true,
	OpGitTagUpdate:  true,
}

var validRepoVisibilities = map[string]bool{
	"public":  true,
	"private": true,
	"*":       true,
}

var knownAttrs = map[string]bool{
	"max_bytes":  true,
	"ref_change": true,
}

var validRefChangeAttrs = map[string]bool{
	"create":           true,
	"fast_forward":     true,
	"non_fast_forward": true,
	"delete":           true,
	"tag_update":       true,
}

var targetMatcherFields = map[string]bool{
	"kind":            true,
	"type":            true,
	"owner":           true,
	"name":            true,
	"refs":            true,
	"paths":           true,
	"visibility":      true,
	"keys":            true,
	"snapshot_prefix": true,
}

var ruleFieldParsers = []ruleFieldParser{
	parseRuleID,
	parseRuleEffect,
	parseRuleCollections,
	parseRuleGrantPolicy,
}

// UnmarshalJSON tracks present optional arrays so empty arrays can fail closed
// instead of becoming wildcards after normal struct decoding.
func (target *TargetMatcher) UnmarshalJSON(data []byte) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	if err := rejectUnknownTargetMatcherFields(fields); err != nil {
		return err
	}
	var decoded targetMatcherJSON
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	*target = targetMatcherFromJSON(decoded, fields)
	return nil
}

func rejectUnknownTargetMatcherFields(fields map[string]json.RawMessage) error {
	for field := range fields {
		if !targetMatcherFields[field] {
			return fmt.Errorf("json: unknown field %q", field)
		}
	}
	return nil
}

func targetMatcherFromJSON(decoded targetMatcherJSON, fields map[string]json.RawMessage) TargetMatcher {
	return TargetMatcher{
		Kind:              decoded.Kind,
		Type:              decoded.Type,
		Owner:             decoded.Owner,
		Name:              decoded.Name,
		Refs:              decoded.Refs,
		Paths:             decoded.Paths,
		Visibility:        decoded.Visibility,
		Keys:              decoded.Keys,
		SnapshotPrefix:    decoded.SnapshotPrefix,
		typeSet:           jsonFieldPresent(fields, "type"),
		refsSet:           jsonFieldPresent(fields, "refs"),
		pathsSet:          jsonFieldPresent(fields, "paths"),
		visibilitySet:     jsonFieldPresent(fields, "visibility"),
		keysSet:           jsonFieldPresent(fields, "keys"),
		snapshotPrefixSet: jsonFieldPresent(fields, "snapshot_prefix"),
	}
}

func jsonFieldPresent(fields map[string]json.RawMessage, name string) bool {
	_, ok := fields[name]
	return ok
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
	rule := Rule{Description: raw.Description}
	if err := parseRuleFields(&rule, prefix, raw); err != nil {
		return Rule{}, err
	}
	if err := validateRuleOperationTargets(prefix, rule.Operations, rule.Targets); err != nil {
		return Rule{}, err
	}
	return rule, nil
}

func parseRuleFields(rule *Rule, prefix string, raw rawRule) error {
	for _, parseField := range ruleFieldParsers {
		if err := parseField(rule, prefix, raw); err != nil {
			return err
		}
	}
	return nil
}

func validateRuleOperationTargets(prefix string, ops []Operation, targets []TargetMatcher) error {
	for _, op := range ops {
		want := operationTargetKind(op)
		for i, target := range targets {
			if target.Kind != want {
				return fmt.Errorf("%s.targets[%d]: operation %s requires %s target", prefix, i, op, want)
			}
		}
	}
	return nil
}

func operationTargetKind(op Operation) TargetKind {
	if strings.HasPrefix(string(op), "bucket.") {
		return KindBucket
	}
	return KindRepo
}

func parseRuleID(rule *Rule, prefix string, raw rawRule) error {
	if !validRuleID(raw.ID) {
		return fmt.Errorf("%s.id: must be 1-%d bytes", prefix, MaxRuleIDBytes)
	}
	rule.ID = raw.ID
	return nil
}

func validRuleID(id string) bool {
	return id != "" && len(id) <= MaxRuleIDBytes
}

func parseRuleEffect(rule *Rule, prefix string, raw rawRule) error {
	effect, err := parseEffect(raw.Effect)
	if err != nil {
		return fmt.Errorf("%s.effect: %w", prefix, err)
	}
	rule.Effect = effect
	return nil
}

func parseRuleCollections(rule *Rule, prefix string, raw rawRule) error {
	return runFieldAssignments([]func() error{
		func() error {
			return assignParsed(&rule.Clients, func() ([]string, error) {
				return parseClients(prefix+".clients", raw.Clients)
			})
		},
		func() error {
			return assignParsed(&rule.Operations, func() ([]Operation, error) {
				return parseOperations(prefix+".operations", raw.Operations)
			})
		},
		func() error {
			return assignParsed(&rule.Targets, func() ([]TargetMatcher, error) {
				return parseTargets(prefix+".targets", raw.Targets)
			})
		},
		func() error {
			return assignParsed(&rule.Attrs, func() (map[string]AttrConstraint, error) {
				return parseAttrs(prefix+".attrs", raw.Attrs)
			})
		},
	})
}

func runFieldAssignments(assignments []func() error) error {
	for _, assign := range assignments {
		if err := assign(); err != nil {
			return err
		}
	}
	return nil
}

func assignParsed[T any](target *T, parse func() (T, error)) error {
	value, err := parse()
	if err != nil {
		return err
	}
	*target = value
	return nil
}

func parseRuleGrantPolicy(rule *Rule, prefix string, raw rawRule) error {
	grantPolicy, err := parseGrantPolicy(prefix+".grant_policy", rule.Effect, rule.Operations, raw.GrantPolicy)
	if err != nil {
		return err
	}
	rule.GrantPolicy = grantPolicy
	return nil
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
	if err := validateRequiredCount(path, len(values), MaxClientsPerRule); err != nil {
		return nil, err
	}
	if err := validateUniqueStrings(path, values, validClientName); err != nil {
		return nil, err
	}
	return slices.Clone(values), nil
}

func validateRequiredCount(path string, count, maxCount int) error {
	if count == 0 {
		return fmt.Errorf("%s: must not be empty", path)
	}
	if count > maxCount {
		return fmt.Errorf("%s: count exceeds %d", path, maxCount)
	}
	return nil
}

func validateUniqueStrings(path string, values []string, valid func(string) bool) error {
	seen := map[string]bool{}
	for _, value := range values {
		if !valid(value) {
			return fmt.Errorf("%s: invalid client %q", path, value)
		}
		if seen[value] {
			return fmt.Errorf("%s: duplicate client %q", path, value)
		}
		seen[value] = true
	}
	return nil
}

func validClientName(value string) bool {
	return value != "" && !strings.ContainsAny(value, " \t\r\n")
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
	prefix, ok := operationFamilyPrefixes[value]
	if !ok {
		return nil, fmt.Errorf("invalid operation-family glob %q", value)
	}
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
	if err := validateNoBucketTargetFields(pathName, target); err != nil {
		return err
	}
	if err := validateRepoTargetType(pathName, target.Type); err != nil {
		return err
	}
	if err := validateOwnerNameGlobs(pathName, target.Owner, target.Name); err != nil {
		return err
	}
	if err := validateOptionalGlobList(pathName+".refs", target.Refs, target.refsSet, false); err != nil {
		return err
	}
	if err := validateOptionalGlobList(pathName+".paths", target.Paths, target.pathsSet, true); err != nil {
		return err
	}
	return validateRepoVisibility(pathName, target.Visibility, target.visibilitySet)
}

func validateBucketTarget(pathName string, target *TargetMatcher) error {
	if err := validateNoRepoTargetFields(pathName, target); err != nil {
		return err
	}
	if err := validateBucketTargetType(pathName, target.Type); err != nil {
		return err
	}
	if err := validateOwnerNameGlobs(pathName, target.Owner, target.Name); err != nil {
		return err
	}
	if err := validateOptionalGlobList(pathName+".keys", target.Keys, target.keysSet, true); err != nil {
		return err
	}
	return validateSnapshotPrefix(pathName, target.SnapshotPrefix)
}

func validateNoBucketTargetFields(pathName string, target *TargetMatcher) error {
	if target.keysSet || target.snapshotPrefixSet {
		return fmt.Errorf("%s: repo targets must not set bucket-only fields", pathName)
	}
	return nil
}

func validateNoRepoTargetFields(pathName string, target *TargetMatcher) error {
	if target.typeSet || target.refsSet || target.pathsSet || target.visibilitySet {
		return fmt.Errorf("%s: bucket targets must not set repo-only fields", pathName)
	}
	return nil
}

func validateRepoTargetType(pathName string, repoType RepoType) error {
	if !validRepoType(repoType) {
		return fmt.Errorf("%s.type: must be model, dataset, space, or *", pathName)
	}
	return nil
}

func validateBucketTargetType(pathName string, repoType RepoType) error {
	if repoType != "" {
		return fmt.Errorf("%s.type: bucket targets must not set type", pathName)
	}
	return nil
}

func validateOwnerNameGlobs(pathName, owner, name string) error {
	if err := validateSegmentGlob(pathName+".owner", owner); err != nil {
		return err
	}
	return validateSegmentGlob(pathName+".name", name)
}

func validateRepoVisibility(pathName string, values []string, present bool) error {
	if present && len(values) == 0 {
		return fmt.Errorf("%s.visibility: must not be empty when set", pathName)
	}
	for _, visibility := range values {
		if !validRepoVisibility(visibility) {
			return fmt.Errorf("%s.visibility: unsupported value %q", pathName, visibility)
		}
	}
	return nil
}

func validRepoVisibility(value string) bool {
	return validRepoVisibilities[value]
}

func validateSnapshotPrefix(pathName, value string) error {
	if value == "" {
		return nil
	}
	if strings.HasPrefix(value, "/") || strings.Contains(value, "..") {
		return fmt.Errorf("%s.snapshot_prefix: must be a relative prefix", pathName)
	}
	return nil
}

func validateGlob(pathName, value string, allowDoubleStar bool) error {
	if invalidGlobShape(value) {
		return fmt.Errorf("%s: malformed glob", pathName)
	}
	if containsUnsupportedGlobSyntax(value) {
		return fmt.Errorf("%s: malformed glob", pathName)
	}
	if err := validateGlobSegments(pathName, value); err != nil {
		return err
	}
	if err := validateDoubleStarGlob(pathName, value, allowDoubleStar); err != nil {
		return err
	}
	return validatePathGlobSyntax(pathName, value)
}

func invalidGlobShape(value string) bool {
	return value == "" ||
		len(value) > MaxGlobBytes ||
		strings.Contains(value, "\x00") ||
		strings.HasPrefix(value, "/") ||
		strings.Contains(value, "//")
}

func containsUnsupportedGlobSyntax(value string) bool {
	return strings.ContainsAny(value, `[]\`)
}

func validateGlobSegments(pathName, value string) error {
	for _, segment := range strings.Split(value, "/") {
		if segment == "" || segment == ".." {
			return fmt.Errorf("%s: malformed glob", pathName)
		}
	}
	return nil
}

func validateDoubleStarGlob(pathName, value string, allowDoubleStar bool) error {
	if strings.Contains(value, "**") && !allowDoubleStar {
		return fmt.Errorf("%s: ** is allowed only for path/key globs", pathName)
	}
	return nil
}

func validatePathGlobSyntax(pathName, value string) error {
	if _, err := path.Match(strings.ReplaceAll(value, "**", "*"), value); err != nil {
		return fmt.Errorf("%s: malformed glob", pathName)
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

func validateOptionalGlobList(pathName string, values []string, present, allowDoubleStar bool) error {
	if present && len(values) == 0 {
		return fmt.Errorf("%s: must not be empty when set", pathName)
	}
	return validateGlobList(pathName, values, allowDoubleStar)
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
		if err := validateAttrConstraint(key, parsed); err != nil {
			return nil, fmt.Errorf("%s.%s: %w", pathName, key, err)
		}
		out[key] = parsed
	}
	return out, nil
}

// AttrValuesMatch reports whether actual satisfies every approved attribute.
//
// Approved values use the same constraint syntax as rule attrs: strings match
// exact values, string arrays match any listed value, and numbers are maximums.
func AttrValuesMatch(approved map[string]any, actual map[string]any) bool {
	constraints, err := AttrConstraintsFromValues(approved)
	if err != nil {
		return false
	}
	return attrsMatch(constraints, actual)
}

// AttrConstraintsFromValues parses attribute values into policy constraints.
func AttrConstraintsFromValues(attrs map[string]any) (map[string]AttrConstraint, error) {
	if len(attrs) == 0 {
		return nil, nil
	}
	out := map[string]AttrConstraint{}
	for key, value := range attrs {
		if !knownAttr(key) {
			return nil, fmt.Errorf("%s: unknown attribute", key)
		}
		raw, err := json.Marshal(value)
		if err != nil {
			return nil, fmt.Errorf("%s: invalid attribute value", key)
		}
		parsed, err := parseAttrValue(raw)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", key, err)
		}
		if err := validateAttrConstraint(key, parsed); err != nil {
			return nil, fmt.Errorf("%s: %w", key, err)
		}
		out[key] = parsed
	}
	return out, nil
}

func validateAttrConstraint(key string, constraint AttrConstraint) error {
	switch key {
	case "max_bytes":
		if constraint.Number == nil {
			return fmt.Errorf("must be a non-negative integer")
		}
	case "ref_change":
		if len(constraint.Values) == 0 {
			return fmt.Errorf("must be a ref change value")
		}
		for _, value := range constraint.Values {
			if !validRefChangeAttrs[value] {
				return fmt.Errorf("unsupported ref change %q", value)
			}
		}
	}
	return nil
}

func knownAttr(key string) bool {
	return knownAttrs[key]
}

func parseAttrValue(raw json.RawMessage) (AttrConstraint, error) {
	for _, parser := range attrParsers() {
		parsed, ok, err := parser(raw)
		if ok || err != nil {
			return parsed, err
		}
	}
	return AttrConstraint{}, fmt.Errorf("must be string, string array, or non-negative integer")
}

func attrParsers() []func(json.RawMessage) (AttrConstraint, bool, error) {
	return []func(json.RawMessage) (AttrConstraint, bool, error){
		parseNumberAttr,
		parseStringAttr,
		parseStringArrayAttr,
	}
}

func parseNumberAttr(raw json.RawMessage) (AttrConstraint, bool, error) {
	var number int64
	if err := json.Unmarshal(raw, &number); err == nil {
		if number < 0 {
			return AttrConstraint{}, true, fmt.Errorf("numeric value must be non-negative")
		}
		return AttrConstraint{Number: &number}, true, nil
	}
	return AttrConstraint{}, false, nil
}

func parseStringAttr(raw json.RawMessage) (AttrConstraint, bool, error) {
	var one string
	if err := json.Unmarshal(raw, &one); err == nil {
		if one == "" {
			return AttrConstraint{}, true, fmt.Errorf("string value must not be empty")
		}
		return AttrConstraint{Values: []string{one}}, true, nil
	}
	return AttrConstraint{}, false, nil
}

func parseStringArrayAttr(raw json.RawMessage) (AttrConstraint, bool, error) {
	var many []string
	if err := json.Unmarshal(raw, &many); err == nil {
		if err := validateStringArrayAttr(many); err != nil {
			return AttrConstraint{}, true, err
		}
		return AttrConstraint{Values: many}, true, nil
	}
	return AttrConstraint{}, false, nil
}

func validateStringArrayAttr(values []string) error {
	if len(values) == 0 {
		return fmt.Errorf("array must not be empty")
	}
	for _, value := range values {
		if value == "" {
			return fmt.Errorf("string value must not be empty")
		}
	}
	return nil
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
	if err := validateGrantableOperations(pathName, ops); err != nil {
		return nil, err
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

func validateGrantableOperations(pathName string, ops []Operation) error {
	for _, op := range ops {
		if operations[op].mode == GrantModeNone {
			return fmt.Errorf("%s.mode: operation %s is not grantable", pathName, op)
		}
	}
	return nil
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
	policy := defaultGrantPolicy(defaultMode)
	if err := assignGrantMode(&policy, raw.Mode); err != nil {
		return GrantPolicy{}, err
	}
	assignGrantPolicyInts(&policy, raw)
	defaultGrantMaxUses(&policy, raw)
	if err := validateGrantDurationPolicy(policy); err != nil {
		return GrantPolicy{}, err
	}
	if policy.Mode == GrantModeExecution {
		return executionGrantPolicy(policy), nil
	}
	return policy, validateGrantUsePolicy(policy)
}

func defaultGrantPolicy(mode GrantMode) GrantPolicy {
	return GrantPolicy{
		Mode:              mode,
		DefaultMinutes:    DefaultGrantMinutes,
		MaxMinutes:        MaxGrantMinutes,
		RequestTTLMinutes: DefaultRequestTTL,
		DefaultMaxUses:    DefaultGrantUses,
		MaxUses:           DefaultGrantUses,
	}
}

func assignGrantMode(policy *GrantPolicy, mode *string) error {
	if mode == nil {
		return nil
	}
	switch GrantMode(*mode) {
	case GrantModeWindow, GrantModeExecution:
		policy.Mode = GrantMode(*mode)
		return nil
	default:
		return fmt.Errorf("mode must be window or execution")
	}
}

func assignGrantPolicyInts(policy *GrantPolicy, raw *rawGrantPolicy) {
	assignInt(&policy.DefaultMinutes, raw.DefaultMinutes)
	assignInt(&policy.MaxMinutes, raw.MaxMinutes)
	assignInt(&policy.RequestTTLMinutes, raw.RequestTTLMinutes)
	assignInt(&policy.DefaultMaxUses, raw.DefaultMaxUses)
	assignInt(&policy.MaxUses, raw.MaxUses)
}

func defaultGrantMaxUses(policy *GrantPolicy, raw *rawGrantPolicy) {
	if raw.MaxUses == nil {
		policy.MaxUses = policy.DefaultMaxUses
	}
}

func validateGrantDurationPolicy(policy GrantPolicy) error {
	return validateGrantPolicyBounds([]grantPolicyBound{
		{value: policy.DefaultMinutes, min: 1, max: MaxGrantMinutes, message: "default_minutes must be between 1 and %d"},
		{value: policy.MaxMinutes, min: policy.DefaultMinutes, max: MaxGrantMinutes, message: "max_minutes must be between default_minutes and %d"},
		{value: policy.RequestTTLMinutes, min: 1, max: MaxGrantMinutes, message: "request_ttl_minutes must be between 1 and %d"},
	})
}

func executionGrantPolicy(policy GrantPolicy) GrantPolicy {
	policy.DefaultMaxUses = 1
	policy.MaxUses = 1
	return policy
}

func validateGrantUsePolicy(policy GrantPolicy) error {
	return validateGrantPolicyBounds([]grantPolicyBound{
		{value: policy.DefaultMaxUses, min: 1, max: MaxGrantUses, message: "default_max_uses must be between 1 and %d"},
		{value: policy.MaxUses, min: policy.DefaultMaxUses, max: MaxGrantUses, message: "max_uses must be between default_max_uses and %d"},
	})
}

type grantPolicyBound struct {
	value   int
	min     int
	max     int
	message string
}

func validateGrantPolicyBounds(bounds []grantPolicyBound) error {
	for _, bound := range bounds {
		if bound.invalid() {
			return fmt.Errorf(bound.message, bound.max)
		}
	}
	return nil
}

func (bound grantPolicyBound) invalid() bool {
	return bound.value < bound.min || bound.value > bound.max
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
	return p.decide(req, grants, now, grantRequest, ruleMatches)
}

// DecideReceivePackDiscovery evaluates the ref-less receive-pack discovery
// step. The POST body is still classified and enforced per ref before any
// mutation reaches upstream.
func (p Policy) DecideReceivePackDiscovery(req Request, now time.Time) Decision {
	return p.decide(req, nil, now, false, ruleMatchesReceivePackDiscovery)
}

func (p Policy) decide(req Request, grants []Rule, now time.Time, grantRequest bool, matches ruleMatcher) Decision {
	if _, ok := operations[req.Operation]; !ok {
		return Decision{Effect: EffectDeny, Reason: "invalid_operation"}
	}
	if err := validateRequestTarget(req.Target); err != nil {
		return Decision{Effect: EffectDeny, Reason: "invalid_target"}
	}
	denyIDs := matchingRuleIDs(p.rules, req, EffectDeny, now, matches)
	if len(denyIDs) > 0 {
		return Decision{Effect: EffectDeny, Reason: "policy_denied", MatchedDenyRuleIDs: denyIDs}
	}
	grantIDs := matchingGeneratedGrantIDs(grants, req, now, matches)
	if len(grantIDs) > 0 {
		return Decision{Effect: EffectAllow, Reason: "grant_allowed", MatchedGrantRuleIDs: grantIDs, GrantID: grantIDs[0]}
	}
	allowIDs := matchingRuleIDs(p.rules, req, EffectAllow, now, matches)
	if len(allowIDs) > 0 {
		return Decision{Effect: EffectAllow, Reason: "policy_allowed", MatchedAllowRuleIDs: allowIDs}
	}
	requestRules := matchingRules(p.rules, req, EffectRequest, now, matches)
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
		return validateRepoRequestTarget(target)
	case KindBucket:
		return validateBucketRequestTarget(target)
	default:
		return fmt.Errorf("invalid target kind")
	}
}

func validateRepoRequestTarget(target Target) error {
	if !validConcreteRepoType(target.Type) || !validRequestSegment(target.Owner) || !validRequestSegment(target.Name) {
		return fmt.Errorf("invalid repo target")
	}
	return nil
}

func validateBucketRequestTarget(target Target) error {
	if !validRequestSegment(target.Owner) || !validRequestSegment(target.Name) {
		return fmt.Errorf("invalid bucket target")
	}
	return nil
}

func validRequestSegment(value string) bool {
	return value != "" &&
		value != ".." &&
		!strings.Contains(value, "/") &&
		!strings.Contains(value, "\x00")
}

func validConcreteRepoType(value RepoType) bool {
	return validRepoType(value) && value != TypeAny
}

type ruleMatcher func(Rule, Request) bool

func matchingGeneratedGrantIDs(rules []Rule, req Request, now time.Time, matches ruleMatcher) []string {
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
		if matches(rule, req) {
			out = append(out, nonEmpty(rule.GrantID, rule.ID))
		}
	}
	return out
}

func matchingRuleIDs(rules []Rule, req Request, effect Effect, now time.Time, matches ruleMatcher) []string {
	return ruleIDs(matchingRules(rules, req, effect, now, matches))
}

func matchingRules(rules []Rule, req Request, effect Effect, _ time.Time, matches ruleMatcher) []Rule {
	var out []Rule
	for _, rule := range rules {
		if rule.Generated || rule.Effect != effect {
			continue
		}
		if matches(rule, req) {
			out = append(out, rule)
		}
	}
	return out
}

func ruleMatches(rule Rule, req Request) bool {
	return ruleMatchesClientOperation(rule, req) &&
		anyRuleTargetMatches(rule, req) &&
		ruleAttrsMatch(rule, req)
}

func ruleMatchesReceivePackDiscovery(rule Rule, req Request) bool {
	return ruleMatchesClientOperation(rule, req) &&
		anyReceivePackDiscoveryTargetMatches(rule, req.Target)
}

func ruleMatchesClientOperation(rule Rule, req Request) bool {
	return clientMatches(rule.Clients, req.Client) &&
		operationMatches(rule.Operations, req.Operation)
}

func clientMatches(patterns []string, client string) bool {
	return slices.Contains(patterns, "*") || slices.Contains(patterns, client)
}

func operationMatches(ops []Operation, op Operation) bool {
	return slices.Contains(ops, op)
}

func anyRuleTargetMatches(rule Rule, req Request) bool {
	for _, matcher := range rule.Targets {
		if refLessSupportTrafficSkipsMatcher(rule, req, matcher) {
			continue
		}
		if targetMatches(matcher, req) {
			return true
		}
	}
	return false
}

func refLessSupportTrafficSkipsMatcher(rule Rule, req Request, matcher TargetMatcher) bool {
	return req.IgnoreRepoRefs &&
		rule.Effect == EffectDeny &&
		matcher.Kind == KindRepo &&
		len(matcher.Refs) > 0
}

func anyReceivePackDiscoveryTargetMatches(rule Rule, target Target) bool {
	for _, matcher := range rule.Targets {
		if receivePackDiscoveryTargetEligible(rule, matcher) && repoTargetMatchesReceivePackDiscovery(matcher, target) {
			return true
		}
	}
	return false
}

func receivePackDiscoveryTargetEligible(rule Rule, matcher TargetMatcher) bool {
	if rule.Effect != EffectDeny {
		return true
	}
	return len(rule.Attrs) == 0 &&
		len(matcher.Refs) == 0 &&
		len(matcher.Paths) == 0 &&
		len(matcher.Visibility) == 0
}

func targetMatches(matcher TargetMatcher, req Request) bool {
	target := req.Target
	if matcher.Kind != target.Kind {
		return false
	}
	switch target.Kind {
	case KindRepo:
		return repoTargetMatches(matcher, target, req.Operation, req.IgnoreRepoRefs)
	case KindBucket:
		return bucketTargetMatches(matcher, target, req.Operation)
	default:
		return false
	}
}

func repoTargetMatches(matcher TargetMatcher, target Target, operation Operation, ignoreRefs bool) bool {
	return repoTypeMatches(matcher.Type, target.Type) &&
		namedTargetMatches(matcher, target) &&
		repoRefsMatch(operation, matcher.Refs, target.Refs, ignoreRefs) &&
		optionalGlobListMatches(matcher.Paths, target.Paths) &&
		optionalStringListMatches(matcher.Visibility, target.Visibility)
}

func repoRefsMatch(operation Operation, patterns, actuals []string, ignoreRefs bool) bool {
	if ignoreRefs || !operationUsesRefs(operation) {
		return true
	}
	return optionalGlobListMatches(patterns, actuals)
}

func operationUsesRefs(operation Operation) bool {
	return refScopedOperations[operation]
}

func repoTargetMatchesReceivePackDiscovery(matcher TargetMatcher, target Target) bool {
	return matcher.Kind == KindRepo &&
		target.Kind == KindRepo &&
		repoTypeMatches(matcher.Type, target.Type) &&
		namedTargetMatches(matcher, target)
}

func bucketTargetMatches(matcher TargetMatcher, target Target, operation Operation) bool {
	return namedTargetMatches(matcher, target) &&
		bucketSnapshotPrefixAllows(matcher.SnapshotPrefix, target.Keys, operation) &&
		optionalGlobListMatches(matcher.Keys, target.Keys)
}

func bucketSnapshotPrefixAllows(prefix string, keys []string, operation Operation) bool {
	if prefix == "" || !bucketOperationMutatesObjects(operation) {
		return true
	}
	for _, key := range keys {
		if keyUnderSnapshotPrefix(key, prefix) {
			return false
		}
	}
	return true
}

func bucketOperationMutatesObjects(operation Operation) bool {
	return operation == OpBucketObjectWrite || operation == OpBucketObjectDel
}

func keyUnderSnapshotPrefix(key, prefix string) bool {
	prefix = strings.TrimSuffix(prefix, "/")
	return key == prefix || strings.HasPrefix(key, prefix+"/")
}

func namedTargetMatches(matcher TargetMatcher, target Target) bool {
	if !globMatches(matcher.Owner, target.Owner) {
		return false
	}
	return globMatches(matcher.Name, target.Name)
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
	if optionalStringListIsWildcard(patterns) {
		return true
	}
	return anyStringListValueMatches(patterns, actuals)
}

func optionalStringListIsWildcard(patterns []string) bool {
	return len(patterns) == 0 || slices.Contains(patterns, "*")
}

func anyStringListValueMatches(patterns, actuals []string) bool {
	return anyContained(actuals, patterns)
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

func ruleAttrsMatch(rule Rule, req Request) bool {
	for key, constraint := range rule.Attrs {
		if refLessSupportTrafficSkipsAttr(rule, req, key) {
			continue
		}
		value, ok := req.Attrs[key]
		if !ok {
			return false
		}
		if !attrMatches(constraint, value) {
			return false
		}
	}
	return true
}

func refLessSupportTrafficSkipsAttr(rule Rule, req Request, key string) bool {
	return rule.Effect != EffectDeny && req.IgnoreRepoRefs && key == "ref_change"
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
		targetListsMayOverlap(a.Targets, b.Targets) &&
		attrsMayOverlap(a.Attrs, b.Attrs)
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
	return anyContained(a, b)
}

func anyContained[T comparable](values, allowed []T) bool {
	for _, value := range values {
		if slices.Contains(allowed, value) {
			return true
		}
	}
	return false
}

func attrsMayOverlap(a, b map[string]AttrConstraint) bool {
	for key, av := range a {
		if bv, ok := b[key]; ok && !attrConstraintsMayOverlap(av, bv) {
			return false
		}
	}
	return true
}

func attrConstraintsMayOverlap(a, b AttrConstraint) bool {
	if a.Number != nil || b.Number != nil {
		return a.Number != nil && b.Number != nil
	}
	return anyContained(a.Values, b.Values)
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
	return a.Kind == b.Kind &&
		targetIdentityMayOverlap(a, b) &&
		targetConstraintsMayOverlap(a, b)
}

func targetIdentityMayOverlap(a, b TargetMatcher) bool {
	return allOverlap(
		globPatternsMayOverlap(nonEmpty(string(a.Type), "*"), nonEmpty(string(b.Type), "*")),
		globPatternsMayOverlap(a.Owner, b.Owner),
		globPatternsMayOverlap(a.Name, b.Name),
	)
}

func targetConstraintsMayOverlap(a, b TargetMatcher) bool {
	switch a.Kind {
	case KindRepo:
		return repoTargetConstraintsMayOverlap(a, b)
	case KindBucket:
		return bucketTargetConstraintsMayOverlap(a, b)
	default:
		return true
	}
}

func repoTargetConstraintsMayOverlap(a, b TargetMatcher) bool {
	return allOverlap(
		optionalGlobListsMayOverlap(a.Refs, b.Refs),
		optionalGlobListsMayOverlap(a.Paths, b.Paths),
		optionalStringListsMayOverlap(a.Visibility, b.Visibility),
	)
}

func bucketTargetConstraintsMayOverlap(a, b TargetMatcher) bool {
	return allOverlap(
		optionalGlobListsMayOverlap(a.Keys, b.Keys),
		optionalPrefixesMayOverlap(a.SnapshotPrefix, b.SnapshotPrefix),
	)
}

func allOverlap(values ...bool) bool {
	for _, value := range values {
		if !value {
			return false
		}
	}
	return true
}

func optionalGlobListsMayOverlap(a, b []string) bool {
	if len(a) == 0 || len(b) == 0 {
		return true
	}
	for _, av := range a {
		for _, bv := range b {
			if globPatternsMayOverlap(av, bv) {
				return true
			}
		}
	}
	return false
}

func optionalStringListsMayOverlap(a, b []string) bool {
	if len(a) == 0 || len(b) == 0 || slices.Contains(a, "*") || slices.Contains(b, "*") {
		return true
	}
	return anyContained(a, b)
}

func optionalPrefixesMayOverlap(a, b string) bool {
	return a == "" || b == "" || strings.HasPrefix(a, b) || strings.HasPrefix(b, a)
}

func segmentGlobsMayOverlap(a, b string) bool {
	return globPatternsMayOverlap(a, b)
}

func globPatternsMayOverlap(a, b string) bool {
	aWild := strings.ContainsAny(a, "*?")
	bWild := strings.ContainsAny(b, "*?")
	if !aWild && !bWild {
		return a == b
	}
	return wildcardPatternsMayOverlap(a, b, aWild, bWild)
}

func wildcardPatternsMayOverlap(a, b string, aWild, bWild bool) bool {
	if aWild && !bWild {
		return globMatches(a, b)
	}
	if !aWild && bWild {
		return globMatches(b, a)
	}
	return true
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
