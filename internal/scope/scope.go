// Package scope models the hand-edited scope.json file and decides which
// operations are allowed against which targets.
//
// The file is loaded once at startup; there is deliberately no API to
// read or change it at runtime. Parsing fails closed: unknown fields,
// malformed ids, and invalid modes all reject the whole file.
package scope

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
)

// RepoType is the Hub repository kind; it determines the upstream URL prefix.
type RepoType string

// Supported repository types.
const (
	TypeModel   RepoType = "model"
	TypeDataset RepoType = "dataset"
	TypeSpace   RepoType = "space"
)

// Mode is a target's standing access mode. There is intentionally no
// full-write mode; anything beyond append-only is a grant (level 4).
type Mode string

// Supported modes.
const (
	ModeReadOnly   Mode = "read-only"
	ModeAppendOnly Mode = "append-only"
)

const (
	// DefaultGrantMinutes is the normal grant duration when policy omits it.
	DefaultGrantMinutes = 5
	// MaxGrantMinutes is the hard cap for any grant duration.
	MaxGrantMinutes = 60
	// DefaultGrantUses is the normal use budget for window grants.
	DefaultGrantUses = 1
	// MaxGrantUses is the largest use budget accepted in scope policy.
	MaxGrantUses = 25
)

// Repo is one in-scope git repository.
type Repo struct {
	Owner       string
	Name        string
	Type        RepoType
	Mode        Mode
	GrantPolicy RepoGrantPolicy
}

// Bucket is one in-scope bucket (enforced by the bucket proxy, M2).
type Bucket struct {
	Owner          string
	Name           string
	Mode           Mode
	SnapshotPrefix string
	GrantPolicy    BucketGrantPolicy
}

// RepoGrantPolicy configures optional grantable operations for one repo entry.
type RepoGrantPolicy struct {
	GitHistoryRewrite    *GrantUsePolicy          `json:"git_history_rewrite,omitempty"`
	GitRefDelete         *GrantUsePolicy          `json:"git_ref_delete,omitempty"`
	GitTagUpdate         *GrantUsePolicy          `json:"git_tag_update,omitempty"`
	RepoCreatePrivate    *ExecutionGrantPolicy    `json:"repo_create_private,omitempty"`
	RepoMetadataUpdate   *ExecutionGrantPolicy    `json:"repo_metadata_update,omitempty"`
	RepoVisibilityUpdate *RepoVisibilityGrantSpec `json:"repo_visibility_update,omitempty"`
}

// BucketGrantPolicy configures optional grantable operations for one bucket.
type BucketGrantPolicy struct {
	BucketDelete *BucketDeleteGrantSpec `json:"bucket_delete,omitempty"`
}

// GrantUsePolicy configures a time-boxed grant that can be used more than once.
type GrantUsePolicy struct {
	DefaultMinutes int `json:"default_minutes"`
	MaxMinutes     int `json:"max_minutes"`
	DefaultMaxUses int `json:"default_max_uses"`
	MaxUses        int `json:"max_uses"`

	defaultMinutesSet bool
	maxMinutesSet     bool
	defaultMaxUsesSet bool
	maxUsesSet        bool
}

// ExecutionGrantPolicy configures a single broker-executed grant plan.
type ExecutionGrantPolicy struct {
	DefaultMinutes int `json:"default_minutes"`
	MaxMinutes     int `json:"max_minutes"`

	defaultMinutesSet bool
	maxMinutesSet     bool
}

// RepoVisibilityGrantSpec configures allowed visibility changes.
type RepoVisibilityGrantSpec struct {
	DefaultMinutes int      `json:"default_minutes"`
	MaxMinutes     int      `json:"max_minutes"`
	Allowed        []string `json:"allowed"`

	defaultMinutesSet bool
	maxMinutesSet     bool
}

// BucketDeleteGrantSpec configures allowed bucket deletion shapes.
type BucketDeleteGrantSpec struct {
	DefaultMinutes int      `json:"default_minutes"`
	MaxMinutes     int      `json:"max_minutes"`
	Allowed        []string `json:"allowed"`

	defaultMinutesSet bool
	maxMinutesSet     bool
}

// Scope is the parsed, validated scope file.
type Scope struct {
	repos   map[string]Repo
	buckets map[string]Bucket
}

var namePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

type repoJSON struct {
	ID          string           `json:"id"`
	Type        string           `json:"type"`
	Mode        string           `json:"mode"`
	GrantPolicy *RepoGrantPolicy `json:"grant_policy"`
}

type bucketJSON struct {
	ID             string             `json:"id"`
	Mode           string             `json:"mode"`
	SnapshotPrefix string             `json:"snapshot_prefix"`
	GrantPolicy    *BucketGrantPolicy `json:"grant_policy"`
}

type scopeJSON struct {
	Repos   []repoJSON   `json:"repos"`
	Buckets []bucketJSON `json:"buckets"`
}

type grantUsePolicyJSON struct {
	DefaultMinutes *int `json:"default_minutes"`
	MaxMinutes     *int `json:"max_minutes"`
	DefaultMaxUses *int `json:"default_max_uses"`
	MaxUses        *int `json:"max_uses"`
}

type timedPolicyJSON struct {
	DefaultMinutes *int `json:"default_minutes"`
	MaxMinutes     *int `json:"max_minutes"`
}

type timedAllowedPolicyJSON struct {
	DefaultMinutes *int     `json:"default_minutes"`
	MaxMinutes     *int     `json:"max_minutes"`
	Allowed        []string `json:"allowed"`
}

func (p *GrantUsePolicy) UnmarshalJSON(data []byte) error {
	return unmarshalGrantUsePolicy(data, p)
}

func (p *ExecutionGrantPolicy) UnmarshalJSON(data []byte) error {
	return unmarshalExecutionGrantPolicy(data, p)
}

func (p *RepoVisibilityGrantSpec) UnmarshalJSON(data []byte) error {
	return unmarshalTimedAllowedPolicy(data, p)
}

func (p *BucketDeleteGrantSpec) UnmarshalJSON(data []byte) error {
	return unmarshalTimedAllowedPolicy(data, p)
}

// These custom decoders keep explicit zero values fail-closed while omitted
// fields still receive defaults during normalization.
func unmarshalGrantUsePolicy(data []byte, policy *GrantUsePolicy) error {
	var raw grantUsePolicyJSON
	if err := decodeStrictJSON(data, &raw); err != nil {
		return err
	}
	*policy = GrantUsePolicy{}
	assignOptionalInt(&policy.DefaultMinutes, &policy.defaultMinutesSet, raw.DefaultMinutes)
	assignOptionalInt(&policy.MaxMinutes, &policy.maxMinutesSet, raw.MaxMinutes)
	assignOptionalInt(&policy.DefaultMaxUses, &policy.defaultMaxUsesSet, raw.DefaultMaxUses)
	assignOptionalInt(&policy.MaxUses, &policy.maxUsesSet, raw.MaxUses)
	return nil
}

func unmarshalExecutionGrantPolicy(data []byte, policy *ExecutionGrantPolicy) error {
	var raw timedPolicyJSON
	if err := decodeStrictJSON(data, &raw); err != nil {
		return err
	}
	*policy = ExecutionGrantPolicy{}
	assignTimedPolicy(&policy.DefaultMinutes, &policy.defaultMinutesSet, &policy.MaxMinutes, &policy.maxMinutesSet, raw)
	return nil
}

func unmarshalTimedAllowedPolicy(data []byte, target any) error {
	var raw timedAllowedPolicyJSON
	if err := decodeStrictJSON(data, &raw); err != nil {
		return err
	}
	assignTimedAllowedPolicy(target, raw)
	return nil
}

func assignTimedAllowedPolicy(target any, raw timedAllowedPolicyJSON) {
	switch policy := target.(type) {
	case *RepoVisibilityGrantSpec:
		*policy = RepoVisibilityGrantSpec{Allowed: raw.Allowed}
		assignTimedPolicy(&policy.DefaultMinutes, &policy.defaultMinutesSet, &policy.MaxMinutes, &policy.maxMinutesSet, timedPolicy(raw))
	case *BucketDeleteGrantSpec:
		*policy = BucketDeleteGrantSpec{Allowed: raw.Allowed}
		assignTimedPolicy(&policy.DefaultMinutes, &policy.defaultMinutesSet, &policy.MaxMinutes, &policy.maxMinutesSet, timedPolicy(raw))
	}
}

func timedPolicy(raw timedAllowedPolicyJSON) timedPolicyJSON {
	return timedPolicyJSON{DefaultMinutes: raw.DefaultMinutes, MaxMinutes: raw.MaxMinutes}
}

func assignTimedPolicy(defaultValue *int, defaultSet *bool, maxValue *int, maxSet *bool, raw timedPolicyJSON) {
	assignOptionalInt(defaultValue, defaultSet, raw.DefaultMinutes)
	assignOptionalInt(maxValue, maxSet, raw.MaxMinutes)
}

// LoadFile reads and parses the scope file at path.
func LoadFile(path string) (Scope, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- operator-configured path from the environment.
	if err != nil {
		return Scope{}, fmt.Errorf("read scope file: %w", err)
	}
	return Parse(data)
}

// Parse parses scope.json content, rejecting unknown fields.
func Parse(data []byte) (Scope, error) {
	raw, err := decodeScopeJSON(data)
	if err != nil {
		return Scope{}, err
	}
	return buildScope(raw)
}

func decodeScopeJSON(data []byte) (scopeJSON, error) {
	var raw scopeJSON
	if err := decodeStrictJSON(data, &raw); err != nil {
		return scopeJSON{}, fmt.Errorf("parse scope file: %w", err)
	}
	return raw, nil
}

func decodeStrictJSON(data []byte, out any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(out); err != nil {
		return err
	}
	var trailing struct{}
	if err := decoder.Decode(&trailing); err != io.EOF {
		return fmt.Errorf("trailing content")
	}
	return nil
}

func assignOptionalInt(target *int, present *bool, value *int) {
	if value == nil {
		return
	}
	*target = *value
	*present = true
}

func buildScope(raw scopeJSON) (Scope, error) {
	scope := Scope{repos: map[string]Repo{}, buckets: map[string]Bucket{}}
	for _, entry := range raw.Repos {
		repo, err := parseRepo(entry)
		if err != nil {
			return Scope{}, err
		}
		key := repoKey(repo.Type, repo.Owner, repo.Name)
		if _, exists := scope.repos[key]; exists {
			return Scope{}, fmt.Errorf("duplicate repo %q", entry.ID)
		}
		scope.repos[key] = repo
	}
	for _, entry := range raw.Buckets {
		bucket, err := parseBucket(entry)
		if err != nil {
			return Scope{}, err
		}
		key := entry.ID
		if _, exists := scope.buckets[key]; exists {
			return Scope{}, fmt.Errorf("duplicate bucket %q", entry.ID)
		}
		scope.buckets[key] = bucket
	}
	return scope, nil
}

func parseRepo(entry repoJSON) (Repo, error) {
	owner, name, err := splitID(entry.ID)
	if err != nil {
		return Repo{}, fmt.Errorf("repo %q: %w", entry.ID, err)
	}
	repoType := RepoType(entry.Type)
	switch repoType {
	case TypeModel, TypeDataset, TypeSpace:
	default:
		return Repo{}, fmt.Errorf("repo %q: type must be model, dataset, or space", entry.ID)
	}
	mode, err := parseMode(entry.Mode)
	if err != nil {
		return Repo{}, fmt.Errorf("repo %q: %w", entry.ID, err)
	}
	grantPolicy, err := normalizeRepoGrantPolicy(entry.GrantPolicy)
	if err != nil {
		return Repo{}, fmt.Errorf("repo %q: %w", entry.ID, err)
	}
	return Repo{Owner: owner, Name: name, Type: repoType, Mode: mode, GrantPolicy: grantPolicy}, nil
}

func parseBucket(entry bucketJSON) (Bucket, error) {
	owner, name, err := splitID(entry.ID)
	if err != nil {
		return Bucket{}, fmt.Errorf("bucket %q: %w", entry.ID, err)
	}
	mode, err := parseMode(entry.Mode)
	if err != nil {
		return Bucket{}, fmt.Errorf("bucket %q: %w", entry.ID, err)
	}
	prefix, err := normalizeSnapshotPrefix(entry.ID, entry.SnapshotPrefix)
	if err != nil {
		return Bucket{}, err
	}
	grantPolicy, err := normalizeBucketGrantPolicy(entry.GrantPolicy)
	if err != nil {
		return Bucket{}, fmt.Errorf("bucket %q: %w", entry.ID, err)
	}
	return Bucket{Owner: owner, Name: name, Mode: mode, SnapshotPrefix: prefix, GrantPolicy: grantPolicy}, nil
}

func normalizeSnapshotPrefix(bucketID, prefix string) (string, error) {
	if prefix == "" {
		prefix = "snapshots/"
	}
	if !strings.HasSuffix(prefix, "/") || strings.HasPrefix(prefix, "/") || strings.Contains(prefix, "..") {
		return "", fmt.Errorf("bucket %q: snapshot_prefix must be a relative prefix ending with /", bucketID)
	}
	return prefix, nil
}

func parseMode(value string) (Mode, error) {
	switch Mode(value) {
	case ModeReadOnly, ModeAppendOnly:
		return Mode(value), nil
	case "":
		return ModeAppendOnly, nil
	default:
		return "", fmt.Errorf("mode must be read-only or append-only, got %q", value)
	}
}

func normalizeRepoGrantPolicy(policy *RepoGrantPolicy) (RepoGrantPolicy, error) {
	if policy == nil {
		return RepoGrantPolicy{}, nil
	}
	if !repoGrantPolicyConfigured(policy) {
		return RepoGrantPolicy{}, fmt.Errorf("grant_policy must configure at least one action")
	}
	if err := normalizeRepoGrantActions(policy); err != nil {
		return RepoGrantPolicy{}, err
	}
	return *policy, nil
}

func repoGrantPolicyConfigured(policy *RepoGrantPolicy) bool {
	return policy.GitHistoryRewrite != nil ||
		policy.GitRefDelete != nil ||
		policy.GitTagUpdate != nil ||
		policy.RepoCreatePrivate != nil ||
		policy.RepoMetadataUpdate != nil ||
		policy.RepoVisibilityUpdate != nil
}

func normalizeRepoGrantActions(policy *RepoGrantPolicy) error {
	if err := normalizeRepoGitGrantActions(policy); err != nil {
		return err
	}
	if err := normalizeRepoExecutionGrantActions(policy); err != nil {
		return err
	}
	if err := normalizeRepoVisibilityGrantPolicy(policy.RepoVisibilityUpdate); err != nil {
		return err
	}
	return nil
}

func normalizeRepoGitGrantActions(policy *RepoGrantPolicy) error {
	for _, item := range []struct {
		name   string
		policy *GrantUsePolicy
	}{
		{name: "grant_policy.git_history_rewrite", policy: policy.GitHistoryRewrite},
		{name: "grant_policy.git_ref_delete", policy: policy.GitRefDelete},
		{name: "grant_policy.git_tag_update", policy: policy.GitTagUpdate},
	} {
		if err := normalizeGrantUsePolicy(item.name, item.policy); err != nil {
			return err
		}
	}
	return nil
}

func normalizeRepoExecutionGrantActions(policy *RepoGrantPolicy) error {
	for _, item := range []struct {
		name   string
		policy *ExecutionGrantPolicy
	}{
		{name: "grant_policy.repo_create_private", policy: policy.RepoCreatePrivate},
		{name: "grant_policy.repo_metadata_update", policy: policy.RepoMetadataUpdate},
	} {
		if err := normalizeExecutionGrantPolicy(item.name, item.policy); err != nil {
			return err
		}
	}
	return nil
}

func normalizeBucketGrantPolicy(policy *BucketGrantPolicy) (BucketGrantPolicy, error) {
	if policy == nil {
		return BucketGrantPolicy{}, nil
	}
	if policy.BucketDelete == nil {
		return BucketGrantPolicy{}, fmt.Errorf("grant_policy must configure at least one action")
	}
	if err := normalizeBucketDeleteGrantPolicy(policy.BucketDelete); err != nil {
		return BucketGrantPolicy{}, err
	}
	return *policy, nil
}

func normalizeGrantUsePolicy(name string, policy *GrantUsePolicy) error {
	if policy == nil {
		return nil
	}
	defaultMinutes, maxMinutes, err := normalizeGrantBounds(grantBoundsConfig{
		name:            name,
		defaultField:    "default_minutes",
		maxField:        "max_minutes",
		defaultValue:    policy.DefaultMinutes,
		maxValue:        policy.MaxMinutes,
		defaultSet:      policy.defaultMinutesSet,
		maxSet:          policy.maxMinutesSet,
		defaultFallback: DefaultGrantMinutes,
		maxFallback:     MaxGrantMinutes,
		hardMax:         MaxGrantMinutes,
	})
	if err != nil {
		return err
	}
	defaultUses, maxUses, err := normalizeGrantBounds(grantBoundsConfig{
		name:            name,
		defaultField:    "default_max_uses",
		maxField:        "max_uses",
		defaultValue:    policy.DefaultMaxUses,
		maxValue:        policy.MaxUses,
		defaultSet:      policy.defaultMaxUsesSet,
		maxSet:          policy.maxUsesSet,
		defaultFallback: DefaultGrantUses,
		hardMax:         MaxGrantUses,
	})
	if err != nil {
		return err
	}
	policy.DefaultMinutes = defaultMinutes
	policy.MaxMinutes = maxMinutes
	policy.DefaultMaxUses = defaultUses
	policy.MaxUses = maxUses
	return nil
}

func normalizeExecutionGrantPolicy(name string, policy *ExecutionGrantPolicy) error {
	if policy == nil {
		return nil
	}
	return applyExecutionGrantMinutes(name, policy)
}

func applyExecutionGrantMinutes(name string, policy *ExecutionGrantPolicy) error {
	defaultMinutes, maxMinutes, err := normalizeGrantBounds(grantBoundsConfig{
		name:            name,
		defaultField:    "default_minutes",
		maxField:        "max_minutes",
		defaultValue:    policy.DefaultMinutes,
		maxValue:        policy.MaxMinutes,
		defaultSet:      policy.defaultMinutesSet,
		maxSet:          policy.maxMinutesSet,
		defaultFallback: DefaultGrantMinutes,
		maxFallback:     MaxGrantMinutes,
		hardMax:         MaxGrantMinutes,
	})
	if err != nil {
		return err
	}
	policy.DefaultMinutes = defaultMinutes
	policy.MaxMinutes = maxMinutes
	return nil
}

func normalizeRepoVisibilityGrantPolicy(policy *RepoVisibilityGrantSpec) error {
	if policy == nil {
		return nil
	}
	normalized, err := normalizeGrantEnumPolicy("grant_policy.repo_visibility_update", policy.DefaultMinutes, policy.MaxMinutes, policy.Allowed, map[string]bool{
		"private_to_public": true,
		"public_to_private": true,
	}, policy.defaultMinutesSet, policy.maxMinutesSet)
	if err != nil {
		return err
	}
	policy.DefaultMinutes = normalized.defaultMinutes
	policy.MaxMinutes = normalized.maxMinutes
	policy.Allowed = normalized.allowed
	return nil
}

func normalizeBucketDeleteGrantPolicy(policy *BucketDeleteGrantSpec) error {
	normalized, err := normalizeGrantEnumPolicy("grant_policy.bucket_delete", policy.DefaultMinutes, policy.MaxMinutes, policy.Allowed, map[string]bool{
		"object": true,
		"prefix": true,
	}, policy.defaultMinutesSet, policy.maxMinutesSet)
	if err != nil {
		return err
	}
	policy.DefaultMinutes = normalized.defaultMinutes
	policy.MaxMinutes = normalized.maxMinutes
	policy.Allowed = normalized.allowed
	return nil
}

type normalizedGrantEnumPolicy struct {
	defaultMinutes int
	maxMinutes     int
	allowed        []string
}

func normalizeGrantEnumPolicy(name string, defaultMinutes, maxMinutes int, values []string, allowed map[string]bool, defaultMinutesSet, maxMinutesSet bool) (normalizedGrantEnumPolicy, error) {
	defaultMinutes, maxMinutes, err := normalizeGrantBounds(grantBoundsConfig{
		name:            name,
		defaultField:    "default_minutes",
		maxField:        "max_minutes",
		defaultValue:    defaultMinutes,
		maxValue:        maxMinutes,
		defaultSet:      defaultMinutesSet,
		maxSet:          maxMinutesSet,
		defaultFallback: DefaultGrantMinutes,
		maxFallback:     MaxGrantMinutes,
		hardMax:         MaxGrantMinutes,
	})
	if err != nil {
		return normalizedGrantEnumPolicy{}, err
	}
	values, err = normalizeGrantEnumList(name+".allowed", values, allowed)
	if err != nil {
		return normalizedGrantEnumPolicy{}, err
	}
	return normalizedGrantEnumPolicy{defaultMinutes: defaultMinutes, maxMinutes: maxMinutes, allowed: values}, nil
}

type grantBoundsConfig struct {
	name            string
	defaultField    string
	maxField        string
	defaultValue    int
	maxValue        int
	defaultSet      bool
	maxSet          bool
	defaultFallback int
	maxFallback     int
	hardMax         int
}

func normalizeGrantBounds(cfg grantBoundsConfig) (int, int, error) {
	defaultValue, err := normalizeGrantDefault(cfg)
	if err != nil {
		return 0, 0, err
	}
	maxValue := normalizeGrantMax(cfg, defaultValue)
	if maxValue < defaultValue || maxValue > cfg.hardMax {
		return 0, 0, fmt.Errorf("%s.%s must be between %s and %d", cfg.name, cfg.maxField, cfg.defaultField, cfg.hardMax)
	}
	return defaultValue, maxValue, nil
}

func normalizeGrantDefault(cfg grantBoundsConfig) (int, error) {
	value := cfg.defaultValue
	if !cfg.defaultSet && value == 0 {
		value = cfg.defaultFallback
	}
	if value < 1 || value > cfg.hardMax {
		return 0, fmt.Errorf("%s.%s must be between 1 and %d", cfg.name, cfg.defaultField, cfg.hardMax)
	}
	return value, nil
}

func normalizeGrantMax(cfg grantBoundsConfig, defaultValue int) int {
	if cfg.maxSet || cfg.maxValue != 0 {
		return cfg.maxValue
	}
	if cfg.maxFallback != 0 {
		return cfg.maxFallback
	}
	return defaultValue
}

func normalizeGrantEnumList(name string, values []string, allowed map[string]bool) ([]string, error) {
	if len(values) == 0 {
		return nil, fmt.Errorf("%s must list at least one value", name)
	}
	seen := make(map[string]bool, len(values))
	for _, value := range values {
		if !allowed[value] {
			return nil, fmt.Errorf("%s contains unsupported value %q", name, value)
		}
		if seen[value] {
			return nil, fmt.Errorf("%s contains duplicate value %q", name, value)
		}
		seen[value] = true
	}
	return values, nil
}

func splitID(id string) (owner, name string, err error) {
	owner, name, found := strings.Cut(id, "/")
	if !found || !namePattern.MatchString(owner) || !namePattern.MatchString(name) || strings.Contains(id, "..") {
		return "", "", fmt.Errorf("id must be owner/name with [A-Za-z0-9._-] segments")
	}
	return owner, name, nil
}

func repoKey(t RepoType, owner, name string) string {
	return string(t) + "/" + owner + "/" + name
}

// Repo returns the scope entry for (type, owner, name), if any.
func (s Scope) Repo(t RepoType, owner, name string) (Repo, bool) {
	repo, ok := s.repos[repoKey(t, owner, name)]
	return repo, ok
}

// Buckets returns all configured buckets (used by the bucket proxy, M2).
func (s Scope) Buckets() []Bucket {
	buckets := make([]Bucket, 0, len(s.buckets))
	for _, bucket := range s.buckets {
		buckets = append(buckets, bucket)
	}
	return buckets
}
