// Package policy evaluates broker authorization rules.
package policy

import "time"

// Effect is a rule or decision effect.
type Effect string

const (
	EffectAllow   Effect = "allow"
	EffectRequest Effect = "request"
	EffectDeny    Effect = "deny"
	EffectNoMatch Effect = "no_match"
)

// Request is the provider-classified authorization unit.
type Request struct {
	Client    string
	Operation string
	Target    Target
	Attrs     map[string][]string
}

// Target identifies one provider resource.
type Target struct {
	Kind   string
	Fields map[string][]string
}

// Rule is one normalized policy rule.
type Rule struct {
	ID          string
	Effect      Effect
	Clients     []string
	Operations  []string
	Targets     []TargetMatcher
	Attrs       map[string][]string
	GrantPolicy *GrantPolicy
	Description string
}

// TargetMatcher is one target constraint in a rule.
type TargetMatcher struct {
	Kind   string
	Fields map[string][]string
}

// GrantPolicy bounds requestable approval grants.
type GrantPolicy struct {
	Mode              string `json:"mode"`
	DefaultMinutes    int    `json:"default_minutes"`
	MaxMinutes        int    `json:"max_minutes"`
	RequestTTLMinutes int    `json:"request_ttl_minutes"`
	DefaultMaxUses    int    `json:"default_max_uses"`
	MaxUses           int    `json:"max_uses"`
}

// Grant is an active generated allow rule.
type Grant struct {
	ID        string
	Client    string
	Operation string
	Target    Target
	Attrs     map[string][]string
	ExpiresAt time.Time
	UsesLeft  int
}

// Decision is the result of policy evaluation.
type Decision struct {
	Effect                Effect
	Allowed               bool
	Reason                string
	MatchedDenyRuleIDs    []string
	MatchedGrantRuleIDs   []string
	MatchedAllowRuleIDs   []string
	MatchedRequestRuleIDs []string
	GrantID               string
	GrantPolicy           *GrantPolicy
}

// DecisionOptions controls one evaluation.
type DecisionOptions struct {
	ForGrantRequest bool
	Now             time.Time
	ActiveGrants    []Grant
}

// Policy is a normalized policy document.
type Policy struct {
	registry Registry
	rules    []Rule
}
