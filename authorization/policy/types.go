// Package policy evaluates broker authorization rules.
package policy

import (
	"time"

	"github.com/osolmaz/unyolo/authorization/budget"
)

// Effect is a rule or decision effect.
type Effect string

const (
	EffectAllow   Effect = "allow"
	EffectRequest Effect = "request"
	EffectDeny    Effect = "deny"
	EffectNoMatch Effect = "no_match"
)

// CredentialUse identifies whether one execution path may use a managed
// provider credential. Brokers select this value after classifying a request;
// callers cannot supply it.
type CredentialUse string

const (
	CredentialUseNone    CredentialUse = "none"
	CredentialUseManaged CredentialUse = "managed"
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
	ID             string
	Effect         Effect
	Clients        []string
	Operations     []string
	Targets        []TargetMatcher
	Attrs          map[string][]string
	CredentialUses []CredentialUse
	GrantPolicy    *GrantPolicy
	Description    string
}

// TargetMatcher is one target constraint in a rule.
type TargetMatcher struct {
	Kind   string
	Fields map[string][]string
}

// GrantPolicy bounds requestable approval grants.
type GrantPolicy struct {
	Mode              string          `json:"mode"`
	DefaultMinutes    int             `json:"default_minutes"`
	MaxMinutes        int             `json:"max_minutes"`
	RequestTTLMinutes int             `json:"request_ttl_minutes"`
	DefaultMaxUses    usebudget.Limit `json:"default_max_uses"`
	MaxUses           usebudget.Limit `json:"max_uses"`
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
	Unlimited bool
}

// Decision is the result of policy evaluation.
type Decision struct {
	Effect                Effect
	Allowed               bool
	Reason                string
	CredentialUse         CredentialUse
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
	CredentialUse   CredentialUse
}

// Policy is a normalized policy document.
type Policy struct {
	registry Registry
	rules    []Rule
}
