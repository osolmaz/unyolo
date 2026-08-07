package policy

import (
	"time"

	"github.com/osolmaz/unyolo/internal/copyx"
)

// Decide evaluates one classified request.
func (p *Policy) Decide(request Request, opts DecisionOptions) Decision {
	request = normalizeRequest(request)
	credentialUse := defaultedCredentialUse(opts.CredentialUse)
	if err := p.registry.validateRequest(request); err != nil {
		return Decision{Effect: EffectNoMatch, Reason: err.Error(), CredentialUse: credentialUse}
	}
	if err := p.registry.validateRequestCredentialUse(request.Operation, credentialUse); err != nil {
		return Decision{Effect: EffectNoMatch, Reason: err.Error(), CredentialUse: credentialUse}
	}
	return p.decideValidRequest(request, opts, credentialUse)
}

func (p *Policy) decideValidRequest(request Request, opts DecisionOptions, credentialUse CredentialUse) Decision {
	if ids := p.matchingRuleIDs(request, EffectDeny, credentialUse); len(ids) > 0 {
		return Decision{Effect: EffectDeny, Reason: "policy_denied", CredentialUse: credentialUse, MatchedDenyRuleIDs: ids}
	}
	if decision, ok := p.managedGrantDecision(request, opts, credentialUse); ok {
		return decision
	}
	return p.staticRuleDecision(request, opts.ForGrantRequest, credentialUse)
}

func (p *Policy) managedGrantDecision(request Request, opts DecisionOptions, credentialUse CredentialUse) (Decision, bool) {
	if credentialUse != CredentialUseManaged {
		return Decision{}, false
	}
	grant, ok := p.firstMatchingGrant(request, opts)
	if !ok {
		return Decision{}, false
	}
	return Decision{
		Effect: EffectAllow, Allowed: true, Reason: "grant_allowed", CredentialUse: credentialUse,
		MatchedGrantRuleIDs: []string{grant.ID}, GrantID: grant.ID,
	}, true
}

func (p *Policy) staticRuleDecision(request Request, grantRequest bool, credentialUse CredentialUse) Decision {
	if ids := p.matchingRuleIDs(request, EffectAllow, credentialUse); len(ids) > 0 {
		return Decision{Effect: EffectAllow, Allowed: true, Reason: "policy_allowed", CredentialUse: credentialUse, MatchedAllowRuleIDs: ids}
	}
	ids := p.matchingRuleIDs(request, EffectRequest, credentialUse)
	if len(ids) == 0 {
		return Decision{Effect: EffectNoMatch, Reason: "no_matching_rule", CredentialUse: credentialUse}
	}
	if grantRequest {
		return Decision{
			Effect: EffectRequest, Reason: "requestable", CredentialUse: credentialUse,
			MatchedRequestRuleIDs: ids, GrantPolicy: p.firstGrantPolicy(ids[0]),
		}
	}
	return Decision{Effect: EffectDeny, Reason: "approval_required", CredentialUse: credentialUse, MatchedRequestRuleIDs: ids}
}

func (p *Policy) matchingRuleIDs(request Request, effect Effect, credentialUse CredentialUse) []string {
	ids := make([]string, 0)
	for _, rule := range p.rules {
		if rule.Effect == effect && ruleMatches(p.registry, rule, request, credentialUse) {
			ids = append(ids, rule.ID)
		}
	}
	return ids
}

func (p *Policy) firstMatchingGrant(request Request, opts DecisionOptions) (Grant, bool) {
	now := opts.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	for _, grant := range opts.ActiveGrants {
		if grant.ExpiresAt.IsZero() || !now.Before(grant.ExpiresAt) {
			continue
		}
		if grantMatches(p.registry, grant, request) {
			return grant, true
		}
	}
	return Grant{}, false
}

func (p *Policy) firstGrantPolicy(ruleID string) *GrantPolicy {
	for _, rule := range p.rules {
		if rule.ID == ruleID && rule.GrantPolicy != nil {
			grantPolicy := *rule.GrantPolicy
			return &grantPolicy
		}
	}
	return nil
}

func normalizeRequest(request Request) Request {
	return Request{
		Client:    request.Client,
		Operation: request.Operation,
		Target: Target{
			Kind:   request.Target.Kind,
			Fields: copyx.StringSliceMap(request.Target.Fields),
		},
		Attrs: copyx.StringSliceMap(request.Attrs),
	}
}

// Rules returns a copy of normalized rules for diagnostics and tests.
func (p *Policy) Rules() []Rule {
	return cloneRules(p.rules)
}
