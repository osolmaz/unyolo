package policy

import (
	"time"

	"github.com/osolmaz/brokerkit/internal/copyx"
)

// Decide evaluates one classified request.
func (p *Policy) Decide(request Request, opts DecisionOptions) Decision {
	request = normalizeRequest(request)
	if err := p.registry.validateRequest(request); err != nil {
		return Decision{Effect: EffectNoMatch, Reason: err.Error()}
	}
	if ids := p.matchingRuleIDs(request, EffectDeny); len(ids) > 0 {
		return Decision{Effect: EffectDeny, Reason: "policy_denied", MatchedDenyRuleIDs: ids}
	}
	if grant, ok := firstMatchingGrant(request, opts); ok {
		return Decision{
			Effect:              EffectAllow,
			Allowed:             true,
			Reason:              "grant_allowed",
			MatchedGrantRuleIDs: []string{grant.ID},
			GrantID:             grant.ID,
		}
	}
	if ids := p.matchingRuleIDs(request, EffectAllow); len(ids) > 0 {
		return Decision{Effect: EffectAllow, Allowed: true, Reason: "policy_allowed", MatchedAllowRuleIDs: ids}
	}
	if ids := p.matchingRuleIDs(request, EffectRequest); len(ids) > 0 {
		if opts.ForGrantRequest {
			return Decision{
				Effect:                EffectRequest,
				Reason:                "requestable",
				MatchedRequestRuleIDs: ids,
				GrantPolicy:           p.firstGrantPolicy(ids[0]),
			}
		}
		return Decision{Effect: EffectDeny, Reason: "approval_required", MatchedRequestRuleIDs: ids}
	}
	return Decision{Effect: EffectNoMatch, Reason: "no_matching_rule"}
}

func (p *Policy) matchingRuleIDs(request Request, effect Effect) []string {
	ids := make([]string, 0)
	for _, rule := range p.rules {
		if rule.Effect == effect && ruleMatches(p.registry, rule, request) {
			ids = append(ids, rule.ID)
		}
	}
	return ids
}

func firstMatchingGrant(request Request, opts DecisionOptions) (Grant, bool) {
	now := opts.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	for _, grant := range opts.ActiveGrants {
		if grant.ExpiresAt.IsZero() || !now.Before(grant.ExpiresAt) {
			continue
		}
		if grantMatches(grant, request) {
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
			Fields: copyx.StringMap(request.Target.Fields),
		},
		Attrs: copyx.StringMap(request.Attrs),
	}
}

// Rules returns a copy of normalized rules for diagnostics and tests.
func (p *Policy) Rules() []Rule {
	return cloneRules(p.rules)
}
