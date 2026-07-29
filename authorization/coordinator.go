// Package authorization coordinates policy decisions and durable approval requests.
package authorization

import (
	"errors"
	"fmt"
	"reflect"
	"time"

	"github.com/osolmaz/unyolo/authorization/budget"
	"github.com/osolmaz/unyolo/authorization/grants"
	"github.com/osolmaz/unyolo/authorization/policy"
)

var (
	ErrDenied              = errors.New("authorization denied")
	ErrNoMatch             = errors.New("authorization has no matching policy rule")
	ErrInvalidGrantIntent  = errors.New("invalid grant intent")
	ErrApprovalUnsupported = errors.New("operation does not support the requested approval mode")
)

// DecideFunc evaluates one provider-classified request.
type DecideFunc func(policy.Request, policy.DecisionOptions) policy.Decision

// ActiveGrantsFunc projects durable grants relevant to request into policy grants.
type ActiveGrantsFunc func(policy.Request) ([]policy.Grant, error)

// Coordinator owns the provider-neutral authorize-or-request transition.
type Coordinator struct {
	registry     policy.Registry
	decide       DecideFunc
	grants       *grants.Store
	activeGrants ActiveGrantsFunc
	now          func() time.Time
}

// Options configures a Coordinator.
type Options struct {
	Registry policy.Registry
	Decide   DecideFunc
	Grants   *grants.Store
	// ActiveGrants projects durable provider grants into policy grants. It
	// defaults to Grants.ActivePolicyGrants when provider-native storage already
	// uses the policy target schema.
	ActiveGrants ActiveGrantsFunc
	Now          func() time.Time
}

// GrantIntent is a provider-built canonical approval request and immutable plan.
type GrantIntent struct {
	Mode          policy.GrantMode
	Authorization policy.Request
	Request       grants.Request
	Plan          grants.ImmutablePlan
}

// IntentBuilder resolves provider defaults and builds an immutable request
// after the coordinator has selected the request rule and its bounds.
type IntentBuilder func(policy.Decision) (GrantIntent, error)

// Result is one authorization decision and optional durable approval request.
type Result struct {
	Decision policy.Decision
	Request  grants.RequestResult
	Created  bool
}

// New constructs a coordinator over a validated provider registry.
func New(options Options) (*Coordinator, error) {
	if err := options.Registry.Validate(); err != nil {
		return nil, fmt.Errorf("validate authorization registry: %w", err)
	}
	if options.Decide == nil || options.Grants == nil {
		return nil, errors.New("authorization decision function and grant store are required")
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	if options.ActiveGrants == nil {
		options.ActiveGrants = func(policy.Request) ([]policy.Grant, error) {
			return options.Grants.ActivePolicyGrants()
		}
	}
	return &Coordinator{
		registry: options.Registry, decide: options.Decide, grants: options.Grants,
		activeGrants: options.ActiveGrants, now: options.Now,
	}, nil
}

// Authorize allows, refuses, or durably creates an approval request.
func (c *Coordinator) Authorize(request policy.Request, build IntentBuilder) (Result, error) {
	if err := c.registry.ValidateRequest(request); err != nil {
		return Result{Decision: policy.Decision{Effect: policy.EffectNoMatch, Reason: err.Error()}}, fmt.Errorf("%w: %w", ErrNoMatch, err)
	}
	active, err := c.activeGrants(request)
	if err != nil {
		return Result{}, fmt.Errorf("load active grants: %w", err)
	}
	now := c.now().UTC()
	decision := c.decide(request, policy.DecisionOptions{Now: now, ActiveGrants: active})
	if decision.Allowed && decision.Effect == policy.EffectAllow {
		return Result{Decision: decision}, nil
	}
	requestDecision := c.decide(request, policy.DecisionOptions{Now: now, ForGrantRequest: true})
	if requestDecision.Effect != policy.EffectRequest {
		return refusedResult(decision)
	}
	return c.createApprovalRequest(request, requestDecision, build)
}

// ActiveGrant returns existing matching grant authority without creating any
// durable state. Callers can use it before atomically recording dependent work.
func (c *Coordinator) ActiveGrant(request policy.Request) (policy.Decision, bool, error) {
	if err := c.registry.ValidateRequest(request); err != nil {
		return policy.Decision{}, false, fmt.Errorf("%w: %w", ErrNoMatch, err)
	}
	active, err := c.activeGrants(request)
	if err != nil {
		return policy.Decision{}, false, fmt.Errorf("load active grants: %w", err)
	}
	decision := c.decide(request, policy.DecisionOptions{Now: c.now().UTC(), ActiveGrants: active})
	return decision, decision.Allowed && decision.GrantID != "", nil
}

// ActiveGrantMode returns existing matching authority only for the requested
// durable grant mode.
func (c *Coordinator) ActiveGrantMode(request policy.Request, mode policy.GrantMode) (policy.Decision, bool, error) {
	if err := c.registry.ValidateRequest(request); err != nil {
		return policy.Decision{}, false, fmt.Errorf("%w: %w", ErrNoMatch, err)
	}
	active, err := c.activeGrants(request)
	if err != nil {
		return policy.Decision{}, false, fmt.Errorf("load active grants: %w", err)
	}
	filtered := make([]policy.Grant, 0, len(active))
	for _, candidate := range active {
		grant, getErr := c.grants.Get(candidate.ID)
		if getErr != nil {
			return policy.Decision{}, false, fmt.Errorf("load active grant mode: %w", getErr)
		}
		if policy.GrantMode(grant.Metadata[grants.MetadataMode]) == mode {
			filtered = append(filtered, candidate)
		}
	}
	decision := c.decide(request, policy.DecisionOptions{Now: c.now().UTC(), ActiveGrants: filtered})
	return decision, decision.Allowed && decision.GrantID != "", nil
}

// RequestApproval explicitly requests a bounded approval even when an existing
// grant could currently authorize the same capability.
func (c *Coordinator) RequestApproval(request policy.Request, build IntentBuilder) (Result, error) {
	if err := c.registry.ValidateRequest(request); err != nil {
		return Result{Decision: policy.Decision{Effect: policy.EffectNoMatch, Reason: err.Error()}}, fmt.Errorf("%w: %w", ErrNoMatch, err)
	}
	decision := c.decide(request, policy.DecisionOptions{Now: c.now().UTC(), ForGrantRequest: true})
	if decision.Effect != policy.EffectRequest {
		return refusedResult(decision)
	}
	return c.createApprovalRequest(request, decision, build)
}

func (c *Coordinator) createApprovalRequest(request policy.Request, decision policy.Decision, build IntentBuilder) (Result, error) {
	intent, err := buildIntent(build, decision)
	if err != nil {
		return Result{Decision: decision}, err
	}
	if err := c.validateIntent(request, decision, &intent); err != nil {
		return Result{Decision: decision}, err
	}
	created, wasCreated, err := c.grants.RequestWithPlan(intent.Request, intent.Plan)
	if err != nil {
		return Result{Decision: decision}, fmt.Errorf("create approval request: %w", err)
	}
	return Result{Decision: decision, Request: created, Created: wasCreated}, nil
}

func buildIntent(build IntentBuilder, decision policy.Decision) (GrantIntent, error) {
	if build == nil {
		return GrantIntent{}, ErrInvalidGrantIntent
	}
	intent, err := build(decision)
	if err != nil {
		return GrantIntent{}, fmt.Errorf("%w: %w", ErrInvalidGrantIntent, err)
	}
	return intent, nil
}

func refusedResult(decision policy.Decision) (Result, error) {
	if decision.Effect == policy.EffectNoMatch {
		return Result{Decision: decision}, ErrNoMatch
	}
	return Result{Decision: decision}, ErrDenied
}

func (c *Coordinator) validateIntent(request policy.Request, decision policy.Decision, intent *GrantIntent) error {
	if intent == nil || !reflect.DeepEqual(request, intent.Authorization) {
		return ErrInvalidGrantIntent
	}
	spec, ok := c.registry.Operation(request.Operation)
	if !ok || !spec.AllowsGrantMode(intent.Mode) {
		return ErrApprovalUnsupported
	}
	if err := validateGrantBounds(intent, decision.GrantPolicy); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidGrantIntent, err)
	}
	return nil
}

func validateGrantBounds(intent *GrantIntent, bounds *policy.GrantPolicy) error {
	if bounds == nil {
		return errors.New("request rule has no grant bounds")
	}
	if policy.GrantMode(bounds.Mode) != intent.Mode {
		return errors.New("approval mode does not match policy bounds")
	}
	if err := validateTimedBound("requested duration", intent.Request.Duration, bounds.MaxMinutes); err != nil {
		return err
	}
	if err := validateTimedBound("pending timeout", intent.Request.PendingTimeout, bounds.RequestTTLMinutes); err != nil {
		return err
	}
	return validateUseCount(intent.Mode, intent.Request.MaxUses, bounds.MaxUses)
}

func validateTimedBound(name string, value time.Duration, maxMinutes int) error {
	if value <= 0 || value > time.Duration(maxMinutes)*time.Minute {
		return fmt.Errorf("%s exceeds policy bounds", name)
	}
	return nil
}

func validateUseCount(mode policy.GrantMode, uses, maximum usebudget.Limit) error {
	if uses < 0 || (maximum.IsFinite() && (uses.IsUnlimited() || uses > maximum)) {
		return errors.New("requested use count exceeds policy bounds")
	}
	if mode == policy.GrantModeExecution && uses != usebudget.Limit(1) {
		return errors.New("execution approvals must have exactly one use")
	}
	return nil
}
