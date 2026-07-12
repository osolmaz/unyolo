// Package authorization coordinates policy decisions and durable approval requests.
package authorization

import (
	"errors"
	"fmt"
	"reflect"
	"time"

	"github.com/osolmaz/brokerkit/grants"
	"github.com/osolmaz/brokerkit/policy"
)

var (
	ErrDenied              = errors.New("authorization denied")
	ErrNoMatch             = errors.New("authorization has no matching policy rule")
	ErrInvalidGrantIntent  = errors.New("invalid grant intent")
	ErrApprovalUnsupported = errors.New("operation does not support the requested approval mode")
)

// DecideFunc evaluates one provider-classified request.
type DecideFunc func(policy.Request, policy.DecisionOptions) policy.Decision

// Coordinator owns the provider-neutral authorize-or-request transition.
type Coordinator struct {
	registry policy.Registry
	decide   DecideFunc
	grants   *grants.Store
	now      func() time.Time
}

// Options configures a Coordinator.
type Options struct {
	Registry policy.Registry
	Decide   DecideFunc
	Grants   *grants.Store
	Now      func() time.Time
}

// GrantIntent is a provider-built canonical approval request and immutable plan.
type GrantIntent struct {
	Mode    policy.GrantMode
	Request grants.Request
	Plan    grants.ImmutablePlan
}

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
	return &Coordinator{registry: options.Registry, decide: options.Decide, grants: options.Grants, now: options.Now}, nil
}

// Authorize allows, refuses, or durably creates an approval request.
func (c *Coordinator) Authorize(request policy.Request, intent *GrantIntent) (Result, error) {
	if err := c.registry.ValidateRequest(request); err != nil {
		return Result{Decision: policy.Decision{Effect: policy.EffectNoMatch, Reason: err.Error()}}, fmt.Errorf("%w: %v", ErrNoMatch, err)
	}
	active, err := c.grants.ActivePolicyGrants()
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
	if err := c.validateIntent(request, requestDecision, intent); err != nil {
		return Result{Decision: requestDecision}, err
	}
	created, wasCreated, err := c.grants.RequestWithPlan(intent.Request, intent.Plan)
	if err != nil {
		return Result{Decision: requestDecision}, fmt.Errorf("create approval request: %w", err)
	}
	return Result{Decision: requestDecision, Request: created, Created: wasCreated}, nil
}

func refusedResult(decision policy.Decision) (Result, error) {
	if decision.Effect == policy.EffectNoMatch {
		return Result{Decision: decision}, ErrNoMatch
	}
	return Result{Decision: decision}, ErrDenied
}

func (c *Coordinator) validateIntent(request policy.Request, decision policy.Decision, intent *GrantIntent) error {
	if intent == nil || !grantRequestMatches(request, intent.Request) {
		return ErrInvalidGrantIntent
	}
	spec, ok := c.registry.Operation(request.Operation)
	if !ok || !spec.AllowsGrantMode(intent.Mode) {
		return ErrApprovalUnsupported
	}
	if err := validateGrantBounds(intent, decision.GrantPolicy); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidGrantIntent, err)
	}
	return nil
}

func grantRequestMatches(request policy.Request, grant grants.Request) bool {
	return request.Client == grant.Client && request.Operation == grant.Operation &&
		reflect.DeepEqual(request.Target, grant.Target) && reflect.DeepEqual(request.Attrs, grant.Attrs)
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

func validateUseCount(mode policy.GrantMode, uses, maximum int) error {
	if uses <= 0 || uses > maximum {
		return errors.New("requested use count exceeds policy bounds")
	}
	if mode == policy.GrantModeExecution && uses != 1 {
		return errors.New("execution approvals must have exactly one use")
	}
	return nil
}
