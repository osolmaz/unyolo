// Package admission provides bounded admission control for authenticated agent operations.
package admission

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

const maxClientIDBytes = 128

// Limits bounds accepted operation submissions and durable active work.
type Limits struct {
	RequestsPerWindow int
	Window            time.Duration
	ClientActive      int64
	ClientPending     int64
	GlobalActive      int64
	GlobalExecuting   int64
}

// DefaultLimits returns conservative limits suitable for a local broker daemon.
func DefaultLimits() Limits {
	return Limits{
		RequestsPerWindow: 60,
		Window:            time.Minute,
		ClientActive:      25,
		ClientPending:     10,
		GlobalActive:      512,
		GlobalExecuting:   64,
	}
}

// Usage is the durable operation occupancy used by the admission decision.
type Usage struct {
	ClientActive    int64
	ClientPending   int64
	GlobalActive    int64
	GlobalExecuting int64
}

// UsageFunc reads current durable occupancy for one configured client.
type UsageFunc func(context.Context, string) (Usage, error)

// LimitError is a stable, provider-safe admission refusal.
type LimitError struct {
	Code       string
	RetryAfter time.Duration
}

func (e *LimitError) Error() string { return "operation admission limit reached" }

type clientState struct {
	windowStart time.Time
	requests    int
	reserved    int64
}

// Controller coordinates in-memory rate buckets with durable operation occupancy.
type Controller struct {
	mu             sync.Mutex
	limits         Limits
	usage          UsageFunc
	now            func() time.Time
	clients        map[string]*clientState
	globalReserved int64
}

// New constructs a controller for a fixed set of authenticated client identities.
func New(clients []string, limits Limits, usage UsageFunc) (*Controller, error) {
	return newController(clients, limits, usage, time.Now)
}

func newController(clients []string, limits Limits, usage UsageFunc, now func() time.Time) (*Controller, error) {
	if usage == nil || now == nil || !validLimits(limits) || len(clients) == 0 {
		return nil, errors.New("admission clients, limits, usage reader, and clock are required")
	}
	states, err := clientStates(clients)
	if err != nil {
		return nil, err
	}
	return &Controller{limits: limits, usage: usage, now: now, clients: states}, nil
}

func clientStates(clients []string) (map[string]*clientState, error) {
	states := make(map[string]*clientState, len(clients))
	for _, client := range clients {
		client = strings.TrimSpace(client)
		if !validClientID(client) {
			return nil, errors.New("admission client identity is invalid")
		}
		if _, exists := states[client]; exists {
			return nil, errors.New("admission client identity is duplicated")
		}
		states[client] = &clientState{}
	}
	return states, nil
}

func validLimits(value Limits) bool {
	return positiveLimits(value) && hierarchicalLimits(value)
}

func positiveLimits(value Limits) bool {
	return value.RequestsPerWindow > 0 && value.Window > 0 && value.ClientActive > 0 && value.ClientPending > 0 &&
		value.GlobalActive > 0 && value.GlobalExecuting > 0
}

func hierarchicalLimits(value Limits) bool {
	return value.ClientPending <= value.ClientActive && value.ClientActive <= value.GlobalActive &&
		value.GlobalExecuting <= value.GlobalActive
}

func validClientID(value string) bool { return value != "" && len(value) <= maxClientIDBytes }

// Admit reserves capacity until the caller either commits a durable operation or releases the permit.
func (c *Controller) Admit(ctx context.Context, client string) (*Permit, error) {
	client = strings.TrimSpace(client)
	c.mu.Lock()
	defer c.mu.Unlock()
	state, ok := c.clients[client]
	if !ok {
		return nil, errors.New("admission client is not configured")
	}
	now := c.now().UTC()
	if err := c.chargeRequest(state, now); err != nil {
		return nil, err
	}
	usage, err := c.usage(ctx, client)
	if err != nil {
		return nil, fmt.Errorf("read operation admission usage: %w", err)
	}
	if code := c.capacityCode(state, usage); code != "" {
		return nil, capacityError(code)
	}
	state.reserved++
	c.globalReserved++
	return &Permit{controller: c, client: client}, nil
}

func (c *Controller) chargeRequest(state *clientState, now time.Time) error {
	if state.windowStart.IsZero() || !now.Before(state.windowStart.Add(c.limits.Window)) {
		state.windowStart, state.requests = now, 0
	}
	if state.requests >= c.limits.RequestsPerWindow {
		return &LimitError{Code: "submission_rate_limited", RetryAfter: positiveDuration(state.windowStart.Add(c.limits.Window).Sub(now))}
	}
	state.requests++
	return nil
}

func (c *Controller) capacityCode(state *clientState, usage Usage) string {
	if usage.ClientActive+state.reserved >= c.limits.ClientActive {
		return "client_operation_limit"
	}
	if usage.ClientPending+state.reserved >= c.limits.ClientPending {
		return "client_pending_limit"
	}
	if usage.GlobalActive+c.globalReserved >= c.limits.GlobalActive {
		return "global_operation_limit"
	}
	if usage.GlobalExecuting >= c.limits.GlobalExecuting {
		return "global_execution_limit"
	}
	return ""
}

func capacityError(code string) *LimitError {
	return &LimitError{Code: code, RetryAfter: 2 * time.Second}
}

func positiveDuration(value time.Duration) time.Duration {
	if value < time.Second {
		return time.Second
	}
	return value
}

// Permit protects one provisional active-operation slot.
type Permit struct {
	controller *Controller
	client     string
	once       sync.Once
}

// Commit releases provisional capacity after the operation is durable.
func (p *Permit) Commit() { p.release() }

// Release rolls back provisional capacity when no operation was created.
func (p *Permit) Release() { p.release() }

func (p *Permit) release() {
	if p == nil || p.controller == nil {
		return
	}
	p.once.Do(func() {
		p.controller.mu.Lock()
		defer p.controller.mu.Unlock()
		state := p.controller.clients[p.client]
		if state != nil && state.reserved > 0 {
			state.reserved--
		}
		if p.controller.globalReserved > 0 {
			p.controller.globalReserved--
		}
	})
}
