// Package agentv1 defines the provider-neutral Agent Operations V1 lifecycle.
package agentv1

import (
	"encoding/json"
	"time"
)

const APIVersion = "brokerkit.io/agent/v1"

type State string

const (
	StatePending   State = "pending"
	StateApproved  State = "approved"
	StateExecuting State = "executing"
	StateSucceeded State = "succeeded"
	StateFailed    State = "failed"
	StateDenied    State = "denied"
	StateExpired   State = "expired"
	StateCanceled  State = "canceled"
)

type Descriptor struct {
	APIVersion string `json:"api_version"`
}

type Presentation struct {
	Title   string `json:"title"`
	Summary string `json:"summary,omitempty"`
}

type OperationError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type Operation struct {
	APIVersion     string          `json:"api_version"`
	ID             string          `json:"id"`
	Broker         string          `json:"broker"`
	ClientID       string          `json:"client_id"`
	IdempotencyKey string          `json:"idempotency_key"`
	Operation      string          `json:"operation"`
	Target         json.RawMessage `json:"target"`
	Arguments      json.RawMessage `json:"arguments"`
	Reason         string          `json:"reason"`
	State          State           `json:"state"`
	Revision       int64           `json:"revision"`
	ApprovalID     string          `json:"approval_id,omitempty"`
	CreatedAt      time.Time       `json:"created_at"`
	UpdatedAt      time.Time       `json:"updated_at"`
	TerminalAt     *time.Time      `json:"terminal_at,omitempty"`
	Presentation   Presentation    `json:"presentation"`
	PlanDigest     string          `json:"plan_digest,omitempty"`
	Result         json.RawMessage `json:"result,omitempty"`
	Error          *OperationError `json:"error,omitempty"`
}

type SubmitRequest struct {
	IdempotencyKey string          `json:"idempotency_key"`
	Operation      string          `json:"operation"`
	Target         json.RawMessage `json:"target"`
	Arguments      json.RawMessage `json:"arguments"`
	Reason         string          `json:"reason"`
}

// ListOptions selects one bounded page of operations owned by a client.
// Cursor values are opaque to callers and are validated by the store.
type ListOptions struct {
	IdempotencyKey string
	State          State
	Limit          int
	Cursor         string
}

type OperationSummary struct {
	APIVersion     string       `json:"api_version"`
	ID             string       `json:"id"`
	Broker         string       `json:"broker"`
	ClientID       string       `json:"client_id"`
	IdempotencyKey string       `json:"idempotency_key"`
	Operation      string       `json:"operation"`
	State          State        `json:"state"`
	Revision       int64        `json:"revision"`
	CreatedAt      time.Time    `json:"created_at"`
	UpdatedAt      time.Time    `json:"updated_at"`
	TerminalAt     *time.Time   `json:"terminal_at,omitempty"`
	Presentation   Presentation `json:"presentation"`
}

type OperationPage struct {
	APIVersion string             `json:"api_version"`
	Operations []OperationSummary `json:"operations"`
	NextCursor *string            `json:"next_cursor"`
}

type Error struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type ErrorEnvelope struct {
	Error Error `json:"error"`
}

func (s State) Terminal() bool {
	switch s {
	case StateSucceeded, StateFailed, StateDenied, StateExpired, StateCanceled:
		return true
	default:
		return false
	}
}

func (s State) Valid() bool {
	switch s {
	case StatePending, StateApproved, StateExecuting, StateSucceeded,
		StateFailed, StateDenied, StateExpired, StateCanceled:
		return true
	default:
		return false
	}
}
