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
