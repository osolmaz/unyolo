// Package operatorv1 defines the stable BrokerKit Operator V1 wire contract.
package operatorv1

import (
	"context"
	"io"
	"time"

	"github.com/osolmaz/brokerkit/grants"
	"github.com/osolmaz/brokerkit/policy"
)

const APIVersion = "brokerkit.io/operator/v1"

type Action string

const (
	ActionApprove Action = "approve"
	ActionDeny    Action = "deny"
	ActionCancel  Action = "cancel"
	ActionRevoke  Action = "revoke"
)

type Descriptor struct {
	APIVersion string `json:"api_version"`
}

type Fact struct {
	Label string `json:"label"`
	Value string `json:"value"`
}

type Presentation struct {
	Risk    string `json:"risk"`
	Title   string `json:"title"`
	Summary string `json:"summary,omitempty"`
	Facts   []Fact `json:"facts,omitempty"`
}

type ApprovalBounds struct {
	MaxDurationSeconds int64 `json:"max_duration_seconds"`
	MaxUses            int   `json:"max_uses"`
}

type Request struct {
	ID                       string          `json:"id"`
	Revision                 int64           `json:"revision"`
	Requester                string          `json:"requester"`
	Operation                string          `json:"operation"`
	Status                   grants.Status   `json:"status"`
	RequestedAt              time.Time       `json:"requested_at"`
	PendingExpiresAt         *time.Time      `json:"pending_expires_at,omitempty"`
	ActiveExpiresAt          *time.Time      `json:"active_expires_at,omitempty"`
	RequestedDurationSeconds int64           `json:"requested_duration_seconds"`
	RequestedMaxUses         int             `json:"requested_max_uses"`
	GrantedMaxUses           *int            `json:"granted_max_uses"`
	UsedCount                int             `json:"used_count"`
	RequestReason            string          `json:"request_reason,omitempty"`
	DecidedAt                *time.Time      `json:"decided_at,omitempty"`
	DecidedBy                string          `json:"decided_by,omitempty"`
	DecidedOnBehalfOf        string          `json:"decided_on_behalf_of,omitempty"`
	Presentation             Presentation    `json:"presentation"`
	PresentationUnavailable  bool            `json:"presentation_unavailable,omitempty"`
	AllowedActions           []Action        `json:"allowed_actions"`
	ApprovalBounds           *ApprovalBounds `json:"approval_bounds,omitempty"`
}

type Page struct {
	Requests    []Request `json:"requests"`
	NextCursor  string    `json:"next_cursor,omitempty"`
	EventCursor string    `json:"event_cursor,omitempty"`
}

type Query struct {
	Status    grants.StatusGroup
	Requester string
	Operation string
	Target    *policy.Target
	Cursor    string
	Limit     int
}

type Constraints struct {
	DurationSeconds int64 `json:"duration_seconds,omitempty"`
	MaxUses         int   `json:"max_uses,omitempty"`
}

type Decision struct {
	ExpectedRevision int64        `json:"expected_revision"`
	IdempotencyKey   string       `json:"idempotency_key"`
	OnBehalfOf       string       `json:"on_behalf_of,omitempty"`
	Constraints      *Constraints `json:"constraints,omitempty"`
}

type Event struct {
	Cursor     string        `json:"cursor"`
	Kind       string        `json:"kind"`
	RequestID  string        `json:"request_id"`
	Revision   int64         `json:"revision"`
	Status     grants.Status `json:"status"`
	OccurredAt time.Time     `json:"occurred_at"`
	UsedCount  int           `json:"used_count"`
}

type Error struct {
	Code          string   `json:"code"`
	Message       string   `json:"message"`
	CorrelationID string   `json:"correlation_id"`
	Current       *Request `json:"current,omitempty"`
}

type ErrorEnvelope struct {
	Error Error `json:"error"`
}

// EventStream is one source event stream. Receive blocks until an event or error.
type EventStream interface {
	Receive(context.Context) (Event, error)
	Close() error
}

// Source is the complete provider-neutral trusted-host client contract.
type Source interface {
	Discover(context.Context) (Descriptor, error)
	List(context.Context, Query) (Page, error)
	Get(context.Context, string) (Request, error)
	Decide(context.Context, string, Action, Decision) (Request, error)
	Watch(context.Context, string) (EventStream, error)
	Health(context.Context) error
}

var _ io.Closer = (EventStream)(nil)
