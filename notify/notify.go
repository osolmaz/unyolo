// Package notify defines broker approval notification interfaces.
package notify

import (
	"github.com/osolmaz/brokerkit/usebudget"
)

// Action is an approval decision action.
type Action string

const (
	ActionApprove Action = "approve"
	ActionDeny    Action = "deny"
)

// MessageRef identifies an editable notification.
type MessageRef struct {
	Kind               string `json:"kind"`
	Renderer           string `json:"renderer"`
	ChatID             int64  `json:"chat_id"`
	MessageID          int    `json:"message_id"`
	Text               string `json:"text"`
	PresentationJSON   string `json:"presentation_json"`
	PresentationDigest string `json:"presentation_digest"`
	RenderedDigest     string `json:"rendered_digest"`
}

// Answer identifies one fixed callback answer rendered by the channel.
type Answer string

const (
	AnswerApproved         Answer = "approved"
	AnswerDenied           Answer = "denied"
	AnswerAlreadyApproved  Answer = "already_approved"
	AnswerAlreadyDenied    Answer = "already_denied"
	AnswerAlreadyExpired   Answer = "already_expired"
	AnswerAlreadyConsumed  Answer = "already_consumed"
	AnswerAlreadyRevoked   Answer = "already_revoked"
	AnswerAlreadyCanceled  Answer = "already_canceled"
	AnswerNotFound         Answer = "not_found"
	AnswerSuperseded       Answer = "superseded"
	AnswerIgnored          Answer = "ignored"
	AnswerRouteUnavailable Answer = "route_unavailable"
	AnswerUnavailable      Answer = "unavailable"
	AnswerClosed           Answer = "closed"
)

// StatusKind identifies one operator-facing notification lifecycle state.
type StatusKind string

const (
	StatusActive         StatusKind = "active"
	StatusDenied         StatusKind = "denied"
	StatusPendingExpired StatusKind = "pending_expired"
	StatusActiveExpired  StatusKind = "active_expired"
	StatusConsumed       StatusKind = "consumed"
	StatusRevoked        StatusKind = "revoked"
	StatusCanceled       StatusKind = "canceled"
	StatusRetained       StatusKind = "retained"
	StatusUsedActive     StatusKind = "used_active"
	StatusSuperseded     StatusKind = "superseded"
	StatusUnavailable    StatusKind = "unavailable"
	StatusClosed         StatusKind = "closed"
)

// Status carries bounded counters needed for deterministic terminal rendering.
type Status struct {
	Kind          StatusKind
	UsedCount     int
	ReservedCount int
	MaxUses       usebudget.Limit
}

// Decision is a parsed operator decision.
type Decision struct {
	Route         string
	Action        Action
	GrantID       string
	DecisionToken string
	Approver      string
	ChatID        int64
	CallbackID    string
	MessageID     int
	MessageText   string
	Notification  *MessageRef
	OperatorID    int64
	OperatorTag   string
}

// DecisionResult is the callback answer returned after an operator decision.
type DecisionResult struct {
	// Answer is rendered into a short callback answer by the channel.
	Answer Answer
	// MessageStatus is rendered into the durable approval message. A non-empty
	// kind also closes the message's decision controls.
	MessageStatus Status
	// ClearButtons closes decision controls without replacing broker-owned status text.
	ClearButtons bool
	// Retry leaves the callback unanswered and its update offset uncommitted.
	// Brokers use it when a durable decision transaction could not be saved.
	Retry bool
}
