// Package notify defines broker approval notification interfaces.
package notify

import (
	"context"

	"github.com/osolmaz/brokerkit/usebudget"
)

// Action is an approval decision action.
type Action string

const (
	ActionApprove Action = "approve"
	ActionDeny    Action = "deny"
)

// ApprovalMessage is the generic notification payload for an approval request.
type ApprovalMessage struct {
	GrantID          string
	DecisionToken    string
	Text             string
	Client           string
	Operation        string
	Target           string
	Reason           string
	RequestedMinutes int
	MaxUses          usebudget.Limit
	Fields           []Field
}

// Field is one provider-specific display line.
type Field struct {
	Name  string
	Value string
}

// MessageRef identifies an editable notification.
type MessageRef struct {
	Kind      string `json:"kind"`
	ChatID    int64  `json:"chat_id"`
	MessageID int    `json:"message_id"`
	Text      string `json:"text"`
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
	OperatorID    int64
	OperatorTag   string
}

// DecisionResult is the callback answer returned after an operator decision.
type DecisionResult struct {
	// Answer is the short callback answer shown by the approval channel.
	Answer string
	// MessageStatus is the durable status rendered into the approval message.
	// A non-empty value also closes the message's decision controls.
	MessageStatus string
	// Retry leaves the callback unanswered and its update offset uncommitted.
	// Brokers use it when a durable decision transaction could not be saved.
	Retry bool
}

// Notifier sends approval requests and status updates.
type Notifier interface {
	SendApproval(context.Context, ApprovalMessage) (MessageRef, error)
	UpdateStatus(context.Context, MessageRef, string) error
}

// Memory is an in-memory notifier for tests and local dry runs.
type Memory struct {
	Messages []ApprovalMessage
	Statuses []string
}

// SendApproval records msg and returns a fake message reference.
func (m *Memory) SendApproval(_ context.Context, msg ApprovalMessage) (MessageRef, error) {
	stored := msg
	stored.DecisionToken = ""
	m.Messages = append(m.Messages, stored)
	return MessageRef{Kind: "memory", ChatID: 1, MessageID: len(m.Messages), Text: msg.Operation}, nil
}

// UpdateStatus records a status update.
func (m *Memory) UpdateStatus(_ context.Context, _ MessageRef, status string) error {
	m.Statuses = append(m.Statuses, status)
	return nil
}
