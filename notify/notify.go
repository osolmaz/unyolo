// Package notify defines broker approval notification interfaces.
package notify

import (
	"context"
	"time"
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
	Client           string
	Operation        string
	Target           string
	Reason           string
	RequestedMinutes int
	MaxUses          int
	PendingExpiresAt time.Time
	Fields           []Field
}

// Field is one provider-specific display line.
type Field struct {
	Name  string
	Value string
}

// MessageRef identifies an editable notification.
type MessageRef struct {
	Kind      string
	ChatID    int64
	MessageID int
	Text      string
}

// Decision is a parsed operator decision.
type Decision struct {
	Action        Action
	GrantID       string
	DecisionToken string
	Approver      string
	ChatID        int64
	CallbackID    string
	MessageID     int
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
