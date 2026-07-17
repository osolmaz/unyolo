// Package approvalnotify defines semantic approval notifications shared by all
// brokers and presentation channels.
package approvalnotify

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/osolmaz/brokerkit/approvalview"
	"github.com/osolmaz/brokerkit/grants"
	"github.com/osolmaz/brokerkit/notify"
	"github.com/osolmaz/brokerkit/usebudget"
)

// Approval is the bounded semantic payload for an approval request.
type Approval struct {
	GrantID                  string
	DecisionToken            string
	Broker                   string
	Requester                string
	Operation                string
	Reason                   string
	RequestedDurationSeconds int64
	MaxUses                  usebudget.Limit
	PendingExpiresAt         time.Time
	Presentation             approvalview.Presentation
	PresentationUnavailable  bool
}

// Project creates one semantic approval from the canonical grant and provider presenter.
func Project(ctx context.Context, broker string, presenter approvalview.Presenter, grant grants.Grant, decisionToken string) Approval {
	presentation, unavailable := approvalview.Project(ctx, presenter, grant)
	requester := approvalview.BoundedLine(grant.Client, 80)
	if requester == "" {
		requester = "Unknown requester"
	}
	duration := grant.RequestedDuration
	if duration <= 0 {
		duration = grant.Duration
	}
	return Approval{
		GrantID: grant.ID, DecisionToken: decisionToken, Broker: broker, Requester: requester,
		Operation: grant.Operation, Reason: grant.Reason, RequestedDurationSeconds: int64(duration / time.Second),
		MaxUses: grant.MaxUses, PendingExpiresAt: grant.PendingExpiresAt,
		Presentation: presentation, PresentationUnavailable: unavailable,
	}
}

// SnapshotJSON returns the canonical semantic approval snapshot without the
// decision token. The snapshot is suitable for durable notification audit.
func SnapshotJSON(approval Approval) string {
	value := struct {
		GrantID                  string                    `json:"grant_id"`
		Broker                   string                    `json:"broker"`
		Requester                string                    `json:"requester"`
		Operation                string                    `json:"operation"`
		Reason                   string                    `json:"reason"`
		RequestedDurationSeconds int64                     `json:"requested_duration_seconds"`
		MaxUses                  usebudget.Limit           `json:"max_uses"`
		PendingExpiresAt         time.Time                 `json:"pending_expires_at"`
		Presentation             approvalview.Presentation `json:"presentation"`
		PresentationUnavailable  bool                      `json:"presentation_unavailable,omitempty"`
	}{approval.GrantID, approval.Broker, approval.Requester, approval.Operation, approval.Reason,
		approval.RequestedDurationSeconds, approval.MaxUses, approval.PendingExpiresAt.UTC(), approval.Presentation,
		approval.PresentationUnavailable}
	var encoded bytes.Buffer
	encoder := json.NewEncoder(&encoded)
	encoder.SetEscapeHTML(false)
	err := encoder.Encode(value)
	if err != nil {
		return ""
	}
	return string(bytes.TrimSuffix(encoded.Bytes(), []byte{'\n'}))
}

// PresentationDigest binds the normalized semantic presentation without secrets.
func PresentationDigest(approval Approval) string {
	snapshot := SnapshotJSON(approval)
	if snapshot == "" {
		return ""
	}
	digest := sha256.Sum256([]byte(snapshot))
	return "sha256:" + hex.EncodeToString(digest[:])
}

// Notifier sends semantic approvals and typed status updates.
type Notifier interface {
	SendApproval(context.Context, Approval) (notify.MessageRef, error)
	UpdateStatus(context.Context, notify.MessageRef, notify.Status) error
}

// Memory is an in-memory notifier for tests and local dry runs.
type Memory struct {
	Messages []Approval
	Statuses []notify.Status
}

// SendApproval records approval without retaining its decision token.
func (m *Memory) SendApproval(_ context.Context, approval Approval) (notify.MessageRef, error) {
	stored := approval
	stored.DecisionToken = ""
	m.Messages = append(m.Messages, stored)
	return notify.MessageRef{Kind: "memory", Renderer: "memory-v1", ChatID: 1, MessageID: len(m.Messages),
		Text: approval.Operation, PresentationJSON: SnapshotJSON(approval), PresentationDigest: PresentationDigest(approval)}, nil
}

// UpdateStatus records a typed status update.
func (m *Memory) UpdateStatus(_ context.Context, _ notify.MessageRef, status notify.Status) error {
	m.Statuses = append(m.Statuses, status)
	return nil
}
