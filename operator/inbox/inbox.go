// Package operatorinbox projects durable grants into bounded, operator-safe records.
package operatorinbox

import (
	"context"
	"errors"
	"time"

	"github.com/osolmaz/brokerkit/approval/view"
	"github.com/osolmaz/brokerkit/authorization/budget"
	"github.com/osolmaz/brokerkit/authorization/grants"
)

const (
	maxTargetBytes = 500
	maxReasonBytes = 2_000
	maxLabelBytes  = 80
)

// Item is the only grant representation exposed by the operator HTTP API.
type Item struct {
	ID                       string                    `json:"id"`
	Revision                 int64                     `json:"revision"`
	Client                   string                    `json:"client"`
	Operation                string                    `json:"operation"`
	Status                   grants.Status             `json:"status"`
	RequestedAt              time.Time                 `json:"requested_at"`
	PendingExpiresAt         time.Time                 `json:"pending_expires_at"`
	ActiveExpiresAt          *time.Time                `json:"active_expires_at,omitempty"`
	RequestedDurationSeconds int64                     `json:"requested_duration_seconds"`
	RequestedMaxUses         usebudget.Limit           `json:"requested_max_uses"`
	MaxUses                  usebudget.Limit           `json:"max_uses"`
	UsedCount                int                       `json:"used_count"`
	ReservedCount            int                       `json:"reserved_count"`
	Reason                   string                    `json:"reason,omitempty"`
	DecidedAt                *time.Time                `json:"decided_at,omitempty"`
	DecidedBy                string                    `json:"decided_by,omitempty"`
	DecidedOnBehalfOf        string                    `json:"decided_on_behalf_of,omitempty"`
	Presentation             approvalview.Presentation `json:"presentation"`
	PresentationUnavailable  bool                      `json:"presentation_unavailable,omitempty"`
}

// Page is one bounded inbox result.
type Page struct {
	Items       []Item `json:"items"`
	NextCursor  string `json:"next_cursor,omitempty"`
	HasMore     bool   `json:"has_more"`
	EventCursor string `json:"event_cursor,omitempty"`
}

// Service joins the durable store with one broker-owned presenter.
type Service struct {
	store     *grants.Store
	presenter approvalview.Presenter
}

// New constructs an inbox service. A nil presenter uses safe generic wording.
func New(store *grants.Store, presenter approvalview.Presenter) (*Service, error) {
	if store == nil {
		return nil, errors.New("grant store is required")
	}
	return &Service{store: store, presenter: presenter}, nil
}

// List returns bounded safe records matching query.
func (s *Service) List(ctx context.Context, query grants.Query) (Page, error) {
	page, err := s.store.QueryGrants(query)
	if err != nil {
		return Page{}, err
	}
	out := Page{Items: make([]Item, 0, len(page.Grants)), NextCursor: page.NextCursor, HasMore: page.HasMore, EventCursor: page.EventCursor}
	for _, grant := range page.Grants {
		out.Items = append(out.Items, s.project(ctx, grant))
	}
	return out, nil
}

// Get returns one safe record by durable grant ID.
func (s *Service) Get(ctx context.Context, id string) (Item, error) {
	grant, err := s.store.Get(id)
	if err != nil {
		return Item{}, err
	}
	return s.project(ctx, grant), nil
}

// Project creates a safe item from an authoritative grant returned by a transition.
func (s *Service) Project(ctx context.Context, grant grants.Grant) Item {
	return s.project(ctx, grant)
}

func (s *Service) project(ctx context.Context, grant grants.Grant) Item {
	presentation, unavailable := approvalview.Project(ctx, s.presenter, grant)
	requester := approvalview.BoundedLine(grant.Client, maxLabelBytes)
	if requester == "" {
		requester = "Unknown requester"
	}
	requestedDuration := grant.RequestedDuration
	if requestedDuration <= 0 {
		requestedDuration = grant.Duration
	}
	requestedMaxUses := grant.RequestedMaxUses
	if requestedMaxUses < 0 {
		requestedMaxUses = grant.MaxUses
	}
	item := Item{
		ID: grant.ID, Revision: grant.Revision, Client: requester,
		Operation: approvalview.SafeOrEmpty(grant.Operation, maxTargetBytes, false), Status: grant.Status,
		RequestedAt: grant.CreatedAt, PendingExpiresAt: grant.PendingExpiresAt,
		RequestedDurationSeconds: int64(requestedDuration / time.Second), RequestedMaxUses: requestedMaxUses, MaxUses: grant.MaxUses,
		UsedCount: grant.UsedCount, ReservedCount: grant.ReservedCount,
		Reason: approvalview.SafeOrEmpty(grant.Reason, maxReasonBytes, true), DecidedBy: approvalview.SafeOrEmpty(grant.DecidedBy, maxLabelBytes, false),
		DecidedOnBehalfOf: approvalview.SafeOrEmpty(grant.DecidedOnBehalfOf, maxLabelBytes, false),
		Presentation:      presentation, PresentationUnavailable: unavailable,
	}
	if !grant.ExpiresAt.IsZero() {
		expires := grant.ExpiresAt
		item.ActiveExpiresAt = &expires
	}
	if !grant.DecidedAt.IsZero() {
		decided := grant.DecidedAt
		item.DecidedAt = &decided
	}
	return item
}

// Store exposes the durable store to the shared HTTP transport.
func (s *Service) Store() *grants.Store { return s.store }
