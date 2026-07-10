// Package operatorinbox projects durable grants into bounded, operator-safe records.
package operatorinbox

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/osolmaz/brokerkit/grants"
)

const (
	maxTitleBytes    = 200
	maxSummaryBytes  = 2_000
	maxTargetBytes   = 500
	maxReasonBytes   = 2_000
	maxPlanHashBytes = 128
	maxFields        = 20
	maxAudits        = 20
	maxLabelBytes    = 80
	maxValueBytes    = 500
)

// Risk is a provider-supplied display classification with a fixed vocabulary.
type Risk string

const (
	RiskUnknown  Risk = "unknown"
	RiskLow      Risk = "low"
	RiskMedium   Risk = "medium"
	RiskHigh     Risk = "high"
	RiskCritical Risk = "critical"
)

// LabeledValue is one bounded operator-facing display fact.
type LabeledValue struct {
	Label string `json:"label"`
	Value string `json:"value"`
}

// DisplayField is one bounded provider-specific display value.
type DisplayField = LabeledValue

// AuditSummary is one safe, bounded audit fact.
type AuditSummary = LabeledValue

// Presentation is the provider-owned safe display projection.
type Presentation struct {
	Risk     Risk           `json:"risk"`
	Title    string         `json:"title"`
	Summary  string         `json:"summary,omitempty"`
	Target   string         `json:"target"`
	Fields   []DisplayField `json:"fields,omitempty"`
	PlanHash string         `json:"plan_hash,omitempty"`
	Audit    []AuditSummary `json:"audit,omitempty"`
}

// Presenter converts a canonical grant into display-only provider wording.
type Presenter interface {
	Present(context.Context, grants.Grant) (Presentation, error)
}

// PresenterFunc adapts a function to Presenter.
type PresenterFunc func(context.Context, grants.Grant) (Presentation, error)

func (f PresenterFunc) Present(ctx context.Context, grant grants.Grant) (Presentation, error) {
	return f(ctx, grant)
}

// Item is the only grant representation exposed by the operator HTTP API.
type Item struct {
	ID                       string        `json:"id"`
	Revision                 int64         `json:"revision"`
	Client                   string        `json:"client"`
	Operation                string        `json:"operation"`
	Status                   grants.Status `json:"status"`
	RequestedAt              time.Time     `json:"requested_at"`
	PendingExpiresAt         time.Time     `json:"pending_expires_at"`
	ActiveExpiresAt          *time.Time    `json:"active_expires_at,omitempty"`
	RequestedDurationSeconds int64         `json:"requested_duration_seconds"`
	MaxUses                  int           `json:"max_uses"`
	UsedCount                int           `json:"used_count"`
	ReservedCount            int           `json:"reserved_count"`
	Reason                   string        `json:"reason,omitempty"`
	DecidedAt                *time.Time    `json:"decided_at,omitempty"`
	DecidedBy                string        `json:"decided_by,omitempty"`
	DecisionReason           string        `json:"decision_reason,omitempty"`
	Presentation             Presentation  `json:"presentation"`
	PresentationUnavailable  bool          `json:"presentation_unavailable,omitempty"`
}

// Page is one bounded inbox result.
type Page struct {
	Items      []Item `json:"items"`
	NextCursor string `json:"next_cursor,omitempty"`
	HasMore    bool   `json:"has_more"`
}

// Service joins the durable store with one broker-owned presenter.
type Service struct {
	store     *grants.Store
	presenter Presenter
}

// New constructs an inbox service. A nil presenter uses safe generic wording.
func New(store *grants.Store, presenter Presenter) (*Service, error) {
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
	out := Page{Items: make([]Item, 0, len(page.Grants)), NextCursor: page.NextCursor, HasMore: page.HasMore}
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
	presentation, unavailable := s.presentation(ctx, grant)
	item := Item{
		ID: grant.ID, Revision: grant.Revision, Client: safeOrEmpty(grant.Client, maxLabelBytes, false),
		Operation: safeOrEmpty(grant.Operation, maxTargetBytes, false), Status: grant.Status,
		RequestedAt: grant.CreatedAt, PendingExpiresAt: grant.PendingExpiresAt,
		RequestedDurationSeconds: int64(grant.Duration / time.Second), MaxUses: grant.MaxUses,
		UsedCount: grant.UsedCount, ReservedCount: grant.ReservedCount,
		Reason: safeOrEmpty(grant.Reason, maxReasonBytes, true), DecidedBy: safeOrEmpty(grant.DecidedBy, maxLabelBytes, false),
		DecisionReason: safeOrEmpty(grant.DecisionReason, maxReasonBytes, true),
		Presentation:   presentation, PresentationUnavailable: unavailable,
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

func (s *Service) presentation(ctx context.Context, grant grants.Grant) (Presentation, bool) {
	fallback := Presentation{Risk: RiskUnknown, Title: "Approval request", Target: "Protected resource"}
	if s.presenter == nil {
		return fallback, false
	}
	presentation, err := s.presenter.Present(ctx, grant)
	if err != nil || validatePresentation(presentation) != nil {
		return fallback, true
	}
	return copyPresentation(presentation), false
}

func validatePresentation(value Presentation) error {
	if value.Risk == "" {
		value.Risk = RiskUnknown
	}
	switch value.Risk {
	case RiskUnknown, RiskLow, RiskMedium, RiskHigh, RiskCritical:
	default:
		return errors.New("invalid risk")
	}
	if !safeSingleLineText(value.Title, maxTitleBytes, true) || !safeSingleLineText(value.Target, maxTargetBytes, true) {
		return errors.New("invalid presentation text")
	}
	if !safeText(value.Summary, maxSummaryBytes, false) || !safeSingleLineText(value.PlanHash, maxPlanHashBytes, false) {
		return errors.New("invalid presentation details")
	}
	if err := validateDisplayFields(value.Fields); err != nil {
		return err
	}
	return validateAuditSummaries(value.Audit)
}

func validateDisplayFields(fields []DisplayField) error {
	return validateLabelValues(fields, maxFields, "presentation")
}

func validateAuditSummaries(audits []AuditSummary) error {
	return validateLabelValues(audits, maxAudits, "audit")
}

func validateLabelValues(values []LabeledValue, maximum int, kind string) error {
	if len(values) > maximum {
		return fmt.Errorf("too many %s fields", kind)
	}
	for _, value := range values {
		if !safeSingleLineText(value.Label, maxLabelBytes, true) || !safeText(value.Value, maxValueBytes, true) {
			return fmt.Errorf("invalid %s field %q", kind, value.Label)
		}
	}
	return nil
}

func copyPresentation(value Presentation) Presentation {
	if value.Risk == "" {
		value.Risk = RiskUnknown
	}
	value.Fields = append([]DisplayField(nil), value.Fields...)
	value.Audit = append([]AuditSummary(nil), value.Audit...)
	return value
}

func safeOrEmpty(value string, maxBytes int, multiline bool) string {
	validator := safeSingleLineText
	if multiline {
		validator = safeText
	}
	if !validator(value, maxBytes, false) {
		return ""
	}
	return value
}

func safeSingleLineText(value string, maxBytes int, required bool) bool {
	if !validTextSize(value, maxBytes, required) {
		return false
	}
	for _, char := range value {
		if unicode.IsControl(char) {
			return false
		}
	}
	return true
}

func safeText(value string, maxBytes int, required bool) bool {
	if !validTextSize(value, maxBytes, required) {
		return false
	}
	for _, char := range value {
		if !supportedTextRune(char) {
			return false
		}
	}
	return true
}

func validTextSize(value string, maxBytes int, required bool) bool {
	return (!required || strings.TrimSpace(value) != "") && len(value) <= maxBytes && utf8.ValidString(value)
}

func supportedTextRune(char rune) bool {
	return !unicode.IsControl(char) || char == '\n' || char == '\t'
}

// Store exposes the durable store to the shared HTTP transport.
func (s *Service) Store() *grants.Store { return s.store }
