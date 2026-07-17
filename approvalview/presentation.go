// Package approvalview defines the bounded, provider-neutral display projection
// shared by operator APIs and approval notification channels.
package approvalview

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/osolmaz/brokerkit/grants"
)

const (
	maxTitleBytes    = 200
	maxSummaryBytes  = 2_000
	maxTargetBytes   = 500
	maxPlanHashBytes = 128
	maxFacts         = 20
	maxWarnings      = 10
	maxAudits        = 20
	maxLabelBytes    = 80
	maxValueBytes    = 500
	maxWarningBytes  = 500
)

// BoundedTitle truncates a trusted single-line title to the canonical title
// bound without splitting UTF-8. Validation still rejects unsafe text.
func BoundedTitle(value string) string {
	if len(value) <= maxTitleBytes {
		return value
	}
	const marker = "…"
	limit := maxTitleBytes - len(marker)
	for limit > 0 && !utf8.RuneStart(value[limit]) {
		limit--
	}
	return value[:limit] + marker
}

// Risk is a provider-supplied display classification with a fixed vocabulary.
type Risk string

const (
	RiskUnknown  Risk = "unknown"
	RiskLow      Risk = "low"
	RiskMedium   Risk = "medium"
	RiskHigh     Risk = "high"
	RiskCritical Risk = "critical"
)

// Fact is one bounded operator-facing display fact.
type Fact struct {
	Label string `json:"label"`
	Value string `json:"value"`
}

// Warning is one bounded provider-owned operator warning.
type Warning struct {
	Severity Risk   `json:"severity"`
	Text     string `json:"text"`
}

// Presentation is the provider-owned safe display projection.
type Presentation struct {
	Risk     Risk      `json:"risk"`
	Title    string    `json:"title"`
	Summary  string    `json:"summary,omitempty"`
	Target   string    `json:"target"`
	Facts    []Fact    `json:"facts,omitempty"`
	Warnings []Warning `json:"warnings,omitempty"`
	PlanHash string    `json:"plan_hash,omitempty"`
	Audit    []Fact    `json:"audit,omitempty"`
}

// Presenter converts a canonical grant into display-only provider wording.
type Presenter interface {
	Present(context.Context, grants.Grant) (Presentation, error)
}

// PresenterFunc adapts a function to Presenter.
type PresenterFunc func(context.Context, grants.Grant) (Presentation, error)

// Present implements Presenter.
func (f PresenterFunc) Present(ctx context.Context, grant grants.Grant) (Presentation, error) {
	return f(ctx, grant)
}

// Project returns a validated defensive copy or the safe generic fallback.
func Project(ctx context.Context, presenter Presenter, grant grants.Grant) (Presentation, bool) {
	fallback := Presentation{Risk: RiskUnknown, Title: "Approval request", Target: "Protected resource"}
	if presenter == nil {
		return fallback, false
	}
	presentation, err := presenter.Present(ctx, grant)
	if err != nil || Validate(presentation) != nil {
		return fallback, true
	}
	return clone(presentation), false
}

// Validate rejects unbounded or unsafe provider presentation data.
func Validate(value Presentation) error {
	if value.Risk == "" {
		value.Risk = RiskUnknown
	}
	if !validRisk(value.Risk) {
		return errors.New("invalid presentation risk")
	}
	if err := validatePresentationText(value); err != nil {
		return err
	}
	if err := validateFacts(value.Facts, maxFacts, "presentation"); err != nil {
		return err
	}
	if err := validateFacts(value.Audit, maxAudits, "audit"); err != nil {
		return err
	}
	return validateWarnings(value.Warnings)
}

func validatePresentationText(value Presentation) error {
	if !safeSingleLineText(value.Title, maxTitleBytes, true) || !safeSingleLineText(value.Target, maxTargetBytes, true) {
		return errors.New("invalid presentation text")
	}
	if !safeText(value.Summary, maxSummaryBytes, false) || !safeSingleLineText(value.PlanHash, maxPlanHashBytes, false) {
		return errors.New("invalid presentation details")
	}
	return nil
}

func validateWarnings(warnings []Warning) error {
	if len(warnings) > maxWarnings {
		return errors.New("too many presentation warnings")
	}
	for _, warning := range warnings {
		if !validRisk(warning.Severity) || !safeText(warning.Text, maxWarningBytes, true) {
			return errors.New("invalid presentation warning")
		}
	}
	return nil
}

func validRisk(value Risk) bool {
	switch value {
	case RiskUnknown, RiskLow, RiskMedium, RiskHigh, RiskCritical:
		return true
	default:
		return false
	}
}

func validateFacts(values []Fact, maximum int, kind string) error {
	if len(values) > maximum {
		return fmt.Errorf("too many %s facts", kind)
	}
	for _, value := range values {
		if !safeSingleLineText(value.Label, maxLabelBytes, true) || !safeText(value.Value, maxValueBytes, true) {
			return fmt.Errorf("invalid %s fact %q", kind, value.Label)
		}
	}
	return nil
}

func clone(value Presentation) Presentation {
	if value.Risk == "" {
		value.Risk = RiskUnknown
	}
	value.Facts = append([]Fact(nil), value.Facts...)
	value.Warnings = append([]Warning(nil), value.Warnings...)
	value.Audit = append([]Fact(nil), value.Audit...)
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
		if unicode.IsControl(char) && char != '\n' && char != '\t' {
			return false
		}
	}
	return true
}

func validTextSize(value string, maxBytes int, required bool) bool {
	return (!required || strings.TrimSpace(value) != "") && len(value) <= maxBytes && utf8.ValidString(value)
}
