package approvalview

import (
	"context"
	"errors"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/osolmaz/brokerkit/grants"
)

func TestProjectValidatesAndCopies(t *testing.T) {
	facts := []Fact{{Label: "Operation", Value: "repo.delete"}}
	warnings := []Warning{{Severity: RiskCritical, Text: "Permanent change."}}
	presentation, unavailable := Project(t.Context(), PresenterFunc(func(context.Context, grants.Grant) (Presentation, error) {
		return Presentation{Risk: RiskCritical, Title: "Delete repository", Target: "example/repo", Facts: facts, Warnings: warnings}, nil
	}), grants.Grant{})
	if unavailable || presentation.Title != "Delete repository" {
		t.Fatalf("Project() = %+v, unavailable=%v", presentation, unavailable)
	}
	facts[0].Value = "changed"
	warnings[0].Text = "changed"
	if presentation.Facts[0].Value != "repo.delete" || presentation.Warnings[0].Text != "Permanent change." {
		t.Fatal("Project() did not defensively copy provider output")
	}
}

func TestProjectFallback(t *testing.T) {
	presentation, unavailable := Project(t.Context(), PresenterFunc(func(context.Context, grants.Grant) (Presentation, error) {
		return Presentation{}, errors.New("unavailable")
	}), grants.Grant{})
	if !unavailable || presentation.Title == "" || presentation.Target == "" {
		t.Fatalf("Project() fallback = %+v, unavailable=%v", presentation, unavailable)
	}
	if presentation, unavailable = Project(t.Context(), nil, grants.Grant{}); unavailable || presentation.Title == "" {
		t.Fatalf("Project(nil) = %+v, unavailable=%v", presentation, unavailable)
	}
}

func TestValidateBoundsAndText(t *testing.T) {
	valid := Presentation{Risk: RiskLow, Title: "Request", Target: "repo"}
	if err := Validate(valid); err != nil {
		t.Fatal(err)
	}
	tests := []Presentation{
		{Risk: "invalid", Title: "Request", Target: "repo"},
		{Risk: RiskLow, Target: "repo"},
		{Risk: RiskLow, Title: "bad\ntitle", Target: "repo"},
		{Risk: RiskLow, Title: "Request", Target: "repo", Summary: strings.Repeat("x", maxSummaryBytes+1)},
		{Risk: RiskLow, Title: "Request", Target: "repo", Facts: make([]Fact, maxFacts+1)},
		{Risk: RiskLow, Title: "Request", Target: "repo", Facts: []Fact{{Label: "", Value: "value"}}},
		{Risk: RiskLow, Title: "Request", Target: "repo", Audit: make([]Fact, maxAudits+1)},
		{Risk: RiskLow, Title: "Request", Target: "repo", Warnings: make([]Warning, maxWarnings+1)},
		{Risk: RiskLow, Title: "Request", Target: "repo", Warnings: []Warning{{Severity: "invalid", Text: "warning"}}},
		{Risk: RiskLow, Title: "Request", Target: "repo", Warnings: []Warning{{Severity: RiskHigh, Text: "bad\x00value"}}},
	}
	for _, presentation := range tests {
		if err := Validate(presentation); err == nil {
			t.Fatalf("Validate(%+v) returned no error", presentation)
		}
	}
	invalidUTF8 := string([]byte{utf8.RuneSelf})
	if safeText(invalidUTF8, 10, false) || safeText("bad\x00", 10, false) || safeText(strings.Repeat("x", 11), 10, false) || safeText("  ", 10, true) {
		t.Fatal("safeText() accepted unsafe text")
	}
	if !safeText("line\nvalue\t", 20, true) {
		t.Fatal("safeText() rejected supported whitespace")
	}
}
