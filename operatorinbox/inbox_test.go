package operatorinbox

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/osolmaz/brokerkit/grants"
	"github.com/osolmaz/brokerkit/policy"
)

func TestProjectionNeverExposesGrantInternals(t *testing.T) {
	store := grants.New(t.TempDir()+"/grants.json", grants.Options{})
	result, _, err := store.Request(grants.Request{
		Client: "bob", ClientRequestID: "safe", Operation: "provider.write",
		Target: policy.Target{Kind: "repo", Fields: map[string][]string{"name": {"demo"}}},
		Reason: "ship change", Metadata: map[string]string{"upstream_token": "protected-token-value"},
	})
	if err != nil {
		t.Fatal(err)
	}
	service, err := New(store, PresenterFunc(func(context.Context, grants.Grant) (Presentation, error) {
		return Presentation{Risk: RiskHigh, Title: "Write repository", Target: "demo"}, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	item, err := service.Get(context.Background(), result.Grant.ID)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(item)
	if err != nil {
		t.Fatal(err)
	}
	for _, protected := range []string{"protected-token-value", "decision_token_verifier", result.DecisionToken} {
		if strings.Contains(string(encoded), protected) {
			t.Fatalf("projection leaked %q: %s", protected, encoded)
		}
	}
}

func TestPresentationFailureFallsBackWithoutDroppingItem(t *testing.T) {
	store := grants.New(t.TempDir()+"/grants.json", grants.Options{})
	result, _, err := store.Request(grants.Request{
		Client: "bob", Operation: "provider.write", Target: policy.Target{Kind: "repo"}, Reason: "ship",
	})
	if err != nil {
		t.Fatal(err)
	}
	service, _ := New(store, PresenterFunc(func(context.Context, grants.Grant) (Presentation, error) {
		return Presentation{}, errors.New("provider presentation failed")
	}))
	item, err := service.Get(context.Background(), result.Grant.ID)
	if err != nil || !item.PresentationUnavailable || item.Presentation.Title == "" {
		t.Fatalf("Get() = %+v, %v", item, err)
	}
}

func TestPresentationValidationBounds(t *testing.T) {
	valid := Presentation{Risk: RiskLow, Title: "Request", Target: "repo"}
	if err := validatePresentation(valid); err != nil {
		t.Fatal(err)
	}
	tests := []Presentation{
		{Risk: "invalid", Title: "Request", Target: "repo"},
		{Risk: RiskLow, Target: "repo"},
		{Risk: RiskLow, Title: "bad\ntitle", Target: "repo"},
		{Risk: RiskLow, Title: "Request", Target: "repo", Summary: strings.Repeat("x", maxSummaryBytes+1)},
		{Risk: RiskLow, Title: "Request", Target: "repo", Fields: make([]DisplayField, maxFields+1)},
		{Risk: RiskLow, Title: "Request", Target: "repo", Fields: []DisplayField{{Label: "", Value: "value"}}},
		{Risk: RiskLow, Title: "Request", Target: "repo", Audit: make([]AuditSummary, maxAudits+1)},
		{Risk: RiskLow, Title: "Request", Target: "repo", Audit: []AuditSummary{{Label: "Fact", Value: "bad\x00value"}}},
	}
	for _, presentation := range tests {
		if err := validatePresentation(presentation); err == nil {
			t.Fatalf("validatePresentation(%+v) returned no error", presentation)
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

func TestListAndGenericPresenter(t *testing.T) {
	store := grants.New(t.TempDir()+"/grants.json", grants.Options{})
	if _, _, err := store.Request(grants.Request{Client: "bob", Operation: "write", Target: policy.Target{Kind: "repo"}, Reason: "test"}); err != nil {
		t.Fatal(err)
	}
	service, err := New(store, nil)
	if err != nil {
		t.Fatal(err)
	}
	page, err := service.List(context.Background(), grants.Query{})
	if err != nil || len(page.Items) != 1 || page.Items[0].Presentation.Title == "" {
		t.Fatalf("List() = %+v, %v", page, err)
	}
	if _, err := New(nil, nil); err == nil {
		t.Fatal("New() accepted nil store")
	}
}
