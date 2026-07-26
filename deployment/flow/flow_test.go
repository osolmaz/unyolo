package flow

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestStepValidation(t *testing.T) {
	expires := time.Now().Add(time.Minute)
	tests := []struct {
		name string
		step Step
		ok   bool
	}{
		{"select", Step{APIVersion: APIVersion, ID: "provider", Type: StepSelect, Title: "Provider", Options: []Option{{Value: "github", Label: "GitHub"}}}, true},
		{"secret default", Step{APIVersion: APIVersion, ID: "token", Type: StepSecret, Title: "Token", Default: "leak"}, false},
		{"http URL", Step{APIVersion: APIVersion, ID: "login", Type: StepOpenURL, Title: "Login", URL: "http://example.com"}, false},
		{"device code", Step{APIVersion: APIVersion, ID: "device", Type: StepDeviceCode, Title: "Device", Code: "ABCD", ExpiresAt: &expires}, true},
		{"duplicate option", Step{APIVersion: APIVersion, ID: "provider", Type: StepSelect, Title: "Provider", Options: []Option{{Value: "a", Label: "A"}, {Value: "a", Label: "Again"}}}, false},
		{"multiselect", Step{APIVersion: APIVersion, ID: "providers", Type: StepMultiSelect, Title: "Providers", Options: []Option{{Value: "a", Label: "A"}}}, true},
		{"text", Step{APIVersion: APIVersion, ID: "name", Type: StepText, Title: "Name", Validation: Validation{MinLength: 1, MaxLength: 20, Pattern: `^[a-z]+$`}}, true},
		{"secret", Step{APIVersion: APIVersion, ID: "secret", Type: StepSecret, Title: "Secret"}, true},
		{"file", Step{APIVersion: APIVersion, ID: "file", Type: StepFile, Title: "File"}, true},
		{"confirm", Step{APIVersion: APIVersion, ID: "confirm", Type: StepConfirm, Title: "Confirm"}, true},
		{"progress", Step{APIVersion: APIVersion, ID: "progress", Type: StepProgress, Title: "Progress"}, true},
		{"review", Step{APIVersion: APIVersion, ID: "review", Type: StepReview, Title: "Review"}, true},
		{"wrong version", Step{APIVersion: "old", ID: "note", Type: StepNote, Title: "Note"}, false},
		{"invalid ID", Step{APIVersion: APIVersion, ID: "bad id", Type: StepNote, Title: "Note"}, false},
		{"missing title", Step{APIVersion: APIVersion, ID: "note", Type: StepNote}, false},
		{"unknown type", Step{APIVersion: APIVersion, ID: "note", Type: "unknown", Title: "Note"}, false},
		{"options on text", Step{APIVersion: APIVersion, ID: "text", Type: StepText, Title: "Text", Options: []Option{{Value: "a", Label: "A"}}}, false},
		{"empty options", Step{APIVersion: APIVersion, ID: "select", Type: StepSelect, Title: "Select"}, false},
		{"bad option", Step{APIVersion: APIVersion, ID: "select", Type: StepSelect, Title: "Select", Options: []Option{{Value: "", Label: "A"}}}, false},
		{"bad lengths", Step{APIVersion: APIVersion, ID: "text", Type: StepText, Title: "Text", Validation: Validation{MinLength: 2, MaxLength: 1}}, false},
		{"bad pattern", Step{APIVersion: APIVersion, ID: "text", Type: StepText, Title: "Text", Validation: Validation{Pattern: "["}}, false},
		{"wrong transient", Step{APIVersion: APIVersion, ID: "note", Type: StepNote, Title: "Note", Code: "leak"}, false},
		{"device incomplete", Step{APIVersion: APIVersion, ID: "device", Type: StepDeviceCode, Title: "Device"}, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := test.step.Validate()
			if (err == nil) != test.ok {
				t.Fatalf("Validate() error = %v, ok = %v", err, test.ok)
			}
		})
	}
}

func TestFlowErrorsAndHTTPSValidation(t *testing.T) {
	cause := errors.New("cause")
	cancelled := CancelledError{Cause: cause}
	if cancelled.Error() != "setup cancelled" || !errors.Is(cancelled, cause) {
		t.Fatalf("cancelled = %v", cancelled)
	}
	if got := (NavigationError{Direction: "back"}).Error(); !strings.Contains(got, "back") {
		t.Fatalf("navigation = %q", got)
	}
	for _, value := range []string{"", "http://example.com", "https://user@example.com", "https:///missing"} {
		if err := validateHTTPS(value); err == nil {
			t.Fatalf("URL %q was accepted", value)
		}
	}
}
