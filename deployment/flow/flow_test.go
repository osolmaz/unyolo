package flow

import (
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
