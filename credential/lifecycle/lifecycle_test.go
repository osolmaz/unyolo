package credentiallifecycle

import (
	"bytes"
	"strings"
	"testing"

	"github.com/osolmaz/brokerkit/telemetry/audit"
)

func TestReporterRecordsClosedSecretSafeLifecycleEvent(t *testing.T) {
	var output bytes.Buffer
	reporter, err := New(audit.New(&output), "gh-broker", "operator-a")
	if err != nil {
		t.Fatal(err)
	}
	err = reporter.Record(Event{Class: "github-user-oauth", Action: ActionRotated, Outcome: OutcomeSucceeded,
		PreviousID: "github-user:7", CurrentID: "github-user:7", Provider: "github"})
	if err != nil {
		t.Fatal(err)
	}
	got := output.String()
	for _, want := range []string{`"operation":"credential.lifecycle"`, `"target":"github-user-oauth"`, `"lifecycle_action":"rotated"`, `"provider":"github"`} {
		if !strings.Contains(got, want) {
			t.Fatalf("audit event missing %s: %s", want, got)
		}
	}
}

func TestReporterRejectsUnboundedOrOpenValues(t *testing.T) {
	if !ValidIdentifier("broker-client") || ValidIdentifier("broker client") {
		t.Fatal("ValidIdentifier accepted an open value")
	}
	reporter, err := New(audit.New(&bytes.Buffer{}), "gh-broker", "operator-a")
	if err != nil {
		t.Fatal(err)
	}
	for _, event := range []Event{
		{Class: "github user", Action: ActionCreated, Outcome: OutcomeSucceeded},
		{Class: "github-user", Action: "copied", Outcome: OutcomeSucceeded},
		{Class: "github-user", Action: ActionCreated, Outcome: "maybe"},
		{Class: "github-user", Action: ActionCreated, Outcome: OutcomeSucceeded, CurrentID: "raw value with spaces"},
	} {
		if err := reporter.Record(event); err == nil {
			t.Fatalf("Record(%+v) error = nil", event)
		}
	}
}
