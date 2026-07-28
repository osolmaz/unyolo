package agentv1wire

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/osolmaz/unyolo/agent/v1"
)

func TestOperationRoundTrip(t *testing.T) {
	now := time.Date(2026, 7, 13, 8, 0, 0, 0, time.UTC)
	input := agentv1.Operation{APIVersion: agentv1.APIVersion, ID: "operation", Broker: "hf-broker", ClientID: "agent",
		IdempotencyKey: "key", Operation: "repo.create", Target: []byte(`{"kind":"repo"}`), Arguments: []byte(`{"private":true}`),
		Reason: "create", State: agentv1.StateSucceeded, Revision: 2, ApprovalID: "grant", CreatedAt: now, UpdatedAt: now,
		TerminalAt: &now, Presentation: agentv1.Presentation{Title: "Create", Summary: "Done"}, Result: []byte(`{"repo_id":"alice/data"}`),
		Error: &agentv1.OperationError{Code: "warning", Message: "message"}}
	wire, err := OperationToWire(input)
	if err != nil {
		t.Fatal(err)
	}
	output, err := OperationFromWire(wire)
	if err != nil || output.ID != input.ID || output.ApprovalID != input.ApprovalID || string(output.Result) != string(input.Result) || output.Error.Code != input.Error.Code {
		t.Fatalf("round trip = %+v, %v", output, err)
	}
}

func TestSubmitRoundTrip(t *testing.T) {
	input := agentv1.SubmitRequest{IdempotencyKey: "key", Operation: "repo.create", Target: []byte(`{"kind":"repo"}`), Arguments: []byte(`{}`), Reason: "create"}
	wire, err := SubmitToWire(input)
	if err != nil {
		t.Fatal(err)
	}
	output, err := SubmitFromWire(wire)
	if err != nil || output.IdempotencyKey != input.IdempotencyKey || string(output.Target) != string(input.Target) {
		t.Fatalf("round trip = %+v, %v", output, err)
	}
}

func TestDescriptorAndPageRoundTrip(t *testing.T) {
	descriptor := agentv1.Descriptor{APIVersion: agentv1.APIVersion, Operations: []string{"repo.read"},
		Credential: agentv1.CredentialDescriptor{Ready: true, Provider: "test", CredentialKind: "app", Generation: 2, VerificationState: "valid"}}
	wireDescriptor := DescriptorToWire(descriptor)
	if output := DescriptorFromWire(wireDescriptor); output.Credential.Generation != 2 || len(output.Operations) != 1 {
		t.Fatalf("descriptor round trip = %+v", output)
	}
	emptyWire := DescriptorToWire(agentv1.Descriptor{APIVersion: agentv1.APIVersion, Operations: []string{}})
	emptyJSON, err := json.Marshal(emptyWire)
	if err != nil {
		t.Fatal(err)
	}
	empty := DescriptorFromWire(emptyWire)
	if emptyWire.Operations == nil || empty.Operations == nil || !strings.Contains(string(emptyJSON), `"operations":[]`) {
		t.Fatalf("empty descriptor operations were not preserved: wire=%+v domain=%+v json=%s", emptyWire, empty, emptyJSON)
	}
	now := time.Date(2026, 7, 18, 0, 0, 0, 0, time.UTC)
	cursor := "next"
	page := agentv1.OperationPage{APIVersion: agentv1.APIVersion, NextCursor: &cursor, Operations: []agentv1.OperationSummary{{
		APIVersion: agentv1.APIVersion, ID: "op", Broker: "test", ClientID: "agent", IdempotencyKey: "request", Operation: "repo.read",
		State: agentv1.StatePending, Revision: 1, CreatedAt: now, UpdatedAt: now, Presentation: agentv1.Presentation{Title: "Read"},
	}}}
	wirePage := OperationPageToWire(page)
	output := OperationPageFromWire(wirePage)
	if output.NextCursor == nil || *output.NextCursor != cursor || len(output.Operations) != 1 || output.Operations[0].Presentation.Title != "Read" {
		t.Fatalf("page round trip = %+v", output)
	}
}
