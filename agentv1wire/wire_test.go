package agentv1wire

import (
	"testing"
	"time"

	"github.com/osolmaz/brokerkit/agentv1"
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
