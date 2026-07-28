package httpapi

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/osolmaz/unyolo/agent/v1"
	"github.com/osolmaz/unyolo/authorization/grants"
	unyolopolicy "github.com/osolmaz/unyolo/authorization/policy"
	"github.com/osolmaz/unyolo/brokers/huggingface/internal/hubclient"
	"github.com/osolmaz/unyolo/brokers/huggingface/internal/operations"
	"github.com/osolmaz/unyolo/brokers/huggingface/internal/policy"
	"github.com/osolmaz/unyolo/telemetry/audit"
)

func TestOperationOutcomeAuditBindsPlanPolicyAndApproval(t *testing.T) {
	store := grants.New(filepath.Join(t.TempDir(), "grants.json"), grants.Options{})
	requested, _, err := store.Request(grants.Request{Client: "agent", ClientRequestID: "op-1", Operation: "repo.delete",
		Target: unyolopolicy.Target{Kind: "hf", Fields: map[string][]string{"name": {"dataset/acme/demo"}}}, Reason: "remove test repo",
		Duration: time.Minute, PendingTimeout: time.Minute, MaxUses: 1, MaxUsesSpecified: true})
	if err != nil {
		t.Fatal(err)
	}
	approved, err := store.Approve(requested.Grant.ID, requested.DecisionToken, "onur")
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	server := &Server{grants: store, audit: audit.New(&output)}
	digest := "sha256:" + strings.Repeat("a", 64)
	server.recordOperationOutcome(agentv1.Operation{ClientID: "agent", Operation: "repo.delete", ApprovalID: approved.ID, PlanDigest: digest},
		operations.Plan{Policy: policy.Request{Target: policy.Target{Kind: policy.KindRepo, Type: policy.TypeDataset, Owner: "acme", Name: "demo"}},
			PolicyDecision: operations.PolicyDecision{Effect: "request", RuleIDs: []string{"request-delete"}}}, audit.DecisionAllowed, "", 200)
	var event audit.Event
	if err := json.Unmarshal(bytes.TrimSpace(output.Bytes()), &event); err != nil {
		t.Fatal(err)
	}
	if event.PlanDigest != digest || event.GrantID != approved.ID || event.Approver != "onur" ||
		len(event.MatchedRequestRuleIDs) != 1 || event.MatchedRequestRuleIDs[0] != "request-delete" ||
		len(event.MatchedGrantRuleIDs) != 1 || event.MatchedGrantRuleIDs[0] != approved.ID {
		t.Fatalf("audit event = %+v", event)
	}
}

func TestFailedOperationAuditKeepsPlanContext(t *testing.T) {
	upstream := newAbsentRepoUpstream(t, "alice", "dataset", "recovery")
	defer upstream.Close()
	handler := newRecoveryTestServer(t, upstream.URL, emptyPolicyJSON())
	defer func() { _ = handler.Close() }()
	operation := seedExecutingRepoCreate(t, handler, "op_audit_failure")
	_, plan, err := handler.loadOperationPlan(operation)
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	handler.audit = audit.New(&output)
	handler.failOperationExecution(operation, plan, &hubclient.Error{Code: hubclient.CodeConflict}, nil)
	var event audit.Event
	if err := json.Unmarshal(bytes.TrimSpace(output.Bytes()), &event); err != nil {
		t.Fatal(err)
	}
	if event.Target != "dataset/alice/recovery" || event.PlanDigest != operation.PlanDigest ||
		len(event.MatchedRequestRuleIDs) != 1 || event.MatchedRequestRuleIDs[0] != "request-rule" {
		t.Fatalf("failure audit event = %+v", event)
	}
}
