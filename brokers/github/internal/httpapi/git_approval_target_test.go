package httpapi

import (
	"testing"
	"time"

	"github.com/osolmaz/unyolo/authorization/grants"
	corepolicy "github.com/osolmaz/unyolo/authorization/policy"
	"github.com/osolmaz/unyolo/brokers/github/internal/policy"
)

func TestGitTransactionRequestIDIncludesTarget(t *testing.T) {
	t.Parallel()
	server := newTestServer(t)
	attrs := map[string][]string{"plan_digest": {"sha256:test"}}
	first, err := server.gitTransactionRequestID("bob", corepolicy.Target{Kind: "repo", Fields: map[string][]string{"owner": {"one"}, "name": {"repo"}}}, attrs, []string{"rule"})
	if err != nil {
		t.Fatal(err)
	}
	second, err := server.gitTransactionRequestID("bob", corepolicy.Target{Kind: "repo", Fields: map[string][]string{"owner": {"two"}, "name": {"repo"}}}, attrs, []string{"rule"})
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatalf("request IDs collide across targets: %q", first)
	}
}

func TestGrantCreatePlanStoresSelectedExecutionMode(t *testing.T) {
	t.Parallel()
	plan := grantCreatePlan{
		payload:  grantCreateRequest{ClientRequestID: "exact-request", Reason: "approve exact push"},
		request:  policy.Request{Client: "bob", Operation: policy.OperationGitPushForce, Target: policy.Target{Kind: "repo", Owner: "osolmaz", Repo: "unyolo"}},
		decision: policy.Decision{GrantPolicy: &corepolicy.GrantPolicy{Mode: string(corepolicy.GrantModeExecution)}},
		duration: time.Minute, pendingTimeout: time.Minute, maxUses: 1,
	}
	request := plan.storeRequest()
	if request.Metadata[grants.MetadataMode] != string(corepolicy.GrantModeExecution) || request.MaxUses != 1 {
		t.Fatalf("storeRequest() mode=%q max_uses=%d", request.Metadata[grants.MetadataMode], request.MaxUses)
	}
}

func TestReceivePackApprovalBounds(t *testing.T) {
	t.Parallel()
	items := []requestableReceivePackRequest{
		{Decision: policy.Decision{GrantPolicy: &corepolicy.GrantPolicy{Mode: string(corepolicy.GrantModeWindow), DefaultMinutes: 10, RequestTTLMinutes: 8, MaxUses: 1}}},
		{Decision: policy.Decision{GrantPolicy: &corepolicy.GrantPolicy{Mode: string(corepolicy.GrantModeWindow), DefaultMinutes: 5, RequestTTLMinutes: 3, MaxUses: 1}}},
		{Decision: policy.Decision{GrantPolicy: &corepolicy.GrantPolicy{Mode: string(corepolicy.GrantModeWindow), DefaultMinutes: 20, RequestTTLMinutes: 12, MaxUses: 1}}},
	}
	duration, pending, mode, err := receivePackApprovalBounds(items)
	if err != nil || duration != 5*time.Minute || pending != 3*time.Minute || mode != corepolicy.GrantModeWindow {
		t.Fatalf("receivePackApprovalBounds() = %v, %v, %q, %v", duration, pending, mode, err)
	}
	execution := append(items, requestableReceivePackRequest{Decision: policy.Decision{GrantPolicy: &corepolicy.GrantPolicy{
		Mode: string(corepolicy.GrantModeExecution), DefaultMinutes: 4, RequestTTLMinutes: 2, DefaultMaxUses: 1, MaxUses: 1,
	}}})
	duration, pending, mode, err = receivePackApprovalBounds(execution)
	if err != nil || duration != 4*time.Minute || pending != 2*time.Minute || mode != corepolicy.GrantModeExecution {
		t.Fatalf("execution receivePackApprovalBounds() = %v, %v, %q, %v", duration, pending, mode, err)
	}
	for _, decision := range []policy.Decision{
		{},
		{GrantPolicy: &corepolicy.GrantPolicy{Mode: "unsupported", DefaultMaxUses: 1}},
	} {
		if _, _, _, err := receivePackApprovalBounds([]requestableReceivePackRequest{{Decision: decision}}); err == nil {
			t.Fatalf("receivePackApprovalBounds(%+v) error = nil", decision)
		}
	}
	if duration, pending, mode, err := receivePackApprovalBounds(nil); err != nil || duration != 0 || pending != 0 || mode != corepolicy.GrantModeWindow {
		t.Fatalf("receivePackApprovalBounds(nil) = %v, %v, %q, %v", duration, pending, mode, err)
	}
}
