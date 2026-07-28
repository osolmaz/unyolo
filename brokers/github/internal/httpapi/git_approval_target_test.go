package httpapi

import (
	"testing"
	"time"

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

func TestReceivePackApprovalBounds(t *testing.T) {
	t.Parallel()
	items := []requestableReceivePackRequest{
		{Decision: policy.Decision{GrantPolicy: &corepolicy.GrantPolicy{Mode: string(corepolicy.GrantModeWindow), DefaultMinutes: 10, RequestTTLMinutes: 8, MaxUses: 1}}},
		{Decision: policy.Decision{GrantPolicy: &corepolicy.GrantPolicy{Mode: string(corepolicy.GrantModeWindow), DefaultMinutes: 5, RequestTTLMinutes: 3, MaxUses: 1}}},
		{Decision: policy.Decision{GrantPolicy: &corepolicy.GrantPolicy{Mode: string(corepolicy.GrantModeWindow), DefaultMinutes: 20, RequestTTLMinutes: 12, MaxUses: 1}}},
	}
	duration, pending, err := receivePackApprovalBounds(items)
	if err != nil || duration != 5*time.Minute || pending != 3*time.Minute {
		t.Fatalf("receivePackApprovalBounds() = %v, %v, %v", duration, pending, err)
	}
	for _, decision := range []policy.Decision{
		{},
		{GrantPolicy: &corepolicy.GrantPolicy{Mode: string(corepolicy.GrantModeExecution), MaxUses: 1}},
		{GrantPolicy: &corepolicy.GrantPolicy{Mode: string(corepolicy.GrantModeWindow), MaxUses: 0}},
	} {
		if _, _, err := receivePackApprovalBounds([]requestableReceivePackRequest{{Decision: decision}}); err == nil {
			t.Fatalf("receivePackApprovalBounds(%+v) error = nil", decision)
		}
	}
	if duration, pending, err := receivePackApprovalBounds(nil); err != nil || duration != 0 || pending != 0 {
		t.Fatalf("receivePackApprovalBounds(nil) = %v, %v, %v", duration, pending, err)
	}
}
