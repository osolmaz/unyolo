package httpapi

import (
	"testing"
	"time"

	"github.com/osolmaz/brokerkit/brokers/github/internal/ghplan"
	"github.com/osolmaz/brokerkit/grants"
	"github.com/osolmaz/brokerkit/policy"
	"github.com/osolmaz/brokerkit/state"
)

func TestGitHubPlanRetryReusesCreatedAtAcrossStoreReload(t *testing.T) {
	directory := t.TempDir()
	database, err := state.Open(t.Context(), directory, state.Options{})
	if err != nil {
		t.Fatal(err)
	}
	grantStore := grants.NewDatabase(database, grants.Options{})
	plans, err := ghplan.NewStore(database, "github_app")
	if err != nil {
		t.Fatal(err)
	}
	request := restartPlanRequest()
	plan, err := plans.PrepareBind(&request)
	if err != nil {
		t.Fatal(err)
	}
	firstDigest := request.Metadata[ghplan.MetadataDigest]
	if _, _, err := grantStore.RequestWithPlan(request, plan); err != nil {
		t.Fatal(err)
	}
	firstPlan, err := plans.Get(firstDigest)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}

	database, err = state.Open(t.Context(), directory, state.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	reloadedGrants := grants.NewDatabase(database, grants.Options{})
	reloadedPlans, err := ghplan.NewStore(database, "github_app")
	if err != nil {
		t.Fatal(err)
	}
	createdAt, exists, err := existingGitHubPlanCreatedAt(reloadedGrants, reloadedPlans, request.Client, request.ClientRequestID)
	if err != nil || !exists || !createdAt.Equal(firstPlan.CreatedAt) {
		t.Fatalf("existing created_at = %s, %t, %v", createdAt, exists, err)
	}
	retry := restartPlanRequest()
	retryPlan, err := reloadedPlans.PrepareBindAt(&retry, createdAt)
	if err != nil {
		t.Fatal(err)
	}
	if retry.Metadata[ghplan.MetadataDigest] != firstDigest {
		t.Fatalf("retry digest = %s, want %s", retry.Metadata[ghplan.MetadataDigest], firstDigest)
	}
	if result, created, err := reloadedGrants.RequestWithPlan(retry, retryPlan); err != nil || created || result.Grant.ClientRequestID != request.ClientRequestID {
		t.Fatalf("idempotent retry = %+v, %t, %v", result, created, err)
	}
}

func restartPlanRequest() grants.Request {
	return grants.Request{
		Client: "bob", ClientRequestID: "restart-request", Operation: "git.push.force",
		Target: policy.Target{Kind: "repo", Fields: map[string][]string{"owner": {"osolmaz"}, "name": {"gh-broker"}}},
		Attrs:  map[string][]string{"ref": {"refs/heads/main"}}, Reason: "repair", Duration: 5 * time.Minute, MaxUses: 1,
	}
}
