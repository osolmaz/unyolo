package httpapi

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/osolmaz/brokerkit/brokers/github/internal/ghplan"
	"github.com/osolmaz/brokerkit/grants"
	"github.com/osolmaz/brokerkit/policy"
)

func TestGitHubPlanRetryReusesCreatedAtAcrossStoreReload(t *testing.T) {
	directory := t.TempDir()
	grantPath := filepath.Join(directory, "grants.json")
	planPath := filepath.Join(directory, "plans")
	grantStore := grants.New(grantPath, grants.Options{})
	plans, err := ghplan.NewStore(planPath, "github_app")
	if err != nil {
		t.Fatal(err)
	}
	request := restartPlanRequest()
	if err := plans.Bind(&request); err != nil {
		t.Fatal(err)
	}
	firstDigest := request.Metadata[ghplan.MetadataDigest]
	firstPlan, err := plans.Get(firstDigest)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := grantStore.Request(request); err != nil {
		t.Fatal(err)
	}

	reloadedGrants := grants.New(grantPath, grants.Options{})
	reloadedPlans, err := ghplan.NewStore(planPath, "github_app")
	if err != nil {
		t.Fatal(err)
	}
	createdAt, exists, err := existingGitHubPlanCreatedAt(reloadedGrants, reloadedPlans, request.Client, request.ClientRequestID)
	if err != nil || !exists || !createdAt.Equal(firstPlan.CreatedAt) {
		t.Fatalf("existing created_at = %s, %t, %v", createdAt, exists, err)
	}
	retry := restartPlanRequest()
	if err := reloadedPlans.BindAt(&retry, createdAt); err != nil {
		t.Fatal(err)
	}
	if retry.Metadata[ghplan.MetadataDigest] != firstDigest {
		t.Fatalf("retry digest = %s, want %s", retry.Metadata[ghplan.MetadataDigest], firstDigest)
	}
	if result, created, err := reloadedGrants.Request(retry); err != nil || created || result.Grant.ClientRequestID != request.ClientRequestID {
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
