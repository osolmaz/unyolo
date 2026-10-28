package operations

import (
	"encoding/json"
	"testing"

	"github.com/osolmaz/unyolo/brokers/github/internal/githubauth"
	"github.com/osolmaz/unyolo/brokers/github/internal/opbinding"
)

func TestProjectPaginationResultValidation(t *testing.T) {
	binding := opbinding.ByOperation("project.projects_list_items_for_org")[0]
	for _, test := range []struct {
		name       string
		body       string
		status     int
		pagination *githubauth.RESTPagination
		want       string
		failed     bool
	}{
		{name: "terminal", body: "[]", status: 200, pagination: &githubauth.RESTPagination{}, want: `{"items":[],"pagination":{"has_next":false}}`},
		{name: "next", body: `[{"id":13}]`, status: 200, pagination: &githubauth.RESTPagination{HasNext: true, NextAfter: "cursor2"}, want: `{"items":[{"id":13}],"pagination":{"has_next":true,"next_after":"cursor2"}}`},
		{name: "unavailable", body: "[]", status: 200, want: `{"items":[]}`},
		{name: "wrong_root", body: "{}", status: 200, pagination: &githubauth.RESTPagination{}, failed: true},
		{name: "invalid_json", body: "[", status: 200, pagination: &githubauth.RESTPagination{}, failed: true},
		{name: "wrong_status", body: "[]", status: 204, pagination: &githubauth.RESTPagination{}, failed: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			outcome, err := validatedExecutionResult(binding, binding.Operation, githubauth.ExecutionResult{StatusCode: test.status, Body: json.RawMessage(test.body), Pagination: test.pagination})
			if test.failed {
				if err == nil || outcome.Proven || len(outcome.Result) != 0 {
					t.Fatalf("invalid response produced terminal evidence: outcome=%+v err=%v", outcome, err)
				}
				return
			}
			if err != nil || !outcome.Proven || string(outcome.Result) != test.want {
				t.Fatalf("result=%s proven=%v err=%v; want %s", outcome.Result, outcome.Proven, err, test.want)
			}
		})
	}
	// Even an accidentally supplied pagination value cannot alter other routes.
	other := opbinding.ByOperation("project.projects_list_items_for_user")[0]
	outcome, err := validatedExecutionResult(other, other.Operation, githubauth.ExecutionResult{StatusCode: 200, Body: json.RawMessage("[]"), Pagination: &githubauth.RESTPagination{}})
	if err != nil || string(outcome.Result) != `{"items":[]}` {
		t.Fatalf("unrelated operation changed: result=%s err=%v", outcome.Result, err)
	}
}
