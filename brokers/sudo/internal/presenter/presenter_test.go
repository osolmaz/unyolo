package presenter

import (
	"fmt"
	"testing"

	"github.com/osolmaz/brokerkit/approval/view"
	"github.com/osolmaz/brokerkit/authorization/grants"
	corepolicy "github.com/osolmaz/brokerkit/authorization/policy"
	"github.com/osolmaz/brokerkit/brokers/sudo/internal/catalog"
	"github.com/osolmaz/brokerkit/brokers/sudo/internal/sudopolicy"
)

func TestPresenterUsesSafeCatalogFacts(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	snapshot, err := catalog.Parse([]byte(fmt.Sprintf(`{"version":1,"commands":[{
		"id":"scale","executable":"/usr/bin/printf","arguments":[{"slot":"replicas","type":"integer","minimum":1,"maximum":4}],
		"target_users":["root"],"working_directory":%q,"timeout_seconds":5,"max_output_bytes":100,
		"environment":{"PRIVATE_VALUE":"secret-canary"},"description":"Scale a reviewed worker pool.","risk":"high"}]}`, directory)))
	if err != nil {
		t.Fatal(err)
	}
	presentation, err := (Presenter{Catalog: snapshot}).Present(t.Context(), grants.Grant{
		Operation: sudopolicy.OperationExecCommand,
		Target:    corepolicy.Target{Kind: sudopolicy.TargetUser, Fields: map[string][]string{sudopolicy.TargetName: {"root"}}},
		Attrs:     map[string][]string{sudopolicy.AttrCommandID: {"scale"}, sudopolicy.ArgumentPrefix + "replicas": {"2"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if presentation.Risk != approvalview.RiskHigh || presentation.Title != "Run privileged command" || len(presentation.Facts) != 5 || len(presentation.Warnings) != 1 {
		t.Fatalf("presentation = %+v", presentation)
	}
	if fmt.Sprintf("%+v", presentation) == "" || contains(fmt.Sprintf("%+v", presentation), "secret-canary") || contains(fmt.Sprintf("%+v", presentation), "/usr/bin/printf") {
		t.Fatalf("presentation leaked private catalog data: %+v", presentation)
	}
}

func TestPresenterRejectsUnavailableCommand(t *testing.T) {
	t.Parallel()
	if _, err := (Presenter{}).Present(t.Context(), grants.Grant{}); err == nil {
		t.Fatal("nil catalog was accepted")
	}
	snapshot, err := catalog.Parse([]byte(`{"version":1,"commands":[{
		"id":"id","executable":"/usr/bin/printf","arguments":[],"target_users":["root"],
		"working_directory":"/","timeout_seconds":1,"max_output_bytes":0}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := (Presenter{Catalog: snapshot}).Present(t.Context(), grants.Grant{
		Attrs: map[string][]string{sudopolicy.AttrCommandID: {"id"}},
	}); err == nil {
		t.Fatal("grant without target user was accepted")
	}
}

func TestRiskMapping(t *testing.T) {
	t.Parallel()
	tests := map[string]approvalview.Risk{
		"low":      approvalview.RiskLow,
		"MEDIUM":   approvalview.RiskMedium,
		"high":     approvalview.RiskHigh,
		"critical": approvalview.RiskUnknown,
	}
	for value, want := range tests {
		if got := risk(value); got != want {
			t.Fatalf("risk(%q) = %q, want %q", value, got, want)
		}
	}
}

func TestPresenterCoversEveryCatalogCommand(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	snapshot, err := catalog.Parse([]byte(fmt.Sprintf(`{"version":1,"commands":[
		{"id":"inspect","executable":"/usr/bin/true","arguments":[],"target_users":["deploy"],"working_directory":%q,"timeout_seconds":5,"max_output_bytes":100,"risk":"low"},
		{"id":"restart","executable":"/usr/bin/true","arguments":[],"target_users":["deploy"],"working_directory":%q,"timeout_seconds":5,"max_output_bytes":100,"risk":"medium"},
		{"id":"upgrade","executable":"/usr/bin/true","arguments":[],"target_users":["root"],"working_directory":%q,"timeout_seconds":5,"max_output_bytes":100,"risk":"high"}
	]}`, directory, directory, directory)))
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct{ command, user string }{{"inspect", "deploy"}, {"restart", "deploy"}, {"upgrade", "root"}} {
		presentation, err := (Presenter{Catalog: snapshot}).Present(t.Context(), grants.Grant{
			Operation: sudopolicy.OperationExecCommand,
			Target:    corepolicy.Target{Kind: sudopolicy.TargetUser, Fields: map[string][]string{sudopolicy.TargetName: {test.user}}},
			Attrs:     map[string][]string{sudopolicy.AttrCommandID: {test.command}},
		})
		if err != nil {
			t.Errorf("Present(%q) error = %v", test.command, err)
			continue
		}
		if err := approvalview.Validate(presentation); err != nil || len(presentation.Warnings) == 0 {
			t.Errorf("Present(%q) = %+v, validation error = %v", test.command, presentation, err)
		}
	}
}

func contains(value, substring string) bool {
	for index := 0; index+len(substring) <= len(value); index++ {
		if value[index:index+len(substring)] == substring {
			return true
		}
	}
	return false
}
