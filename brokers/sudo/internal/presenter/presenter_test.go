package presenter

import (
	"fmt"
	"testing"

	"github.com/osolmaz/brokerkit/brokers/sudo/internal/catalog"
	"github.com/osolmaz/brokerkit/brokers/sudo/internal/sudopolicy"
	"github.com/osolmaz/brokerkit/grants"
	"github.com/osolmaz/brokerkit/operatorinbox"
	corepolicy "github.com/osolmaz/brokerkit/policy"
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
	if presentation.Risk != operatorinbox.RiskHigh || presentation.Title != "Run privileged command" || len(presentation.Fields) != 5 {
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
}

func contains(value, substring string) bool {
	for index := 0; index+len(substring) <= len(value); index++ {
		if value[index:index+len(substring)] == substring {
			return true
		}
	}
	return false
}
