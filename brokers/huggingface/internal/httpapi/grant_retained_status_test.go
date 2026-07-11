package httpapi

import (
	"testing"

	"github.com/osolmaz/brokerkit/grants"
	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/policy"
)

func TestRetainedGrantAPIStatusIsUnavailable(t *testing.T) {
	grant := grants.Grant{
		Status:              grants.StatusActive,
		MaxUses:             3,
		ReservedCount:       1,
		ReservationRetained: true,
	}
	body := apiGrantFromStore(grant, policy.Target{})
	if body.Status != retainedGrantStatus || body.UsesRemaining != 0 {
		t.Fatalf("apiGrantFromStore(retained) = %+v", body)
	}
	if !validGrantStatusFilter(retainedGrantStatus) || !grantStatusMatchesFilter(grant, retainedGrantStatus) {
		t.Fatal("retained grant is not available through the retained status filter")
	}
	if !grantStatusMatchesFilter(grant, "") {
		t.Fatal("retained grant is missing from an unfiltered grant list")
	}
	if grantStatusMatchesFilter(grant, string(grants.StatusActive)) {
		t.Fatal("retained grant matched the active status filter")
	}
	normal := grants.Grant{Status: grants.StatusActive}
	if matched, handled := retainedGrantMatchesFilter(normal, string(grants.StatusActive)); matched || handled {
		t.Fatalf("retainedGrantMatchesFilter(normal) = matched %t handled %t", matched, handled)
	}
	if apiGrantStatus(normal) != string(grants.StatusActive) ||
		!grantStatusMatchesFilter(normal, string(grants.StatusActive)) ||
		grantStatusMatchesFilter(normal, retainedGrantStatus) {
		t.Fatal("normal active grant did not retain its active API status")
	}
}
