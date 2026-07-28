package httpapi

import (
	"testing"

	"github.com/osolmaz/unyolo/authorization/grants"
)

func TestGrantAPIStatusAndRemainingUses(t *testing.T) {
	retained := grants.Grant{Status: grants.StatusActive, MaxUses: 3, ReservedCount: 1, ReservationRetained: true}
	if apiGrantStatus(retained) != "retained" || grantUsesRemaining(retained) != 0 {
		t.Fatalf("retained grant status=%q remaining=%d", apiGrantStatus(retained), grantUsesRemaining(retained))
	}
	active := grants.Grant{Status: grants.StatusActive, MaxUses: 3, UsedCount: 1, ReservedCount: 1}
	if apiGrantStatus(active) != string(grants.StatusActive) || grantUsesRemaining(active) != 1 {
		t.Fatalf("active grant status=%q remaining=%d", apiGrantStatus(active), grantUsesRemaining(active))
	}
	if grantUsesRemaining(grants.Grant{Status: grants.StatusDenied, MaxUses: 3}) != 0 {
		t.Fatal("terminal grant reported remaining uses")
	}
	if grantUsesRemaining(grants.Grant{Status: grants.StatusActive, MaxUses: 1, UsedCount: 1}) != 0 {
		t.Fatal("exhausted grant reported remaining uses")
	}
	if grantUsesRemaining(grants.Grant{Status: grants.StatusActive, MaxUses: 1, UsedCount: 2}) != 0 {
		t.Fatal("overspent grant reported negative remaining uses")
	}
}
