package httpapi

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/osolmaz/unyolo/authorization/grants"
	"github.com/osolmaz/unyolo/authorization/grants/grantstest"
	"github.com/osolmaz/unyolo/brokers/huggingface/internal/hfgrant"
	"github.com/osolmaz/unyolo/brokers/huggingface/internal/hfplan"
	"github.com/osolmaz/unyolo/brokers/huggingface/internal/policy"
)

func TestParseRepoListLimit(t *testing.T) {
	cases := []struct {
		value string
		want  int
		ok    bool
	}{
		{value: "", want: 100, ok: true},
		{value: "1", want: 1, ok: true},
		{value: "100", want: 100, ok: true},
		{value: "0", ok: false},
		{value: "101", ok: false},
		{value: "many", ok: false},
	}
	for _, tc := range cases {
		got, ok := parseRepoListLimit(tc.value)
		if got != tc.want || ok != tc.ok {
			t.Fatalf("parseRepoListLimit(%q) = %d, %v; want %d, %v", tc.value, got, ok, tc.want, tc.ok)
		}
	}
}

func TestReserveGrantUseFailureRefusesBeforeUpstream(t *testing.T) {
	dir := t.TempDir()
	store := grants.New(filepath.Join(dir, "grants.json"), grants.Options{})
	plans := testPlanStore(t)
	grant, _, err := requestHFGrant(t, store, plans, hfgrant.Input{
		Client:    "agent",
		Operation: string(policy.OpGitPushForce),
		Target:    "dataset/acme/repo",
		Ref:       "refs/heads/main",
		Reason:    "force push",
		MaxUses:   1,
	})
	if err != nil {
		t.Fatal(err)
	}
	approved, err := grantstest.Approve(store, grant.ID, "telegram:1")
	if err != nil {
		t.Fatalf("Approve() error = %v", err)
	}
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = os.Chmod(dir, 0o700)
	}()
	server := &Server{grants: store, plans: plans, planValidator: hfplan.Validator{Store: plans}}

	reserved, err := server.reserveGrantUses([]grantUse{{grant: approved}}, "persistence-failure-use")
	if err == nil {
		t.Fatalf("reserveGrantUses() error = nil, want persistence failure")
	}
	if len(reserved) != 0 {
		t.Fatalf("reserved grants after failure = %+v, want none", reserved)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := hfgrant.MatchActiveFunc(store, approved.Client, approved.Operation, hfgrant.Target(approved), hfgrant.Ref(approved), nil); err != nil || !ok {
		t.Fatalf("MatchActive() after failed reservation ok=%v err=%v, want true nil", ok, err)
	}
}

func TestReleaseGrantUsesRestoresReservedGrant(t *testing.T) {
	store := grants.New(filepath.Join(t.TempDir(), "grants.json"), grants.Options{})
	plans := testPlanStore(t)
	grant, _, err := requestHFGrant(t, store, plans, hfgrant.Input{
		Client:    "agent",
		Operation: string(policy.OpGitPushForce),
		Target:    "dataset/acme/repo",
		Ref:       "refs/heads/main",
		Reason:    "force push",
		MaxUses:   1,
	})
	if err != nil {
		t.Fatal(err)
	}
	approved, err := grantstest.Approve(store, grant.ID, "telegram:1")
	if err != nil {
		t.Fatalf("Approve() error = %v", err)
	}
	server := &Server{grants: store, plans: plans, planValidator: hfplan.Validator{Store: plans}}

	reserved, err := server.reserveGrantUses([]grantUse{{grant: approved}}, "released-reservation-use")
	if err != nil {
		t.Fatalf("reserveGrantUses() error = %v", err)
	}
	if _, ok, err := hfgrant.MatchActiveFunc(store, approved.Client, approved.Operation, hfgrant.Target(approved), hfgrant.Ref(approved), nil); err != nil || ok {
		t.Fatalf("MatchActive() while reserved ok=%v err=%v, want false nil", ok, err)
	}

	settleGrantUses(reserved, server.grants.ReleaseUse)
	if _, ok, err := hfgrant.MatchActiveFunc(store, approved.Client, approved.Operation, hfgrant.Target(approved), hfgrant.Ref(approved), nil); err != nil || !ok {
		t.Fatalf("MatchActive() after release ok=%v err=%v, want true nil", ok, err)
	}
}

func TestRetainGrantUseReservationsPersistsReviewMarker(t *testing.T) {
	store := grants.New(filepath.Join(t.TempDir(), "grants.json"), grants.Options{})
	plans := testPlanStore(t)
	grant, _, err := requestHFGrant(t, store, plans, hfgrant.Input{
		Client:    "agent",
		Operation: string(policy.OpGitPushForce),
		Target:    "dataset/acme/repo",
		Ref:       "refs/heads/main",
		Reason:    "ambiguous push",
	})
	if err != nil {
		t.Fatal(err)
	}
	approved, err := grantstest.Approve(store, grant.ID, "telegram:1")
	if err != nil {
		t.Fatalf("Approve() error = %v", err)
	}
	server := &Server{grants: store, plans: plans, planValidator: hfplan.Validator{Store: plans}}
	reserved, err := server.reserveGrantUses([]grantUse{{grant: approved}}, "retained-reservation-use")
	if err != nil {
		t.Fatalf("reserveGrantUses() error = %v", err)
	}

	if err := server.retainGrantUseReservations(reserved); err != nil {
		t.Fatalf("retainGrantUseReservations() error = %v", err)
	}
	retained, err := store.Get(grant.ID)
	if err != nil || !retained.ReservationRetained || retained.ReservedCount != 1 {
		t.Fatalf("retained grant = %+v, %v, want one retained reservation", retained, err)
	}
}
