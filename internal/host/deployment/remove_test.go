package deployment

import (
	"context"
	"errors"
	"os/user"
	"strings"
	"testing"
	"time"

	"github.com/osolmaz/unyolo/internal/host/bundle"
)

func TestPlanRemovalRequiresReceipt(t *testing.T) {
	t.Parallel()
	state := t.TempDir()
	engine := &Engine{options: Options{Paths: bundle.Paths{Root: t.TempDir(), StateDir: state}, Development: true, Manager: fakeManager{}}}
	if _, err := engine.PlanRemoval(t.Context(), false); err == nil || !strings.Contains(err.Error(), "receipt") {
		t.Fatalf("PlanRemoval() without receipt = %v", err)
	}
}

func TestPlanRemovalCollectsServicesAndRuntime(t *testing.T) {
	t.Parallel()
	state := t.TempDir()
	receipt := sampleReceipt()
	receipt.Accounts = nil // avoid needing real accounts
	if err := SaveReceipt(state, receipt); err != nil {
		t.Fatal(err)
	}
	engine := &Engine{options: Options{Paths: bundle.Paths{Root: t.TempDir(), StateDir: state}, Development: true, Manager: fakeManager{}, Now: func() time.Time { return time.Unix(0, 0).UTC() }}}
	plan, err := engine.PlanRemoval(t.Context(), false)
	if err != nil {
		t.Fatalf("PlanRemoval() = %v", err)
	}
	kinds := map[RemovalActionKind]int{}
	for _, action := range plan.Actions {
		kinds[action.Kind]++
	}
	if kinds[RemovalActionDisableService] != 1 || kinds[RemovalActionRemoveRuntime] != 1 || kinds[RemovalActionDeleteReceipt] != 1 {
		t.Fatalf("plan kinds = %#v", kinds)
	}
}

func TestPlanRemovalRetainsPreexistingAccounts(t *testing.T) {
	t.Parallel()
	state := t.TempDir()
	receipt := sampleReceipt()
	// The receipt has one existing account (bob) and one managed account (unyolo-agent).
	// Existing accounts are always retained.
	receipt.Accounts = []AccountReceipt{{ID: "bob", UnixUser: "bob", Mode: "existing", Home: "/home/bob", Shell: "/bin/bash"}}
	if err := SaveReceipt(state, receipt); err != nil {
		t.Fatal(err)
	}
	engine := &Engine{options: Options{Paths: bundle.Paths{Root: t.TempDir(), StateDir: state}, Development: true, Manager: fakeManager{}, Now: func() time.Time { return time.Unix(0, 0).UTC() }}}
	plan, err := engine.PlanRemoval(t.Context(), false)
	if err != nil {
		t.Fatalf("PlanRemoval() = %v", err)
	}
	if len(plan.Retained) != 1 || plan.Retained[0].Reason != RemovalReasonPreexisting {
		t.Fatalf("retained = %#v", plan.Retained)
	}
	for _, action := range plan.Actions {
		if action.Kind == RemovalActionRemoveAccount {
			t.Fatalf("plan attempted to remove preexisting account: %#v", action)
		}
	}
}

func TestAccountIdentityMatchesReportsMissingAccount(t *testing.T) {
	t.Parallel()
	receipt := AccountReceipt{
		ID: "surely-missing-unyolo-agent", UnixUser: "surely-missing-unyolo-agent",
		Mode: "managed", Home: "/var/lib/surely-missing-unyolo-agent", Shell: "/usr/sbin/nologin",
	}
	matches, detail, err := accountIdentityMatches(context.Background(), receipt)
	if err != nil {
		t.Fatal(err)
	}
	if matches || !strings.Contains(detail, "no longer exists") {
		t.Fatalf("expected missing account, got matches=%v detail=%q", matches, detail)
	}
}

func TestAccountIdentityMatchesRefusesNonManaged(t *testing.T) {
	t.Parallel()
	receipt := AccountReceipt{ID: "bob", UnixUser: "bob", Mode: "existing"}
	matches, detail, err := accountIdentityMatches(context.Background(), receipt)
	if err != nil || matches || !strings.Contains(detail, "not a managed") {
		t.Fatalf("existing account passed identity match: matches=%v detail=%q err=%v", matches, detail, err)
	}
}

func TestFilterRemovalPlanNormalizesOrder(t *testing.T) {
	t.Parallel()
	plan := RemovalPlan{
		APIVersion: "",
		Actions: []RemovalAction{
			{Kind: RemovalActionDeleteReceipt, ID: "receipt"},
			{Kind: RemovalActionDisableService, ID: "b"},
			{Kind: RemovalActionDisableService, ID: "a"},
		},
		Retained: []RemovalRetention{
			{Kind: "account", ID: "b"},
			{Kind: "account", ID: "a"},
		},
	}
	normalized := FilterRemovalPlan(plan)
	if normalized.APIVersion != RemovalAPIVersion {
		t.Fatalf("api version = %q", normalized.APIVersion)
	}
	// Actions sort first by kind then by ID. delete_receipt < disable_service alphabetically.
	if normalized.Actions[0].Kind != RemovalActionDeleteReceipt || normalized.Actions[1].ID != "a" || normalized.Actions[2].ID != "b" {
		t.Fatalf("actions not sorted: %#v", normalized.Actions)
	}
	if normalized.Retained[0].ID != "a" || normalized.Retained[1].ID != "b" {
		t.Fatalf("retained not sorted: %#v", normalized.Retained)
	}
}

func TestApplyRemovalRefusesMismatchedDigests(t *testing.T) {
	t.Parallel()
	state := t.TempDir()
	receipt := sampleReceipt()
	if err := SaveReceipt(state, receipt); err != nil {
		t.Fatal(err)
	}
	engine := &Engine{options: Options{Paths: bundle.Paths{Root: t.TempDir(), StateDir: state}, Development: true, Manager: fakeManager{}}}
	plan := RemovalPlan{APIVersion: RemovalAPIVersion, DeploymentDigest: "sha256:" + strings.Repeat("x", 64), InstallationDigest: receipt.InstallationDigest}
	if _, err := engine.ApplyRemoval(t.Context(), plan); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("ApplyRemoval() = %v", err)
	}
}

func TestRemoveManagedAccountRefusesWhenAccountChanged(t *testing.T) {
	t.Parallel()
	current, err := user.Current()
	if err != nil {
		t.Skipf("no current user available: %v", err)
	}
	// Removing an existing user with a mismatched home should fail closed before invoking any command.
	err = removeManagedAccount(t.Context(), current.Username, "/nonexistent/home/for/receipt-test")
	if err == nil {
		t.Fatal("expected failure due to home mismatch")
	}
	if !strings.Contains(err.Error(), "home changed") {
		t.Fatalf("expected 'home changed' error, got %v", err)
	}
}

func TestRemoveManagedAccountIgnoresUnknownUser(t *testing.T) {
	t.Parallel()
	// A user that doesn't exist is a noop, not an error, so the plan can safely re-run.
	err := removeManagedAccount(t.Context(), "unyolo-nonexistent-user-for-tests", "/nowhere")
	if err != nil {
		var unknown user.UnknownUserError
		if errors.As(err, &unknown) {
			t.Fatal("unknown user was leaked as error")
		}
		t.Fatal(err)
	}
}
