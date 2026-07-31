package deployment

import (
	"context"
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/osolmaz/unyolo/deployment/api"
	componentprofile "github.com/osolmaz/unyolo/deployment/component"
	"github.com/osolmaz/unyolo/internal/host/bundle"
)

func TestRemovalOrdersGroupsAroundAccountDeletion(t *testing.T) {
	t.Parallel()
	plan := FilterRemovalPlan(RemovalPlan{Actions: []RemovalAction{
		{Kind: RemovalActionRemoveAccount, ID: "account"},
		{Kind: RemovalActionRemoveGroup, ID: "secondary", ComponentID: "sudo"},
		{Kind: RemovalActionRemoveGroup, ID: "primary", ComponentID: "sudo", Destructive: true},
	}})
	if got := []string{plan.Actions[0].ID, plan.Actions[1].ID, plan.Actions[2].ID}; !slices.Equal(got, []string{"secondary", "account", "primary"}) {
		t.Fatalf("removal order = %#v", got)
	}
}

func TestPlanRemovalRequiresReceipt(t *testing.T) {
	t.Parallel()
	state := t.TempDir()
	engine := &Engine{options: Options{Paths: bundle.Paths{Root: t.TempDir(), StateDir: state}, Development: true, Manager: fakeManager{}}}
	if _, err := engine.PlanRemoval(t.Context(), false); err == nil || !strings.Contains(err.Error(), "receipt") {
		t.Fatalf("PlanRemoval() without receipt = %v", err)
	}
}

func TestPlanRemovalCollectsRuntimeAndFinalCleanup(t *testing.T) {
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
	if kinds[RemovalActionRemoveRuntime] != 1 || kinds[RemovalActionDeleteReceipt] != 1 {
		t.Fatalf("plan kinds = %#v", kinds)
	}
}

func TestPlanRemovalRemovesOnlyUnchangedCreatedResources(t *testing.T) {
	t.Parallel()
	state, root := t.TempDir(), t.TempDir()
	path := filepath.Join(root, "policy.json")
	if err := os.WriteFile(path, []byte("one\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	fingerprint := componentprofile.ResourceFingerprint(t.Context(), api.Resource{Kind: "file", ID: "policy", Path: path}, true)
	receipt := sampleReceipt()
	receipt.Accounts = nil
	receipt.Resources = []ResourceReceipt{{ComponentID: "github", ActionID: "file-policy", Kind: "file", ID: "policy", Path: path, Created: true, Fingerprint: fingerprint}}
	if err := SaveReceipt(state, receipt); err != nil {
		t.Fatal(err)
	}
	engine := &Engine{options: Options{Paths: bundle.Paths{Root: t.TempDir(), StateDir: state}, Development: true, Manager: fakeManager{}}}
	plan, err := engine.PlanRemoval(t.Context(), false)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(plan.Actions, func(action RemovalAction) bool { return action.Kind == RemovalActionRemoveFile }) {
		t.Fatalf("unchanged created file was not removable: %#v", plan)
	}
	if err := os.WriteFile(path, []byte("changed\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	changed, err := engine.PlanRemoval(t.Context(), false)
	if err != nil {
		t.Fatal(err)
	}
	if slices.ContainsFunc(changed.Actions, func(action RemovalAction) bool { return action.Kind == RemovalActionRemoveFile }) ||
		!slices.ContainsFunc(changed.Retained, func(item RemovalRetention) bool { return item.Reason == RemovalReasonChanged }) {
		t.Fatalf("changed file was not retained: %#v", changed)
	}
}

func TestPlanRemovalUsesContentFingerprintForGeneratedClients(t *testing.T) {
	t.Parallel()
	state, root := t.TempDir(), t.TempDir()
	path := filepath.Join(root, "client.json")
	if err := os.WriteFile(path, []byte("generated\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	fingerprintKey, err := ensureReceiptFingerprintKey(state)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(fingerprintKey)
	fingerprint := componentprofile.KeyedResourceFingerprint(t.Context(), api.Resource{Kind: "client", ID: "bob", Path: path}, fingerprintKey)
	receipt := sampleReceipt()
	receipt.Accounts = nil
	receipt.Resources = []ResourceReceipt{{ComponentID: "github", ActionID: "client-bob", Kind: "client", ID: "bob", Path: path, Created: true, Fingerprint: fingerprint}}
	if err := SaveReceipt(state, receipt); err != nil {
		t.Fatal(err)
	}
	engine := &Engine{options: Options{Paths: bundle.Paths{Root: t.TempDir(), StateDir: state}, Development: true, Manager: fakeManager{}}}
	plan, err := engine.PlanRemoval(t.Context(), false)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(plan.Actions, func(action RemovalAction) bool { return action.Kind == RemovalActionRemoveFile && action.Path == path }) {
		t.Fatalf("unchanged generated client was not removable: %#v", plan)
	}
}

func TestPlanRemovalRequiresSeparateDataConfirmation(t *testing.T) {
	t.Parallel()
	state, root := t.TempDir(), t.TempDir()
	path := filepath.Join(root, "clients.json")
	if err := os.WriteFile(path, []byte("secret-store\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	fingerprintKey, err := ensureReceiptFingerprintKey(state)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(fingerprintKey)
	fingerprint := componentprofile.KeyedResourceFingerprint(t.Context(), api.Resource{Kind: "secret_store", ID: "clients", Path: path}, fingerprintKey)
	originalInfo, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	receipt := sampleReceipt()
	receipt.Accounts = nil
	receipt.Resources = []ResourceReceipt{{ComponentID: "github", ActionID: "secret-store-clients", Kind: "secret_store", ID: "clients", Path: path, Created: true, Data: true, Fingerprint: fingerprint}}
	if err := SaveReceipt(state, receipt); err != nil {
		t.Fatal(err)
	}
	engine := &Engine{options: Options{Paths: bundle.Paths{Root: t.TempDir(), StateDir: state}, Development: true, Manager: fakeManager{}}}
	kept, err := engine.PlanRemoval(t.Context(), false)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(kept.Retained, func(item RemovalRetention) bool { return item.Reason == RemovalReasonInstallation }) {
		t.Fatalf("data was not retained by default: %#v", kept)
	}
	removed, err := engine.PlanRemoval(t.Context(), true)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(removed.Actions, func(action RemovalAction) bool { return action.Kind == RemovalActionRemoveFile && action.Destructive }) {
		t.Fatalf("confirmed data removal was not planned: %#v", removed)
	}
	if err := os.WriteFile(path, []byte("changed-data\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, originalInfo.ModTime(), originalInfo.ModTime()); err != nil {
		t.Fatal(err)
	}
	original := removed.Actions[slices.IndexFunc(removed.Actions, func(action RemovalAction) bool { return action.Path == path })]
	if err := verifyRemovalFingerprint(t.Context(), original, fingerprintKey); err == nil {
		t.Fatal("post-confirmation data change passed the final fingerprint check")
	}
	changed, err := engine.PlanRemoval(t.Context(), true)
	if err != nil {
		t.Fatal(err)
	}
	if slices.ContainsFunc(changed.Actions, func(action RemovalAction) bool { return action.Path == path }) ||
		!slices.ContainsFunc(changed.Retained, func(item RemovalRetention) bool { return item.Detail == path && item.Reason == RemovalReasonChanged }) {
		t.Fatalf("changed data was not retained: %#v", changed)
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
			{Kind: RemovalActionRemoveFile, ID: "b"},
			{Kind: RemovalActionRemoveFile, ID: "a"},
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
	// Resource deletion precedes final receipt deletion.
	if normalized.Actions[0].ID != "a" || normalized.Actions[1].ID != "b" || normalized.Actions[2].Kind != RemovalActionDeleteReceipt {
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
	err = removeManagedAccount(t.Context(), current.Username, "/nonexistent/home/for/receipt-test", "", "")
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
	err := removeManagedAccount(t.Context(), "unyolo-nonexistent-user-for-tests", "/nowhere", "", "")
	if err != nil {
		var unknown user.UnknownUserError
		if errors.As(err, &unknown) {
			t.Fatal("unknown user was leaked as error")
		}
		t.Fatal(err)
	}
}
