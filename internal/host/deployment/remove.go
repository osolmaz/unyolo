package deployment

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/osolmaz/unyolo/deployment/api"
	componentprofile "github.com/osolmaz/unyolo/deployment/component"
	"github.com/osolmaz/unyolo/setup/sourceset"
)

// RemovalAPIVersion identifies the removal-plan schema.
const RemovalAPIVersion = "unyolo.io/host-removal/v1"

// RemovalActionKind is the closed enumeration of removal action kinds.
type RemovalActionKind string

const (
	RemovalActionRemoveFile      RemovalActionKind = "remove_file"
	RemovalActionRemoveDirectory RemovalActionKind = "remove_directory"
	RemovalActionRemoveAccount   RemovalActionKind = "remove_account"
	RemovalActionRemoveGroup     RemovalActionKind = "remove_group"
	RemovalActionRemoveRuntime   RemovalActionKind = "remove_runtime"
	RemovalActionDeleteReceipt   RemovalActionKind = "delete_receipt"
	RemovalActionRemoveContainer RemovalActionKind = "remove_container"
)

// RemovalReason names why a resource is retained during removal.
type RemovalReason string

const (
	RemovalReasonInstallation RemovalReason = "installation_owned"
	RemovalReasonChanged      RemovalReason = "changed_since_apply"
	RemovalReasonPreexisting  RemovalReason = "preexisting"
	RemovalReasonUnknown      RemovalReason = "identity_unavailable"
)

// RemovalAction is one bounded reviewed removal operation.
type RemovalAction struct {
	Kind           RemovalActionKind `json:"kind"`
	ID             string            `json:"id"`
	ComponentID    string            `json:"component_id,omitempty"`
	ResourceID     string            `json:"resource_id,omitempty"`
	Path           string            `json:"path,omitempty"`
	Home           string            `json:"home,omitempty"`
	Shell          string            `json:"shell,omitempty"`
	Group          string            `json:"group,omitempty"`
	Fingerprint    string            `json:"fingerprint,omitempty"`
	RuntimeBundles []string          `json:"runtime_bundles,omitempty"`
	Detail         string            `json:"detail,omitempty"`
	Destructive    bool              `json:"destructive"`
}

// RemovalRetention explains why one recorded resource will not be removed.
type RemovalRetention struct {
	Kind   string        `json:"kind"`
	ID     string        `json:"id"`
	Reason RemovalReason `json:"reason"`
	Detail string        `json:"detail,omitempty"`
}

// RemovalPlan is one canonical reviewed removal plan.
type RemovalPlan struct {
	APIVersion         string             `json:"api_version"`
	InstallationName   string             `json:"installation_name"`
	InstallationDigest string             `json:"installation_digest"`
	DeploymentDigest   string             `json:"deployment_digest"`
	RemoveState        bool               `json:"remove_state"`
	Actions            []RemovalAction    `json:"actions,omitempty"`
	Retained           []RemovalRetention `json:"retained,omitempty"`
	Warnings           []string           `json:"warnings,omitempty"`
}

// RemovalReport summarises the outcome of one applied removal plan.
type RemovalReport struct {
	APIVersion         string             `json:"api_version"`
	InstallationName   string             `json:"installation_name"`
	InstallationDigest string             `json:"installation_digest"`
	DeploymentDigest   string             `json:"deployment_digest"`
	RemovedActions     []RemovalAction    `json:"removed_actions,omitempty"`
	Retained           []RemovalRetention `json:"retained,omitempty"`
	RemoveState        bool               `json:"remove_state"`
}

// PlanRemoval reads the durable ownership receipt and computes a safe removal.
func (engine *Engine) PlanRemoval(ctx context.Context, removeState bool) (RemovalPlan, error) {
	receipt, found, err := LoadReceipt(engine.options.Paths.StateDir)
	if err != nil {
		return RemovalPlan{}, err
	}
	if !found {
		return RemovalPlan{}, errors.New("no ownership receipt: nothing recorded to remove")
	}
	plan := RemovalPlan{
		APIVersion:         RemovalAPIVersion,
		InstallationName:   receipt.InstallationName,
		InstallationDigest: receipt.InstallationDigest,
		DeploymentDigest:   receipt.DeploymentDigest,
		RemoveState:        removeState,
	}
	plan.Actions = append(plan.Actions, RemovalAction{
		Kind: RemovalActionRemoveRuntime, ID: receipt.RuntimeBundleID, Detail: receipt.BaselineBundleID,
		RuntimeBundles: append([]string(nil), receipt.RuntimeBundleIDs...),
	})
	if err := planReceiptResources(ctx, &plan, receipt); err != nil {
		return RemovalPlan{}, err
	}
	if err := planReceiptAccounts(ctx, &plan, receipt); err != nil {
		return RemovalPlan{}, err
	}
	protectAccountsWithRetainedHomeResources(&plan)
	planReceiptGroups(ctx, &plan, receipt)
	if canDeleteRemovalReceipt(plan) {
		plan.Actions = append(plan.Actions, RemovalAction{Kind: RemovalActionDeleteReceipt, ID: "receipt", Destructive: removeState})
	}
	return FilterRemovalPlan(plan), nil
}

func planReceiptResources(ctx context.Context, plan *RemovalPlan, receipt Receipt) error {
	for _, resource := range receipt.Resources {
		retention := RemovalRetention{Kind: resource.Kind, ID: resource.ComponentID + "." + resource.ID, Detail: resource.Path}
		if !resource.Created {
			retention.Reason = RemovalReasonPreexisting
			plan.Retained = append(plan.Retained, retention)
			continue
		}
		if resource.Data && !plan.RemoveState {
			retention.Reason = RemovalReasonInstallation
			plan.Retained = append(plan.Retained, retention)
			continue
		}
		if resource.Fingerprint == "" {
			retention.Reason = RemovalReasonUnknown
			plan.Retained = append(plan.Retained, retention)
			continue
		}
		current := receiptResourceFingerprint(ctx, resource)
		if current != "missing" && current != resource.Fingerprint {
			retention.Reason = RemovalReasonChanged
			plan.Retained = append(plan.Retained, retention)
			plan.Warnings = append(plan.Warnings, fmt.Sprintf("%s %q changed since apply; retaining it", resource.Kind, resource.ID))
			continue
		}
		kind, ok := removalKindForResource(resource.Kind)
		if !ok {
			retention.Reason = RemovalReasonUnknown
			plan.Retained = append(plan.Retained, retention)
			continue
		}
		plan.Actions = append(plan.Actions, RemovalAction{
			Kind: kind, ID: resource.ComponentID + "." + resource.ActionID, ComponentID: resource.ComponentID,
			ResourceID: resource.ID, Path: resource.Path, Home: resource.Home, Shell: resource.Shell,
			Group: resource.Group, Fingerprint: resource.Fingerprint, Destructive: resource.Data,
		})
	}
	return nil
}

func protectAccountsWithRetainedHomeResources(plan *RemovalPlan) {
	actions := plan.Actions[:0]
	for _, action := range plan.Actions {
		if action.Kind != RemovalActionRemoveAccount || action.Home == "" {
			actions = append(actions, action)
			continue
		}
		blocked := false
		for _, retained := range plan.Retained {
			if retained.Detail != "" && (retained.Detail == action.Home || strings.HasPrefix(retained.Detail, action.Home+string(filepath.Separator))) &&
				retained.Reason != RemovalReasonPreexisting {
				blocked = true
				break
			}
		}
		if blocked {
			plan.Retained = append(plan.Retained, RemovalRetention{Kind: "account", ID: action.ID, Reason: RemovalReasonChanged, Detail: "home contains retained resources"})
			continue
		}
		actions = append(actions, action)
	}
	plan.Actions = actions
}

func removalKindForResource(kind string) (RemovalActionKind, bool) {
	switch kind {
	case "file", "credential", "secret_store", "client", "git_config":
		return RemovalActionRemoveFile, true
	case "directory":
		return RemovalActionRemoveDirectory, true
	case "account":
		return RemovalActionRemoveAccount, true
	case "group":
		return RemovalActionRemoveGroup, true
	default:
		return "", false
	}
}

func planReceiptAccounts(ctx context.Context, plan *RemovalPlan, receipt Receipt) error {
	for _, account := range receipt.Accounts {
		retention := RemovalRetention{Kind: "account", ID: account.ID, Detail: account.UnixUser}
		if !account.Created {
			retention.Reason = RemovalReasonPreexisting
			plan.Retained = append(plan.Retained, retention)
			continue
		}
		matches, detail, err := accountIdentityMatches(ctx, account)
		if err != nil {
			return err
		}
		if !matches {
			retention.Reason, retention.Detail = RemovalReasonChanged, detail
			plan.Retained = append(plan.Retained, retention)
			plan.Warnings = append(plan.Warnings, fmt.Sprintf("managed account %q changed since apply; retaining it (%s)", account.UnixUser, detail))
			continue
		}
		if account.HomeFingerprint == "" {
			retention.Reason, retention.Detail = RemovalReasonUnknown, "home contents were not recorded"
			plan.Retained = append(plan.Retained, retention)
			continue
		}
		homeFingerprint, digestErr := sourceset.Digest(account.Home)
		if digestErr != nil || homeFingerprint != account.HomeFingerprint {
			retention.Reason, retention.Detail = RemovalReasonChanged, "home contents changed"
			plan.Retained = append(plan.Retained, retention)
			continue
		}
		plan.Actions = append(plan.Actions, RemovalAction{
			Kind: RemovalActionRemoveAccount, ID: "agent." + account.ID, ResourceID: account.UnixUser,
			Home: account.Home, Shell: account.Shell, Fingerprint: account.HomeFingerprint, Destructive: true,
		})
	}
	return nil
}

func planReceiptGroups(ctx context.Context, plan *RemovalPlan, receipt Receipt) {
	for _, group := range receipt.Groups {
		retention := RemovalRetention{Kind: "group", ID: group.Name}
		if !group.Created {
			retention.Reason = RemovalReasonPreexisting
			plan.Retained = append(plan.Retained, retention)
			continue
		}
		managedAccount := slices.ContainsFunc(receipt.Accounts, func(account AccountReceipt) bool { return account.Created && account.UnixUser == group.Name })
		accountRemoved := slices.ContainsFunc(plan.Actions, func(action RemovalAction) bool {
			return action.Kind == RemovalActionRemoveAccount && action.ResourceID == group.Name
		})
		if managedAccount && !accountRemoved {
			retention.Reason, retention.Detail = RemovalReasonChanged, "managed account was retained"
			plan.Retained = append(plan.Retained, retention)
			continue
		}
		fingerprint := componentprofile.ResourceFingerprint(ctx, api.Resource{Kind: "group", ID: group.Name}, false)
		if fingerprint == "missing" {
			continue
		}
		if !receiptDigestPattern.MatchString(fingerprint) {
			retention.Reason = RemovalReasonUnknown
			plan.Retained = append(plan.Retained, retention)
			continue
		}
		plan.Actions = append(plan.Actions, RemovalAction{
			Kind: RemovalActionRemoveGroup, ID: "agent-group." + group.Name, ResourceID: group.Name,
			Fingerprint: fingerprint, Destructive: true,
		})
	}
}

func canDeleteRemovalReceipt(plan RemovalPlan) bool {
	for _, retained := range plan.Retained {
		if retained.Reason != RemovalReasonPreexisting {
			return false
		}
	}
	return true
}

// accountIdentityMatches confirms that a recorded managed account still matches
// its receipt exactly before any destructive change.
func accountIdentityMatches(ctx context.Context, account AccountReceipt) (bool, string, error) {
	if account.Mode != "managed" {
		return false, "not a managed account", nil
	}
	entry, err := user.Lookup(account.UnixUser)
	if err != nil {
		var unknown user.UnknownUserError
		if errors.As(err, &unknown) {
			return false, "account no longer exists", nil
		}
		return false, "", fmt.Errorf("inspect account %q for removal: %w", account.UnixUser, err)
	}
	if filepath.Clean(entry.HomeDir) != filepath.Clean(account.Home) {
		return false, "home directory changed", nil
	}
	if runtime.GOOS != "linux" {
		return false, "managed account verification only supports Linux in Slice G", nil
	}
	output, err := exec.CommandContext(ctx, "getent", "passwd", account.UnixUser).Output() // #nosec G204 -- validated name from stored receipt.
	if err != nil {
		return false, "unable to inspect account entry", nil
	}
	fields := strings.Split(strings.TrimSpace(string(output)), ":")
	if len(fields) != 7 || filepath.Clean(fields[5]) != filepath.Clean(account.Home) ||
		filepath.Clean(fields[6]) != filepath.Clean(account.Shell) {
		return false, "shell or home differs from receipt", nil
	}
	return true, "", nil
}

// ApplyRemoval executes a reviewed removal plan and returns the outcome.
func (engine *Engine) ApplyRemoval(ctx context.Context, plan RemovalPlan) (RemovalReport, error) {
	if err := engine.requirePrivileged(); err != nil {
		return RemovalReport{}, err
	}
	if plan.APIVersion != RemovalAPIVersion {
		return RemovalReport{}, errors.New("removal plan API is invalid")
	}
	receipt, found, err := LoadReceipt(engine.options.Paths.StateDir)
	if err != nil {
		return RemovalReport{}, err
	}
	if !found {
		return RemovalReport{}, errors.New("no ownership receipt: nothing recorded to remove")
	}
	if receipt.DeploymentDigest != plan.DeploymentDigest || receipt.InstallationDigest != plan.InstallationDigest {
		return RemovalReport{}, errors.New("removal plan does not match recorded deployment")
	}
	lock, err := acquireHostLock(engine.options.Paths.StateDir)
	if err != nil {
		return RemovalReport{}, err
	}
	defer func() { _ = lock.close() }()
	fresh, err := engine.PlanRemoval(ctx, plan.RemoveState)
	if err != nil {
		return RemovalReport{}, err
	}
	if !reflect.DeepEqual(FilterRemovalPlan(plan), FilterRemovalPlan(fresh)) {
		return RemovalReport{}, errors.New("removal plan is stale")
	}
	report := RemovalReport{
		APIVersion: RemovalAPIVersion, InstallationName: receipt.InstallationName,
		InstallationDigest: receipt.InstallationDigest, DeploymentDigest: receipt.DeploymentDigest,
		Retained: plan.Retained, RemoveState: plan.RemoveState,
	}
	deletedReceipt, reloadServices := false, false
	for _, action := range FilterRemovalPlan(plan).Actions {
		if err := engine.executeRemovalAction(ctx, action); err != nil {
			return RemovalReport{}, fmt.Errorf("remove %s %q: %w", action.Kind, action.ID, err)
		}
		deletedReceipt = deletedReceipt || action.Kind == RemovalActionDeleteReceipt
		reloadServices = reloadServices || action.Path != "" && filepath.Dir(action.Path) == "/etc/systemd/system"
		report.RemovedActions = append(report.RemovedActions, action)
	}
	if reloadServices {
		if err := engine.options.Manager.Reload(ctx); err != nil {
			return RemovalReport{}, fmt.Errorf("reload native service definitions: %w", err)
		}
	}
	if !deletedReceipt {
		pruneRemovedReceiptResources(&receipt, report.RemovedActions)
		if err := SaveReceipt(engine.options.Paths.StateDir, receipt); err != nil {
			return RemovalReport{}, err
		}
	}
	return report, nil
}

//nolint:cyclop // Removal execution dispatches over one closed action enumeration.
func (engine *Engine) executeRemovalAction(ctx context.Context, action RemovalAction) error {
	switch action.Kind {
	case RemovalActionRemoveFile:
		return removeReceiptPath(ctx, action, false)
	case RemovalActionRemoveDirectory:
		return removeReceiptPath(ctx, action, true)
	case RemovalActionRemoveAccount:
		if action.Fingerprint != "" && !strings.HasPrefix(action.ID, "agent.") {
			if err := verifyRemovalFingerprint(ctx, action); err != nil {
				return err
			}
		}
		expectedHome := ""
		if strings.HasPrefix(action.ID, "agent.") {
			expectedHome = action.Fingerprint
		}
		return removeManagedAccount(ctx, action.ResourceID, action.Home, action.Shell, expectedHome)
	case RemovalActionRemoveGroup:
		if err := verifyRemovalFingerprint(ctx, action); err != nil {
			return err
		}
		return removeManagedGroup(ctx, action.ResourceID)
	case RemovalActionRemoveRuntime:
		return engine.installer().DeactivateInstallation(ctx, action.ID, action.Detail, action.RuntimeBundles)
	case RemovalActionDeleteReceipt:
		return DeleteReceipt(engine.options.Paths.StateDir)
	case RemovalActionRemoveContainer:
		return errors.New("container removal is not yet supported")
	default:
		return fmt.Errorf("unknown removal action %q", action.Kind)
	}
}

func verifyRemovalFingerprint(ctx context.Context, action RemovalAction) error {
	current := receiptResourceFingerprint(ctx, ResourceReceipt{
		Kind: removalResourceKind(action), ID: action.ResourceID, Path: action.Path, Data: action.Destructive,
	})
	if current == "missing" {
		return nil
	}
	if action.Fingerprint == "" || current != action.Fingerprint {
		return errors.New("resource changed after removal planning")
	}
	return nil
}

func removalResourceKind(action RemovalAction) string {
	if action.Kind == RemovalActionRemoveDirectory {
		return "directory"
	}
	if action.Kind == RemovalActionRemoveAccount {
		return "account"
	}
	if action.Kind == RemovalActionRemoveGroup {
		return "group"
	}
	return "file"
}

func removeReceiptPath(ctx context.Context, action RemovalAction, directory bool) error {
	if err := verifyRemovalFingerprint(ctx, action); err != nil {
		return err
	}
	info, err := os.Lstat(action.Path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("removal path is unavailable or unsafe")
	}
	if directory != info.IsDir() {
		return errors.New("removal path type changed")
	}
	if err := os.Remove(action.Path); err != nil {
		return err
	}
	return nil
}

func removeManagedGroup(ctx context.Context, name string) error {
	if _, err := user.LookupGroup(name); err != nil {
		var unknown user.UnknownGroupError
		if errors.As(err, &unknown) {
			return nil
		}
		return err
	}
	output, err := exec.CommandContext(ctx, "groupdel", name).CombinedOutput() // #nosec G204 -- receipt-bound validated group name.
	if err != nil {
		return fmt.Errorf("remove managed group %q: %w: %s", name, err, strings.TrimSpace(string(output)))
	}
	return nil
}

func pruneRemovedReceiptResources(receipt *Receipt, actions []RemovalAction) {
	removedResources, removedAccounts, removedGroups := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, action := range actions {
		if action.ComponentID != "" {
			removedResources[action.ComponentID+"\x00"+strings.TrimPrefix(action.ID, action.ComponentID+".")] = true
		}
		if action.Kind == RemovalActionRemoveAccount && strings.HasPrefix(action.ID, "agent.") {
			removedAccounts[strings.TrimPrefix(action.ID, "agent.")] = true
		}
		if action.Kind == RemovalActionRemoveGroup && strings.HasPrefix(action.ID, "agent-group.") {
			removedGroups[action.ResourceID] = true
		}
	}
	resources := receipt.Resources[:0]
	for _, resource := range receipt.Resources {
		if !removedResources[resource.ComponentID+"\x00"+resource.ActionID] {
			resources = append(resources, resource)
		}
	}
	receipt.Resources = resources
	accounts := receipt.Accounts[:0]
	for _, account := range receipt.Accounts {
		if !removedAccounts[account.ID] {
			accounts = append(accounts, account)
		}
	}
	receipt.Accounts = accounts
	groups := receipt.Groups[:0]
	for _, group := range receipt.Groups {
		if !removedGroups[group.Name] {
			groups = append(groups, group)
		}
	}
	receipt.Groups = groups
}

// removeManagedAccount fails closed unless the account still matches the receipt.
func removeManagedAccount(ctx context.Context, name, home, shell, expectedHomeFingerprint string) error {
	entry, err := user.Lookup(name)
	if err != nil {
		var unknown user.UnknownUserError
		if errors.As(err, &unknown) {
			return nil
		}
		return err
	}
	if filepath.Clean(entry.HomeDir) != filepath.Clean(home) {
		return errors.New("managed account home changed before removal")
	}
	if runtime.GOOS != "linux" {
		return errors.New("managed account removal is supported only on Linux")
	}
	entryData, err := exec.CommandContext(ctx, "getent", "passwd", name).Output() // #nosec G204 -- validated receipt-bound account name.
	fields := strings.Split(strings.TrimSpace(string(entryData)), ":")
	if err != nil || len(fields) != 7 || filepath.Clean(fields[5]) != filepath.Clean(home) || shell != "" && filepath.Clean(fields[6]) != filepath.Clean(shell) {
		return errors.New("managed account changed before removal")
	}
	if expectedHomeFingerprint != "" {
		fingerprint, digestErr := sourceset.Digest(home)
		if digestErr != nil || fingerprint != expectedHomeFingerprint {
			return errors.New("managed account home contents changed before removal")
		}
	}
	output, err := exec.CommandContext(ctx, "userdel", "--remove", name).CombinedOutput() // #nosec G204 -- validated managed account name from receipt.
	if err != nil {
		if _, lookupErr := user.Lookup(name); lookupErr == nil {
			return fmt.Errorf("remove managed account %q: %w: %s", name, err, strings.TrimSpace(string(output)))
		} else {
			var unknown user.UnknownUserError
			if !errors.As(lookupErr, &unknown) {
				return errors.Join(err, lookupErr)
			}
		}
	}
	if err := os.RemoveAll(home); err != nil {
		return fmt.Errorf("remove managed account home %q: %w", home, err)
	}
	return nil
}

// FilterRemovalPlan returns the same plan with retained-only warnings when there
// are no actions besides the receipt deletion. Callers use this to short-circuit
// noop removal.
func FilterRemovalPlan(plan RemovalPlan) RemovalPlan {
	if plan.APIVersion == "" {
		plan.APIVersion = RemovalAPIVersion
	}
	slices.SortFunc(plan.Actions, func(a, b RemovalAction) int {
		if removalActionRank(a) != removalActionRank(b) {
			return removalActionRank(a) - removalActionRank(b)
		}
		return strings.Compare(a.ID, b.ID)
	})
	slices.SortFunc(plan.Retained, func(a, b RemovalRetention) int {
		if a.Kind != b.Kind {
			return strings.Compare(a.Kind, b.Kind)
		}
		return strings.Compare(a.ID, b.ID)
	})
	return plan
}

func removalActionRank(action RemovalAction) int {
	switch action.Kind {
	case RemovalActionRemoveRuntime:
		return 0
	case RemovalActionRemoveGroup:
		if action.ComponentID != "" && !action.Destructive {
			return 1
		}
		return 4
	case RemovalActionRemoveAccount:
		return 2
	case RemovalActionRemoveFile, RemovalActionRemoveContainer:
		return 3
	case RemovalActionRemoveDirectory:
		return 5
	case RemovalActionDeleteReceipt:
		return 6
	default:
		return 99
	}
}

// RemovalPlanSummary is a short human-readable projection used by CLI output.
func RemovalPlanSummary(plan RemovalPlan) string {
	if len(plan.Actions) == 0 {
		return "Nothing to remove."
	}
	segments := []string{
		fmt.Sprintf("%d changes", len(plan.Actions)),
	}
	if len(plan.Retained) > 0 {
		segments = append(segments, fmt.Sprintf("%d retained", len(plan.Retained)))
	}
	if plan.RemoveState {
		segments = append(segments, "including recorded state")
	}
	return strings.Join(segments, " · ")
}

// RemovalPlanRecordedAt reports when a plan was created; used for status views.
func RemovalPlanRecordedAt() time.Time { return time.Now().UTC() }
