package deployment

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"time"
)

// RemovalAPIVersion identifies the removal-plan schema.
const RemovalAPIVersion = "unyolo.io/host-removal/v1"

// RemovalActionKind is the closed enumeration of removal action kinds.
type RemovalActionKind string

const (
	RemovalActionDisableService  RemovalActionKind = "disable_service"
	RemovalActionRemoveAccount   RemovalActionKind = "remove_account"
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
	Kind        RemovalActionKind `json:"kind"`
	ID          string            `json:"id"`
	Detail      string            `json:"detail,omitempty"`
	Destructive bool              `json:"destructive"`
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
	planReceiptServices(&plan, receipt)
	if err := planReceiptAccounts(ctx, &plan, receipt); err != nil {
		return RemovalPlan{}, err
	}
	planReceiptRuntime(&plan, receipt)
	if removeState {
		plan.Actions = append(plan.Actions, RemovalAction{Kind: RemovalActionDeleteReceipt, ID: "receipt", Destructive: true})
	} else {
		plan.Actions = append(plan.Actions, RemovalAction{Kind: RemovalActionDeleteReceipt, ID: "receipt"})
	}
	return plan, nil
}

func planReceiptServices(plan *RemovalPlan, receipt Receipt) {
	for _, service := range receipt.Services {
		plan.Actions = append(plan.Actions, RemovalAction{
			Kind:   RemovalActionDisableService,
			ID:     service.Name,
			Detail: service.Component,
		})
	}
}

func planReceiptAccounts(ctx context.Context, plan *RemovalPlan, receipt Receipt) error {
	for _, account := range receipt.Accounts {
		if !account.Created {
			plan.Retained = append(plan.Retained, RemovalRetention{
				Kind: "account", ID: account.ID,
				Reason: RemovalReasonPreexisting,
				Detail: account.UnixUser,
			})
			continue
		}
		matches, detail, err := accountIdentityMatches(ctx, account)
		if err != nil {
			return err
		}
		if !matches {
			plan.Retained = append(plan.Retained, RemovalRetention{
				Kind: "account", ID: account.ID,
				Reason: RemovalReasonChanged,
				Detail: detail,
			})
			plan.Warnings = append(plan.Warnings, fmt.Sprintf("managed account %q changed since apply; retaining it (%s)", account.UnixUser, detail))
			continue
		}
		plan.Actions = append(plan.Actions, RemovalAction{
			Kind: RemovalActionRemoveAccount, ID: account.UnixUser,
			Detail: account.Home, Destructive: true,
		})
	}
	return nil
}

func planReceiptRuntime(plan *RemovalPlan, receipt Receipt) {
	if receipt.RuntimeBundleID == "" {
		return
	}
	plan.Actions = append(plan.Actions, RemovalAction{
		Kind: RemovalActionRemoveRuntime, ID: receipt.RuntimeBundleID,
	})
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
	report := RemovalReport{
		APIVersion: RemovalAPIVersion, InstallationName: receipt.InstallationName,
		InstallationDigest: receipt.InstallationDigest, DeploymentDigest: receipt.DeploymentDigest,
		Retained: plan.Retained, RemoveState: plan.RemoveState,
	}
	for _, action := range plan.Actions {
		if err := engine.executeRemovalAction(ctx, action); err != nil {
			return RemovalReport{}, fmt.Errorf("remove %s %q: %w", action.Kind, action.ID, err)
		}
		report.RemovedActions = append(report.RemovedActions, action)
	}
	return report, nil
}

//nolint:cyclop // Removal execution dispatches over one closed action enumeration.
func (engine *Engine) executeRemovalAction(ctx context.Context, action RemovalAction) error {
	switch action.Kind {
	case RemovalActionDisableService:
		manager := engine.options.Manager
		if err := manager.Stop(ctx, action.ID); err != nil {
			return err
		}
		return manager.Disable(ctx, action.ID)
	case RemovalActionRemoveAccount:
		return removeManagedAccount(ctx, action.ID, action.Detail)
	case RemovalActionRemoveRuntime:
		return engine.installer().Rollback(ctx)
	case RemovalActionDeleteReceipt:
		return DeleteReceipt(engine.options.Paths.StateDir)
	case RemovalActionRemoveContainer:
		return errors.New("container removal is not yet supported")
	default:
		return fmt.Errorf("unknown removal action %q", action.Kind)
	}
}

// removeManagedAccount fails closed unless the account still matches the receipt.
func removeManagedAccount(ctx context.Context, name, home string) error {
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
	output, err := exec.CommandContext(ctx, "userdel", "--remove", name).CombinedOutput() // #nosec G204 -- validated managed account name from receipt.
	if err != nil {
		return fmt.Errorf("remove managed account %q: %w: %s", name, err, strings.TrimSpace(string(output)))
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
		if a.Kind != b.Kind {
			return strings.Compare(string(a.Kind), string(b.Kind))
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
