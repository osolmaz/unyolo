package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"

	"github.com/osolmaz/unyolo/deployment/flow"
	"github.com/osolmaz/unyolo/deployment/session"
	"github.com/osolmaz/unyolo/internal/buildinfo"
	hostdeployment "github.com/osolmaz/unyolo/internal/host/deployment"
	"github.com/osolmaz/unyolo/internal/host/privilege"
	terminalsetup "github.com/osolmaz/unyolo/internal/terminal/setup"
	setupcompiler "github.com/osolmaz/unyolo/setup/compiler"
	"github.com/osolmaz/unyolo/setup/installation"
)

// runSetupDiscard removes one uncommitted local setup session by ID.
func runSetupDiscard(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("unyolo setup discard", flag.ContinueOnError)
	flags.SetOutput(stderr)
	confirmed := flags.Bool("confirm", false, "confirm local session removal")
	all := flags.Bool("all", false, "discard every incomplete local session")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if !*confirmed {
		return errors.New("usage: unyolo setup discard --confirm [--all | <session-id>]")
	}
	store, err := setupSessionStore()
	if err != nil {
		return err
	}
	if *all {
		return discardAllIncompleteSessions(store, stdout)
	}
	if flags.NArg() != 1 {
		return errors.New("usage: unyolo setup discard --confirm <session-id>")
	}
	if err := store.Cancel(flags.Arg(0)); err != nil {
		return err
	}
	_, err = fmt.Fprintln(stdout, "Discarded the setup session")
	return err
}

func discardAllIncompleteSessions(store session.Store, stdout io.Writer) error {
	values, err := store.List()
	if err != nil {
		return err
	}
	removed := 0
	for _, value := range values {
		if value.Phase == session.PhaseComplete || value.Phase == session.PhaseApplying {
			continue
		}
		if err := store.Cancel(value.ID); err != nil {
			return err
		}
		removed++
	}
	_, err = fmt.Fprintf(stdout, "Discarded %d incomplete setup sessions\n", removed)
	return err
}

// runSetupRepair replans and reapplies the recorded installation without changes.
func runSetupRepair(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("unyolo setup repair", flag.ContinueOnError)
	flags.SetOutput(stderr)
	accessible := flags.Bool("accessible", false, "use screen-reader-friendly prompts")
	noOpen := flags.Bool("no-open", false, "print browser URLs instead of opening them")
	bootstrapStage := flags.String("bootstrap-stage", "", "activate one verified bootstrap stage before administrator planning")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("setup repair does not accept positional arguments")
	}
	return runReconfigureOrRepair(ctx, stdout, stderr, "repair", *accessible, *noOpen, *bootstrapStage)
}

// runSetupReconfigure loads the current installation, applies staged edits and re-runs the transaction.
func runSetupReconfigure(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("unyolo setup reconfigure", flag.ContinueOnError)
	flags.SetOutput(stderr)
	accessible := flags.Bool("accessible", false, "use screen-reader-friendly prompts")
	noOpen := flags.Bool("no-open", false, "print browser URLs instead of opening them")
	bootstrapStage := flags.String("bootstrap-stage", "", "activate one verified bootstrap stage before administrator planning")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("setup reconfigure does not accept positional arguments")
	}
	return runReconfigureOrRepair(ctx, stdout, stderr, "reconfigure", *accessible, *noOpen, *bootstrapStage)
}

//nolint:cyclop // Lifecycle dispatch owns release resolution, session store, worker start, and cancellation.
func runReconfigureOrRepair(ctx context.Context, stdout, stderr io.Writer, action string, accessible, noOpen bool, bootstrapStage string) error {
	if os.Geteuid() == 0 {
		return errors.New("interactive lifecycle commands must run as a normal account, not root")
	}
	if !accessible && !hasInteractiveTTY() {
		return fmt.Errorf("%s requires an interactive TTY; use --accessible for line prompts", action)
	}
	current, err := user.Current()
	if err != nil || current.Username == "" || current.HomeDir == "" {
		return errors.New("resolve the current account")
	}
	options := setupOptions{Operator: current.Username, OperatorHome: current.HomeDir, SourceCommit: buildinfo.SourceCommit}
	if err := configureSetupRelease(bootstrapStage, &options); err != nil {
		return err
	}
	if err := validateGitHubCLI(options.GitHubCLI); err != nil {
		return err
	}
	installRoot, err := installation.DefaultRoot()
	if err != nil {
		return err
	}
	store := installation.Store{Root: installRoot}
	if err := store.Recover(); err != nil {
		return fmt.Errorf("recover the previous installation transaction: %w", err)
	}
	desired, err := store.Load(installation.DefaultName)
	if err != nil {
		return fmt.Errorf("load the recorded installation: %w", err)
	}
	prompter := terminalsetup.New(terminalsetup.Options{Input: os.Stdin, Output: stdout, Accessible: accessible, NoOpen: noOpen})
	defer func() { _ = prompter.Close() }()
	if err := prompter.Intro(ctx, "unYOLO "+action); err != nil {
		return err
	}
	message := fmt.Sprintf("Recorded installation: %s\nCredential services: %s", desired.Name, joinProviders(desired))
	if len(desired.Connections) > 0 {
		message += fmt.Sprintf("\nConnections: %d", len(desired.Connections))
	}
	if err := prompter.Note(ctx, message, "Current installation"); err != nil {
		return err
	}
	confirmed, err := prompter.Confirm(ctx, flow.ConfirmPrompt{
		Message:     confirmMessageFor(action),
		Description: "This will recompile, replan, and reapply the same installation record.",
		Affirmative: confirmActionFor(action),
		Negative:    "Cancel",
		Safe:        true,
	})
	if err != nil || !confirmed {
		if err != nil {
			return err
		}
		return flow.CancelledError{}
	}
	return applyReconfiguration(ctx, prompter, store, desired, options)
}

func applyReconfiguration(ctx context.Context, prompter flow.SetupPrompter, store installation.Store, desired installation.Installation, options setupOptions) error {
	sourceSet, err := selectedReleaseSourceSet(options, desired.CredentialService.Providers)
	if err != nil {
		return err
	}
	installRoot, err := installation.DefaultRoot()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(installRoot, 0o700); err != nil {
		return err
	}
	destination := filepath.Join(installRoot, ".compiled-lifecycle")
	_ = os.RemoveAll(destination)
	compiled, err := setupcompiler.Compile(setupcompiler.Options{
		Installation: desired, SourceSet: sourceSet, Destination: destination,
	})
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(destination) }()
	if err := prompter.Note(ctx, fmt.Sprintf("Configuration digest: %s", compiled.Digest), "Prepared configuration"); err != nil {
		return err
	}
	worker, err := prepareProtectedWorker(ctx, prompter, nil, options.SourceCommit, options.GitHubCLI, startSetupWorker)
	if err != nil {
		return err
	}
	defer func() { _ = worker.Close() }()
	return store.Publish(desired, destination, func(generated string) error {
		return planAndApplyInstallation(ctx, prompter, worker, filepath.Join(filepath.Dir(generated), installation.EntryFilename), generated, session.Store{}, nil)
	})
}

// runSetupRemove reads the ownership receipt and prompts for safe uninstall.
//
//nolint:cyclop // Removal orchestrates release resolution, worker start, review, and safe cleanup.
func runSetupRemove(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("unyolo setup remove", flag.ContinueOnError)
	flags.SetOutput(stderr)
	accessible := flags.Bool("accessible", false, "use screen-reader-friendly prompts")
	noOpen := flags.Bool("no-open", false, "print browser URLs instead of opening them")
	bootstrapStage := flags.String("bootstrap-stage", "", "activate one verified bootstrap stage before removal")
	removeState := flags.Bool("remove-state", false, "also remove recorded installation state after uninstall")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("setup remove does not accept positional arguments")
	}
	if os.Geteuid() == 0 {
		return errors.New("interactive removal must run as a normal account, not root")
	}
	if !*accessible && !hasInteractiveTTY() {
		return errors.New("setup remove requires an interactive TTY; use --accessible for line prompts")
	}
	current, err := user.Current()
	if err != nil || current.Username == "" || current.HomeDir == "" {
		return errors.New("resolve the current account")
	}
	options := setupOptions{Operator: current.Username, OperatorHome: current.HomeDir, SourceCommit: buildinfo.SourceCommit}
	if err := configureSetupRelease(*bootstrapStage, &options); err != nil {
		return err
	}
	if err := validateGitHubCLI(options.GitHubCLI); err != nil {
		return err
	}
	prompter := terminalsetup.New(terminalsetup.Options{Input: os.Stdin, Output: stdout, Accessible: *accessible, NoOpen: *noOpen})
	defer func() { _ = prompter.Close() }()
	if err := prompter.Intro(ctx, "Remove unYOLO"); err != nil {
		return err
	}
	worker, err := prepareProtectedWorker(ctx, prompter, nil, options.SourceCommit, options.GitHubCLI, startSetupWorker)
	if err != nil {
		return err
	}
	defer func() { _ = worker.Close() }()
	progress := prompter.Progress("Preparing the removal plan")
	response, err := worker.PlanRemoval(*removeState)
	if err != nil {
		progress.Fail("Could not prepare the removal plan")
		return err
	}
	progress.Stop("Removal plan is ready to review")
	filtered := hostdeployment.FilterRemovalPlan(response.RemovalPlan)
	if err := showRemovalReview(ctx, prompter, filtered); err != nil {
		_ = worker.Cancel()
		return err
	}
	confirmed, err := prompter.Confirm(ctx, flow.ConfirmPrompt{
		Message: firstRemovalConfirmation(), Description: "This removes services, disables units, and cleans up managed accounts. Provider credentials and broker state are kept.",
		Affirmative: "Remove services", Negative: "Cancel", Safe: true,
	})
	if err != nil || !confirmed {
		_ = worker.Cancel()
		if err != nil {
			return err
		}
		return flow.CancelledError{}
	}
	if *removeState {
		if err := confirmDestructiveDataRemoval(ctx, prompter, filtered); err != nil {
			_ = worker.Cancel()
			return err
		}
	}
	applyProgress := prompter.Progress("Applying the removal plan")
	result, err := worker.ApplyRemoval()
	if err != nil {
		applyProgress.Fail("Removal failed and no cleanup was recorded")
		return err
	}
	applyProgress.Stop(result.Message)
	if err := writeRemovalReport(stdout, result); err != nil {
		return err
	}
	return prompter.Outro(ctx, "unYOLO has been removed. The unYOLO command remains installed until you also remove it.")
}

func showRemovalReview(ctx context.Context, prompter flow.SetupPrompter, plan hostdeployment.RemovalPlan) error {
	summary := hostdeployment.RemovalPlanSummary(plan)
	if err := prompter.Note(ctx, summary, "Removal summary"); err != nil {
		return err
	}
	if len(plan.Retained) > 0 {
		details := "Retained by design:\n"
		for _, retention := range plan.Retained {
			details += fmt.Sprintf("- %s %s (%s)\n", retention.Kind, retention.ID, retention.Reason)
		}
		if err := prompter.Note(ctx, details, "Retained resources"); err != nil {
			return err
		}
	}
	if len(plan.Warnings) > 0 {
		warn := ""
		for _, warning := range plan.Warnings {
			warn += "- " + warning + "\n"
		}
		if err := prompter.Note(ctx, warn, "Warnings"); err != nil {
			return err
		}
	}
	return nil
}

func firstRemovalConfirmation() string {
	return "Remove services and managed accounts?"
}

func confirmDestructiveDataRemoval(ctx context.Context, prompter flow.SetupPrompter, plan hostdeployment.RemovalPlan) error {
	message := "This second confirmation also removes the recorded installation state.\n" +
		"Provider credentials and broker state are removed only when their paths appear in the receipt."
	if err := prompter.Note(ctx, message, "Destructive removal"); err != nil {
		return err
	}
	confirmed, err := prompter.Confirm(ctx, flow.ConfirmPrompt{
		Message: "Also remove recorded state?", Description: "This deletes the ownership receipt after uninstall.",
		Affirmative: "Remove state", Negative: "Keep state", Safe: false,
	})
	if err != nil || !confirmed {
		if err != nil {
			return err
		}
		return flow.CancelledError{}
	}
	return nil
}

func writeRemovalReport(stdout io.Writer, result privilege.Result) error {
	if result.RemovalReport == nil {
		return nil
	}
	data, err := json.MarshalIndent(result.RemovalReport, "", "  ")
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(stdout, string(data))
	return err
}

func joinProviders(desired installation.Installation) string {
	if len(desired.CredentialService.Providers) == 0 {
		return "none"
	}
	result := desired.CredentialService.Providers[0]
	for _, provider := range desired.CredentialService.Providers[1:] {
		result += ", " + provider
	}
	return result
}

func confirmMessageFor(action string) string {
	if action == "reconfigure" {
		return "Recompile and reapply the current installation?"
	}
	return "Repair the current installation?"
}

func confirmActionFor(action string) string {
	if action == "reconfigure" {
		return "Reconfigure"
	}
	return "Repair"
}
