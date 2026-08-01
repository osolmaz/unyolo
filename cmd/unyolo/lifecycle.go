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
	"slices"

	"github.com/osolmaz/unyolo/deployment/flow"
	"github.com/osolmaz/unyolo/deployment/session"
	"github.com/osolmaz/unyolo/internal/buildinfo"
	unyolocli "github.com/osolmaz/unyolo/internal/cli"
	hostdeployment "github.com/osolmaz/unyolo/internal/host/deployment"
	"github.com/osolmaz/unyolo/internal/host/privilege"
	terminalsetup "github.com/osolmaz/unyolo/internal/terminal/setup"
	setupcompiler "github.com/osolmaz/unyolo/setup/compiler"
	"github.com/osolmaz/unyolo/setup/installation"
	setupintent "github.com/osolmaz/unyolo/setup/intent"
	"github.com/osolmaz/unyolo/setup/wizard"
)

type sessionDiscardFlags struct {
	confirmed bool
	all       bool
}

func bindSessionDiscardFlags(output io.Writer) (*flag.FlagSet, *sessionDiscardFlags) {
	flags := flag.NewFlagSet("unyolo session discard", flag.ContinueOnError)
	flags.SetOutput(output)
	values := &sessionDiscardFlags{}
	flags.BoolVar(&values.confirmed, "confirm", false, "confirm local session removal")
	flags.BoolVar(&values.all, "all", false, "discard every incomplete local session")
	return flags, values
}

func newSessionDiscardFlagSet(output io.Writer) *flag.FlagSet {
	flags, _ := bindSessionDiscardFlags(output)
	return flags
}

// runSetupDiscard removes one uncommitted local setup session by ID.
func runSetupDiscard(args []string, stdout, stderr io.Writer) error {
	flags, values := bindSessionDiscardFlags(stderr)
	if err := unyolocli.Parse(flags, args); err != nil {
		return err
	}
	if !values.confirmed {
		return unyolocli.Usage(errors.New("--confirm is required"))
	}
	store, err := setupSessionStore()
	if err != nil {
		return err
	}
	if values.all {
		if flags.NArg() != 0 {
			return unyolocli.Usage(errors.New("--all does not accept a session ID"))
		}
		return discardAllIncompleteSessions(store, stdout)
	}
	if flags.NArg() != 1 {
		return unyolocli.Usage(errors.New("provide one session ID or use --all"))
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

type lifecycleCLIFlags struct {
	accessible     bool
	noOpen         bool
	bootstrapStage string
}

func bindLifecycleFlags(name string, output io.Writer) (*flag.FlagSet, *lifecycleCLIFlags) {
	flags := flag.NewFlagSet("unyolo "+name, flag.ContinueOnError)
	flags.SetOutput(output)
	values := &lifecycleCLIFlags{}
	flags.BoolVar(&values.accessible, "accessible", false, "use screen-reader-friendly prompts")
	flags.BoolVar(&values.noOpen, "no-open", false, "print browser URLs instead of opening them")
	flags.StringVar(&values.bootstrapStage, "bootstrap-stage", "", "activate verified bootstrap stage `DIR` before administrator planning")
	return flags, values
}

func newRepairFlagSet(output io.Writer) *flag.FlagSet {
	flags, _ := bindLifecycleFlags("repair", output)
	return flags
}

func newReconfigureFlagSet(output io.Writer) *flag.FlagSet {
	flags, _ := bindLifecycleFlags("reconfigure", output)
	return flags
}

// runSetupRepair replans and reapplies the recorded installation without changes.
func runSetupRepair(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	return runLifecycleCommand(ctx, "repair", args, stdout, stderr)
}

// runSetupReconfigure loads the current installation, applies staged edits and re-runs the transaction.
func runSetupReconfigure(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	return runLifecycleCommand(ctx, "reconfigure", args, stdout, stderr)
}

func runLifecycleCommand(ctx context.Context, action string, args []string, stdout, stderr io.Writer) error {
	flags, values := bindLifecycleFlags(action, stderr)
	if err := unyolocli.Parse(flags, args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return unyolocli.Usage(fmt.Errorf("%s does not accept positional arguments", action))
	}
	return runReconfigureOrRepair(ctx, stdout, stderr, action, values.accessible, values.noOpen, values.bootstrapStage)
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
	options.Capabilities, err = releaseSetupCapabilities(options.DeploymentKits)
	if err != nil {
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
	if action == "reconfigure" {
		desired, err = editInstallation(ctx, prompter, desired, options)
		if err != nil {
			return err
		}
	} else {
		confirmed, confirmErr := prompter.Confirm(ctx, flow.ConfirmPrompt{
			Message:     confirmMessageFor(action),
			Description: "This recompiles and reapplies the saved installation without changing its choices.",
			Affirmative: confirmActionFor(action),
			Negative:    "Cancel",
			Safe:        true,
		})
		if confirmErr != nil || !confirmed {
			if confirmErr != nil {
				return confirmErr
			}
			return flow.CancelledError{}
		}
	}
	return applyReconfiguration(ctx, prompter, store, desired, options)
}

func editInstallation(ctx context.Context, prompter flow.SetupPrompter, desired installation.Installation, options setupOptions) (installation.Installation, error) {
	for {
		actions := []flow.Option{
			{Value: "done", Label: "Review and apply"},
			{Value: "providers", Label: "Change credential services"},
			{Value: "add-approver", Label: "Add an approver"},
			{Value: "add-connection", Label: "Add an agent connection"},
		}
		if len(desired.Approvers) > 1 {
			actions = append(actions, flow.Option{Value: "remove-approver", Label: "Remove an approver"})
		}
		if len(desired.Connections) > 0 {
			actions = append(actions,
				flow.Option{Value: "change-connection", Label: "Change an agent connection"},
				flow.Option{Value: "remove-connection", Label: "Remove an agent connection"})
		}
		action, err := prompter.Select(ctx, flow.SelectPrompt{
			Message: "What would you like to change?", Description: installationSummary(desired),
			Options: actions, InitialValue: "done",
		})
		if err != nil {
			return installation.Installation{}, err
		}
		switch action {
		case "done":
			return desired, desired.Validate()
		case "providers":
			selected, err := editProviders(ctx, prompter, desired, options)
			if err != nil {
				if isBackNavigation(err) {
					continue
				}
				return installation.Installation{}, err
			}
			desired.CredentialService.Providers = selected
			for index := range desired.Connections {
				desired.Connections[index].Providers = append([]string(nil), selected...)
			}
		case "add-approver":
			account, err := prompter.Text(ctx, flow.Prompt{Message: "Which local account can approve requests?", Required: true, Navigation: flow.Navigation{CanGoBack: true}})
			if err != nil {
				if isBackNavigation(err) {
					continue
				}
				return installation.Installation{}, err
			}
			if slices.ContainsFunc(desired.Approvers, func(value installation.Approver) bool { return value.Account == account }) {
				return installation.Installation{}, errors.New("that approver already exists")
			}
			desired.Approvers = append(desired.Approvers, installation.Approver{ID: account, Account: account})
		case "remove-approver":
			id, err := selectApprover(ctx, prompter, desired.Approvers)
			if err != nil {
				if isBackNavigation(err) {
					continue
				}
				return installation.Installation{}, err
			}
			desired.Approvers = slices.DeleteFunc(desired.Approvers, func(value installation.Approver) bool { return value.ID == id })
		case "add-connection":
			connection, err := editOneConnection(ctx, prompter, nil, desired, options)
			if err != nil {
				if isBackNavigation(err) {
					continue
				}
				return installation.Installation{}, err
			}
			if slices.ContainsFunc(desired.Connections, func(value installation.Connection) bool {
				return value.ID == connection.ID || value.ClientID == connection.ClientID
			}) {
				return installation.Installation{}, errors.New("that connection already exists")
			}
			desired.Connections = append(desired.Connections, connection)
		case "change-connection", "remove-connection":
			id, err := selectConnection(ctx, prompter, desired.Connections, "Which connection?")
			if err != nil {
				if isBackNavigation(err) {
					continue
				}
				return installation.Installation{}, err
			}
			index := slices.IndexFunc(desired.Connections, func(value installation.Connection) bool { return value.ID == id })
			if action == "remove-connection" {
				desired.Connections = slices.Delete(desired.Connections, index, index+1)
				continue
			}
			connection, err := editOneConnection(ctx, prompter, &desired.Connections[index], desired, options)
			if err != nil {
				if isBackNavigation(err) {
					continue
				}
				return installation.Installation{}, err
			}
			desired.Connections[index] = connection
		}
		if err := desired.Validate(); err != nil {
			return installation.Installation{}, err
		}
	}
}

func installationSummary(value installation.Installation) string {
	return fmt.Sprintf("Credential services: %s · Approvers: %d · Connections: %d", joinProviders(value), len(value.Approvers), len(value.Connections))
}

func isBackNavigation(err error) bool {
	var navigation flow.NavigationError
	return errors.As(err, &navigation) && navigation.Direction == "back"
}

func editProviders(ctx context.Context, prompter flow.SetupPrompter, desired installation.Installation, options setupOptions) ([]string, error) {
	choices := providerChoicesFromOptions(options.ProviderOptions)
	seen := map[string]bool{}
	providerOptions := make([]flow.Option, 0, len(choices)+len(desired.CredentialService.Providers))
	for _, choice := range choices {
		providerOptions = append(providerOptions, flow.Option{Value: choice.Value, Label: choice.Label, Hint: choice.Hint})
		seen[choice.Value] = true
	}
	for _, providerID := range desired.CredentialService.Providers {
		if !seen[providerID] {
			providerOptions = append(providerOptions, flow.Option{Value: providerID, Label: providerID})
		}
	}
	return prompter.MultiSelect(ctx, flow.SelectPrompt{
		Message: "Which credential services should run?", Options: providerOptions,
		InitialValues: append([]string(nil), desired.CredentialService.Providers...), Required: true,
		Navigation: flow.Navigation{CanGoBack: true},
	})
}

func selectApprover(ctx context.Context, prompter flow.SetupPrompter, values []installation.Approver) (string, error) {
	options := make([]flow.Option, 0, len(values))
	for _, value := range values {
		options = append(options, flow.Option{Value: value.ID, Label: value.Account})
	}
	return prompter.Select(ctx, flow.SelectPrompt{Message: "Which approver should be removed?", Options: options, Navigation: flow.Navigation{CanGoBack: true}})
}

func selectConnection(ctx context.Context, prompter flow.SetupPrompter, values []installation.Connection, message string) (string, error) {
	options := make([]flow.Option, 0, len(values))
	for _, value := range values {
		options = append(options, flow.Option{Value: value.ID, Label: value.ID, Hint: value.Target.Account})
	}
	return prompter.Select(ctx, flow.SelectPrompt{Message: message, Options: options, Navigation: flow.Navigation{CanGoBack: true}})
}

func editOneConnection(ctx context.Context, prompter flow.SetupPrompter, existing *installation.Connection, desired installation.Installation, options setupOptions) (installation.Connection, error) {
	initial := setupintent.Intent{APIVersion: setupintent.APIVersion, Goal: setupintent.GoalAgentConnection}
	if existing != nil {
		initial.Integrations = append([]string(nil), existing.Integrations...)
		if existing.Target.Kind != installation.TargetLocalAccount {
			return installation.Connection{}, errors.New("this release cannot interactively change that connection target")
		}
		initial.Agent = &setupintent.Agent{Location: setupintent.AgentLocalAccount, ConnectionName: existing.ID,
			Account: &setupintent.Account{Mode: existing.Target.AccountMode, Name: existing.Target.Account}}
		initial.Connection = &setupintent.Connection{Transport: setupintent.TransportLocalSocket}
	}
	result, err := wizard.New(wizard.Options{
		Prompter: prompter, Capabilities: options.Capabilities, Accounts: existingAccountLister{},
		Initial: wizard.State{Intent: initial}, InitialStep: wizard.StepAgentLocation, CurrentAccount: options.Operator,
	}).Run(ctx)
	if err != nil {
		return installation.Connection{}, err
	}
	if result.Intent.Goal != setupintent.GoalAgentConnection {
		return installation.Connection{}, errors.New("connection editing cannot change the installation goal")
	}
	combined := result.Intent
	combined.Goal = setupintent.GoalCompleteLocal
	combined.CredentialService = &setupintent.CredentialService{Location: desired.CredentialService.Location,
		Providers: append([]string(nil), desired.CredentialService.Providers...)}
	generated, err := installationFromIntent(combined, options.Operator, desired.Name)
	if err != nil {
		return installation.Connection{}, err
	}
	if len(generated.Connections) != 1 {
		return installation.Connection{}, errors.New("connection editor did not produce one connection")
	}
	return generated.Connections[0], nil
}

func intentFromInstallation(value installation.Installation) (setupintent.Intent, error) {
	result := setupintent.Intent{
		APIVersion: setupintent.APIVersion, Goal: setupintent.GoalCredentialService,
		CredentialService: &setupintent.CredentialService{Location: value.CredentialService.Location, Providers: append([]string(nil), value.CredentialService.Providers...)},
	}
	if len(value.Connections) == 0 {
		return result, nil
	}
	if len(value.Connections) != 1 {
		return setupintent.Intent{}, errors.New("interactive reconfiguration currently requires exactly one recorded connection")
	}
	connection := value.Connections[0]
	result.Goal = setupintent.GoalCompleteLocal
	result.Integrations = append([]string(nil), connection.Integrations...)
	switch connection.Target.Kind {
	case installation.TargetLocalAccount:
		result.Agent = &setupintent.Agent{
			Location: setupintent.AgentLocalAccount, ConnectionName: connection.ID,
			Account: &setupintent.Account{Mode: connection.Target.AccountMode, Name: connection.Target.Account},
		}
		result.Connection = &setupintent.Connection{Transport: setupintent.TransportLocalSocket}
	case installation.TargetContainer:
		result.Agent = &setupintent.Agent{Location: setupintent.AgentContainer, ConnectionName: connection.ID}
	case installation.TargetRemote:
		result.Agent = &setupintent.Agent{Location: setupintent.AgentRemote, ConnectionName: connection.ID}
	default:
		return setupintent.Intent{}, errors.New("recorded connection target is invalid")
	}
	return result, nil
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
	metadata, err := compiledRenderMetadata(compiled)
	if err != nil {
		return err
	}
	if err := showProviderReview(ctx, prompter, metadata); err != nil {
		return err
	}
	if err := prompter.Note(ctx, fmt.Sprintf("Configuration digest: %s", compiled.Digest), "Prepared configuration"); err != nil {
		return err
	}
	if options.PlanOnly {
		return store.Publish(desired, destination, func(string) error { return nil })
	}
	worker, err := prepareProtectedWorker(ctx, prompter, nil, options.SourceCommit, options.GitHubCLI, startSetupWorker)
	if err != nil {
		return err
	}
	defer func() { _ = worker.Close() }()
	return store.Publish(desired, destination, func(generated string) error {
		return planAndApplyInstallation(ctx, prompter, worker, filepath.Join(filepath.Dir(generated), installation.EntryFilename), generated, session.Store{}, nil, secretPromptIndex(metadata))
	})
}

type removeCLIFlags struct {
	lifecycleCLIFlags
	removeState bool
}

func bindRemoveFlags(output io.Writer) (*flag.FlagSet, *removeCLIFlags) {
	flags := flag.NewFlagSet("unyolo remove", flag.ContinueOnError)
	flags.SetOutput(output)
	values := &removeCLIFlags{}
	flags.BoolVar(&values.accessible, "accessible", false, "use screen-reader-friendly prompts")
	flags.BoolVar(&values.noOpen, "no-open", false, "print browser URLs instead of opening them")
	flags.StringVar(&values.bootstrapStage, "bootstrap-stage", "", "activate verified bootstrap stage `DIR` before removal")
	flags.BoolVar(&values.removeState, "remove-state", false, "also remove installation-owned credentials and data")
	return flags, values
}

func newRemoveFlagSet(output io.Writer) *flag.FlagSet {
	flags, _ := bindRemoveFlags(output)
	return flags
}

// runSetupRemove reads the ownership receipt and prompts for safe uninstall.
//
//nolint:cyclop // Removal orchestrates release resolution, worker start, review, and safe cleanup.
func runSetupRemove(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	flags, values := bindRemoveFlags(stderr)
	if err := unyolocli.Parse(flags, args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return unyolocli.Usage(errors.New("remove does not accept positional arguments"))
	}
	if os.Geteuid() == 0 {
		return errors.New("interactive removal must run as a normal account, not root")
	}
	if !values.accessible && !hasInteractiveTTY() {
		return errors.New("remove requires an interactive TTY; use --accessible for line prompts")
	}
	current, err := user.Current()
	if err != nil || current.Username == "" || current.HomeDir == "" {
		return errors.New("resolve the current account")
	}
	options := setupOptions{Operator: current.Username, OperatorHome: current.HomeDir, SourceCommit: buildinfo.SourceCommit}
	if err := configureSetupRelease(values.bootstrapStage, &options); err != nil {
		return err
	}
	if err := validateGitHubCLI(options.GitHubCLI); err != nil {
		return err
	}
	prompter := terminalsetup.New(terminalsetup.Options{Input: os.Stdin, Output: stdout, Accessible: values.accessible, NoOpen: values.noOpen})
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
	response, err := worker.PlanRemoval(values.removeState)
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
		Message: firstRemovalConfirmation(), Description: "This removes unchanged service configuration, generated connections, and managed agent accounts created by unYOLO. Provider credentials and broker data are kept.",
		Affirmative: "Remove unYOLO resources", Negative: "Cancel", Safe: true,
	})
	if err != nil || !confirmed {
		_ = worker.Cancel()
		if err != nil {
			return err
		}
		return flow.CancelledError{}
	}
	if values.removeState {
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
	if removalFinished(result) {
		root, rootErr := installation.DefaultRoot()
		if rootErr != nil {
			return rootErr
		}
		if err := (installation.Store{Root: root}).Discard(result.RemovalReport.InstallationName); err != nil {
			return err
		}
	}
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
	return "Remove services, connections, and managed accounts?"
}

func confirmDestructiveDataRemoval(ctx context.Context, prompter flow.SetupPrompter, plan hostdeployment.RemovalPlan) error {
	message := "This second confirmation also removes installation-owned credentials, client connections, and broker data.\n" +
		"Changed, preexisting, and ambiguous paths are still retained."
	if err := prompter.Note(ctx, message, "Destructive removal"); err != nil {
		return err
	}
	confirmed, err := prompter.Confirm(ctx, flow.ConfirmPrompt{
		Message: "Also remove credentials and data?", Description: "Only unchanged resources recorded as created by this installation are deleted.",
		Affirmative: "Remove credentials and data", Negative: "Keep credentials and data", Safe: false,
	})
	if err != nil || !confirmed {
		if err != nil {
			return err
		}
		return flow.CancelledError{}
	}
	return nil
}

func removalFinished(result privilege.Result) bool {
	if result.RemovalReport == nil {
		return false
	}
	for _, action := range result.RemovalReport.RemovedActions {
		if action.Kind == hostdeployment.RemovalActionDeleteReceipt {
			return true
		}
	}
	return false
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
