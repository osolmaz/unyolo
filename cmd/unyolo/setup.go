package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/osolmaz/unyolo/deployment/flow"
	deploymentplan "github.com/osolmaz/unyolo/deployment/plan"
	"github.com/osolmaz/unyolo/deployment/profile"
	"github.com/osolmaz/unyolo/deployment/provider"
	"github.com/osolmaz/unyolo/deployment/session"
	"github.com/osolmaz/unyolo/internal/buildinfo"
	hostaccount "github.com/osolmaz/unyolo/internal/host/account"
	"github.com/osolmaz/unyolo/internal/host/privilege"
	terminalsetup "github.com/osolmaz/unyolo/internal/terminal/setup"
	"github.com/osolmaz/unyolo/internal/userinstall"
	"github.com/osolmaz/unyolo/setup/capability"
	setupcompiler "github.com/osolmaz/unyolo/setup/compiler"
	setupcopy "github.com/osolmaz/unyolo/setup/copy"
	"github.com/osolmaz/unyolo/setup/installation"
	setupintent "github.com/osolmaz/unyolo/setup/intent"
	"github.com/osolmaz/unyolo/setup/pairingclient"
	"github.com/osolmaz/unyolo/setup/wizard"
	"golang.org/x/term"
)

type protectedSetupWorker interface {
	Plan(string) (privilege.Response, error)
	PlanInstallation(string, string) (privilege.Response, error)
	Apply(string, map[string][]byte) (privilege.Result, error)
	Cancel() error
	Close() error
}

type setupWorkerStarter func(context.Context, string, string, string, io.Writer) (protectedSetupWorker, error)

var startSetupWorker setupWorkerStarter = func(ctx context.Context, release, sourceCommit, githubCLI string, stderr io.Writer) (protectedSetupWorker, error) {
	return privilege.Start(ctx, release, sourceCommit, githubCLI, stderr)
}

//nolint:cyclop // Setup dispatch owns terminal, release, session, and cancellation boundaries.
func runGuidedSetup(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	if len(args) > 0 {
		switch args[0] {
		case "status":
			return runSetupStatus(args[1:], stdout, stderr)
		case "cancel":
			return runSetupCancel(args[1:], stdout, stderr)
		}
	}
	flags := flag.NewFlagSet("unyolo setup", flag.ContinueOnError)
	flags.SetOutput(stderr)
	profilePath := flags.String("profile", "", "review or repair an advanced locked configuration")
	accessible := flags.Bool("accessible", false, "use screen-reader-friendly prompts")
	noOpen := flags.Bool("no-open", false, "print browser URLs instead of opening them")
	resumeID := flags.String("resume", "", "resume one setup session")
	newSession := flags.Bool("new", false, "start a new setup session")
	planOnly := flags.Bool("plan-only", false, "prepare configuration without administrator changes")
	bootstrapStage := flags.String("bootstrap-stage", "", "activate one verified bootstrap stage before administrator planning")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *resumeID != "" && *newSession {
		return errors.New("setup does not accept positional arguments and --resume conflicts with --new")
	}
	if os.Geteuid() == 0 {
		return errors.New("interactive setup must run as a normal account, not root")
	}
	if !*accessible && !hasInteractiveTTY() {
		return errors.New("setup requires an interactive TTY; use --accessible for line prompts")
	}
	current, err := user.Current()
	if err != nil || current.Username == "" || current.HomeDir == "" {
		return errors.New("resolve the current account")
	}
	options := setupOptions{
		Profile: *profilePath, ResumeID: *resumeID, New: *newSession, PlanOnly: *planOnly,
		Operator: current.Username, OperatorHome: current.HomeDir, SourceCommit: buildinfo.SourceCommit,
	}
	if err := configureSetupRelease(*bootstrapStage, &options); err != nil {
		return err
	}
	if err := validateGitHubCLI(options.GitHubCLI); err != nil {
		return err
	}
	if options.Profile == "" {
		options.Capabilities, err = releaseSetupCapabilities(options.DeploymentKits)
		if err != nil {
			return err
		}
	}
	prompter := terminalsetup.New(terminalsetup.Options{Input: os.Stdin, Output: stdout, Accessible: *accessible, NoOpen: *noOpen})
	defer func() { _ = prompter.Close() }()
	if options.Profile != "" {
		return runAdvancedSetup(ctx, prompter, options)
	}
	return runSetupFlow(ctx, prompter, options)
}

type setupOptions struct {
	Profile          string
	ResumeID         string
	New              bool
	PlanOnly         bool
	ProviderOptions  []provider.Option
	DeploymentKits   string
	RuntimeArtifacts string
	Operator         string
	OperatorHome     string
	GitHubCLI        string
	SourceCommit     string
	Capabilities     capability.Snapshot
	Activate         func(context.Context) error
}

func configureSetupRelease(stage string, options *setupOptions) error {
	if stage != "" {
		providers, err := provider.LoadDirectory(filepath.Join(stage, "share", "providers"))
		if err != nil {
			return err
		}
		options.ProviderOptions = providers
		options.DeploymentKits = filepath.Join(stage, "share", "deployment-kits")
		options.RuntimeArtifacts = filepath.Join(options.DeploymentKits, "artifacts")
		options.GitHubCLI = filepath.Join(stage, "libexec", "gh-attestation-verifier")
		options.Activate = func(ctx context.Context) error {
			return userinstall.Activate(ctx, userinstall.Options{StageRoot: stage})
		}
		return nil
	}
	if options.Profile == "" {
		providers, root, err := installedProviderOptions()
		if err != nil {
			return err
		}
		options.ProviderOptions = providers
		options.DeploymentKits = filepath.Join(root, "deployment-kits")
		options.RuntimeArtifacts = filepath.Join(options.DeploymentKits, "artifacts")
		options.GitHubCLI = filepath.Join(root, "gh-attestation-verifier")
		return nil
	}
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	resolved, err := filepath.EvalSymlinks(executable)
	if err != nil {
		return err
	}
	options.GitHubCLI = filepath.Join(filepath.Dir(resolved), "gh-attestation-verifier")
	return nil
}

func releaseSetupCapabilities(kits string) (capability.Snapshot, error) {
	empty := capability.Snapshot{APIVersion: capability.APIVersion, OperatingSystem: runtime.GOOS, Architecture: runtime.GOARCH}
	if kits == "" {
		return empty, nil
	}
	entries, err := os.ReadDir(filepath.Join(kits, "templates"))
	if err != nil {
		return capability.Snapshot{}, err
	}
	for _, entry := range entries {
		if !entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
			continue
		}
		snapshot, loadErr := profile.Load(filepath.Join(kits, "templates", entry.Name()))
		if loadErr != nil {
			return capability.Snapshot{}, loadErr
		}
		return capability.Resolve(snapshot.Manifest, capability.HostProbe{})
	}
	return capability.Snapshot{}, errors.New("verified release has no setup source")
}

//nolint:cyclop // The coordinator checkpoints each user decision and keeps secret collection after review.
func runSetupFlow(ctx context.Context, prompter flow.SetupPrompter, options setupOptions) error {
	if err := prompter.Intro(ctx, setupcopy.Title); err != nil {
		return err
	}
	if err := prompter.Note(ctx, setupcopy.Intro, "What this does"); err != nil {
		return err
	}
	store, err := setupSessionStore()
	if err != nil {
		return err
	}
	setupSession, err := chooseSession(ctx, prompter, store, options)
	if err != nil {
		return err
	}
	if setupSession.CapabilityDigest != "" && setupSession.CapabilityDigest != options.Capabilities.Digest {
		setupSession.Intent = setupintent.Intent{APIVersion: setupintent.APIVersion}
		setupSession.CompletedStep = nil
		setupSession.CurrentStep = "goal"
	}
	setupSession.CapabilityDigest = options.Capabilities.Digest
	if setupSession.Intent.Goal == "" {
		goal, selectErr := chooseGoal(ctx, prompter, options.Capabilities)
		if selectErr != nil {
			return selectErr
		}
		setupSession.Intent.Goal = setupintent.Goal(goal)
		if err := checkpoint(store, &setupSession, "goal"); err != nil {
			return err
		}
	}
	if setupSession.Intent.Goal == setupintent.GoalCommandOnly {
		return finishCommandOnly(ctx, prompter, store, &setupSession, options.Activate)
	}
	if setupSession.Intent.Goal == setupintent.GoalAgentConnection && setupSession.Intent.CredentialService == nil {
		return runClientOnly(ctx, prompter, store, &setupSession, options)
	}
	if err := collectServiceIntent(ctx, prompter, store, &setupSession, options); err != nil {
		return err
	}
	if setupSession.Intent.Goal == setupintent.GoalCompleteLocal {
		if err := collectAgentIntent(ctx, prompter, store, &setupSession, options); err != nil {
			return err
		}
	}
	if err := setupSession.Intent.Validate(); err != nil {
		return err
	}
	desired, err := installationFromIntent(setupSession.Intent, options.Operator)
	if err != nil {
		return err
	}
	return compileReviewAndApply(ctx, prompter, store, &setupSession, desired, options)
}

func chooseGoal(ctx context.Context, prompter flow.SetupPrompter, capabilities capability.Snapshot) (string, error) {
	choices := wizard.GoalChoices(capabilities)
	options := make([]flow.Option, 0, len(choices))
	for _, choice := range choices {
		options = append(options, flow.Option{Value: choice.Value, Label: choice.Label, Hint: choice.Hint})
	}
	if len(options) == 0 {
		return "", errors.New("this release has no completed setup path")
	}
	return prompter.Select(ctx, flow.SelectPrompt{Message: "What do you want to set up?", Options: options, InitialValue: options[0].Value})
}

func collectServiceIntent(ctx context.Context, prompter flow.SetupPrompter, store session.Store, setupSession *session.Session, options setupOptions) error {
	if setupSession.Intent.CredentialService != nil {
		return nil
	}
	if !options.Capabilities.Has(capability.FeatureNativeService) {
		return errors.New("this release cannot install credential services on this computer")
	}
	selected, err := chooseProviders(ctx, prompter, options.ProviderOptions)
	if err != nil {
		return err
	}
	setupSession.Intent.CredentialService = &setupintent.CredentialService{Location: setupintent.ServiceNative, Providers: selected}
	return checkpoint(store, setupSession, "providers")
}

func collectAgentIntent(ctx context.Context, prompter flow.SetupPrompter, store session.Store, setupSession *session.Session, options setupOptions) error {
	if setupSession.Intent.Agent != nil {
		return nil
	}
	choices := wizard.AgentLocationChoices(options.Capabilities)
	choices = slices.DeleteFunc(choices, func(choice wizard.Choice) bool { return choice.Value == "container" || choice.Value == "remote" })
	flowOptions := make([]flow.Option, 0, len(choices))
	for _, choice := range choices {
		flowOptions = append(flowOptions, flow.Option{Value: choice.Value, Label: choice.Label, Hint: choice.Hint})
	}
	if len(flowOptions) == 0 {
		return errors.New("this release cannot connect a local account")
	}
	mode, err := prompter.Select(ctx, flow.SelectPrompt{Message: "Which account will run the agent?", Options: flowOptions, InitialValue: flowOptions[0].Value})
	if err != nil {
		return err
	}
	record, err := chooseAccount(ctx, prompter, mode, options)
	if err != nil {
		return err
	}
	setupSession.Intent.Agent = &setupintent.Agent{Location: setupintent.AgentLocalAccount, ConnectionName: record.Name, Account: &setupintent.Account{Mode: setupintent.AccountMode(mode), Name: record.Name}}
	if mode == "current" {
		setupSession.Intent.Agent.Account.Name = ""
	}
	setupSession.Intent.Connection = &setupintent.Connection{Transport: setupintent.TransportLocalSocket}
	return checkpoint(store, setupSession, "account")
}

func chooseAccount(ctx context.Context, prompter flow.SetupPrompter, mode string, options setupOptions) (hostaccount.Record, error) {
	if mode == "current" {
		return inspectAccount(ctx, options.Operator)
	}
	backend := hostaccount.New(commandRunner{})
	if mode == "managed" {
		name := "unyolo-agent"
		home := "/var/lib/unyolo-agent"
		uid := 0
		if runtime.GOOS == "darwin" {
			home, uid = "/Users/Shared/unyolo-agent", 550
		}
		plan, err := backend.PlanCreate(name, home, uid)
		return plan.Record, err
	}
	accounts, err := backend.List(ctx)
	if err != nil {
		return hostaccount.Record{}, err
	}
	choices := make([]flow.Option, 0, len(accounts))
	for _, account := range accounts {
		choices = append(choices, flow.Option{Value: account.Name, Label: account.Name, Hint: account.Home})
	}
	name, err := prompter.Select(ctx, flow.SelectPrompt{Message: "Which existing account should be connected?", Options: choices, Searchable: true})
	if err != nil {
		return hostaccount.Record{}, err
	}
	return backend.Inspect(ctx, name)
}

func inspectAccount(ctx context.Context, name string) (hostaccount.Record, error) {
	return hostaccount.New(commandRunner{}).Inspect(ctx, name)
}

type commandRunner struct{}

func (commandRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).CombinedOutput() // #nosec G204 -- account backend assembles fixed commands.
}

func installationFromIntent(value setupintent.Intent, approver string) (installation.Installation, error) {
	result := installation.Installation{
		APIVersion: installation.APIVersion, Name: installation.DefaultName,
		CredentialService: *value.CredentialService, Approvers: []installation.Approver{{ID: approver, Account: approver}},
	}
	if value.Agent != nil {
		record, err := inspectAccount(context.Background(), agentAccountName(value.Agent, approver))
		if err != nil && value.Agent.Account.Mode != setupintent.AccountManaged {
			return installation.Installation{}, err
		}
		target := installation.Target{Kind: installation.TargetLocalAccount, Isolation: "separate", AccountMode: value.Agent.Account.Mode, Account: record.Name, Home: record.Home, Shell: record.Shell, UID: record.UID, GID: record.GID}
		if value.Agent.Account.Mode == setupintent.AccountManaged {
			plan, planErr := hostaccount.New(commandRunner{}).PlanCreate(value.Agent.ConnectionName, map[bool]string{true: "/Users/Shared/unyolo-agent", false: "/var/lib/unyolo-agent"}[runtime.GOOS == "darwin"], map[bool]int{true: 550, false: 0}[runtime.GOOS == "darwin"])
			if planErr != nil {
				return installation.Installation{}, planErr
			}
			target.Account, target.Home, target.Shell, target.UID, target.GID = plan.Record.Name, plan.Record.Home, plan.Record.Shell, plan.Record.UID, plan.Record.GID
		}
		if value.Agent.Account.Mode == setupintent.AccountCurrent {
			target.Isolation = "reduced"
		}
		result.Connections = []installation.Connection{{
			ID: value.Agent.ConnectionName, ClientID: value.Agent.ConnectionName, Target: target,
			Providers: append([]string(nil), value.CredentialService.Providers...), Integrations: append([]string(nil), value.Integrations...),
		}}
	}
	return result, result.Validate()
}

func agentAccountName(agent *setupintent.Agent, current string) string {
	if agent.Account.Mode == setupintent.AccountCurrent {
		return current
	}
	return agent.Account.Name
}

func compileReviewAndApply(ctx context.Context, prompter flow.SetupPrompter, sessions session.Store, setupSession *session.Session, desired installation.Installation, options setupOptions) error {
	templatePath, artifacts, err := selectedReleaseTemplate(options, desired.CredentialService.Providers)
	if err != nil {
		return err
	}
	template, err := profile.Load(templatePath)
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
	destination := filepath.Join(installRoot, fmt.Sprintf(".compiled-%d", time.Now().UnixNano()))
	compiled, err := setupcompiler.Compile(setupcompiler.Options{Installation: desired, Template: template, ArtifactRoot: artifacts, Destination: destination})
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(destination) }()
	if err := showInstallationReview(ctx, prompter, desired, compiled); err != nil {
		return err
	}
	installCLI, err := prompter.Confirm(ctx, flow.ConfirmPrompt{Message: "Install the unYOLO command?", Description: "This installs the verified command for your account.", Affirmative: "Install command", Negative: "Cancel", Safe: true})
	if err != nil || !installCLI {
		if err != nil {
			return err
		}
		return flow.CancelledError{}
	}
	if err := activateVerifiedCLI(ctx, prompter, options.Activate); err != nil {
		return err
	}
	if options.PlanOnly {
		return installation.Store{Root: installRoot}.Publish(desired, destination, func(string) error { return nil })
	}
	worker, err := prepareProtectedWorker(ctx, prompter, nil, options.SourceCommit, options.GitHubCLI, startSetupWorker)
	if err != nil {
		return err
	}
	defer func() { _ = worker.Close() }()
	setupSession.Phase = session.PhaseProfile
	if err := sessions.Save(*setupSession); err != nil {
		return err
	}
	return installation.Store{Root: installRoot}.Publish(desired, destination, func(generated string) error {
		return planAndApplyInstallation(ctx, prompter, worker, filepath.Join(filepath.Dir(generated), installation.EntryFilename), generated, sessions, setupSession)
	})
}

func showInstallationReview(ctx context.Context, prompter flow.SetupPrompter, desired installation.Installation, compiled profile.Snapshot) error {
	connections := "No agent will be connected yet."
	if len(desired.Connections) > 0 {
		parts := make([]string, 0, len(desired.Connections))
		for _, connection := range desired.Connections {
			parts = append(parts, connection.Target.Account+" will receive access to "+strings.Join(connection.Providers, ", "))
		}
		connections = strings.Join(parts, "\n")
	}
	message := fmt.Sprintf("Credential services: %s\nApprover account: %s\n%s", strings.Join(desired.CredentialService.Providers, ", "), desired.Approvers[0].Account, connections)
	if err := prompter.Note(ctx, message, "Review the changes"); err != nil {
		return err
	}
	showDetails, err := prompter.Confirm(ctx, flow.ConfirmPrompt{Message: "Show technical details?", Affirmative: "Show details", Negative: "Continue", Safe: true})
	if err != nil {
		return err
	}
	if showDetails {
		return prompter.Note(ctx, fmt.Sprintf("Configuration digest: %s\nRuntime: %s", compiled.Digest, compiled.Manifest.BundleID), "Technical details")
	}
	return nil
}

func planAndApplyInstallation(ctx context.Context, prompter flow.SetupPrompter, worker protectedSetupWorker, installationPath, generated string, sessions session.Store, setupSession *session.Session) error {
	progress := prompter.Progress("Checking the requested system changes")
	planned, err := worker.PlanInstallation(installationPath, generated)
	if err != nil {
		progress.Fail("Could not prepare the system changes")
		return err
	}
	progress.Stop("System changes are ready to review")
	setupSession.Phase = session.PhasePlanned
	if err := sessions.Save(*setupSession); err != nil {
		_ = worker.Cancel()
		return err
	}
	if err := prompter.Note(ctx, fmt.Sprintf("%d changes\nPlan digest: %s", len(planned.Plan.Actions), planned.PlanDigest), "System changes"); err != nil {
		_ = worker.Cancel()
		return err
	}
	confirmed, err := prompter.Confirm(ctx, flow.ConfirmPrompt{Message: "Allow these administrator changes?", Description: "The helper rejects changed system state or a changed plan.", Affirmative: "Apply system changes", Negative: "Cancel", Safe: true})
	if err != nil || !confirmed {
		_ = worker.Cancel()
		if err != nil {
			return err
		}
		return flow.CancelledError{}
	}
	secrets, err := collectPlanSecrets(ctx, prompter, planned.Plan)
	if err != nil {
		_ = worker.Cancel()
		return err
	}
	defer clearSetupSecrets(secrets)
	setupSession.SecretSlots = nil
	for slot := range secrets {
		setupSession.SecretSlots = append(setupSession.SecretSlots, session.SecretSlot{ID: slot})
	}
	setupSession.Phase = session.PhaseApplying
	if err := sessions.Save(*setupSession); err != nil {
		_ = worker.Cancel()
		return err
	}
	applyProgress := prompter.Progress("Applying and checking the system changes")
	result, err := worker.Apply(planned.PlanDigest, secrets)
	if err != nil {
		applyProgress.Fail("The system changes failed and were rolled back")
		return err
	}
	applyProgress.Stop(result.Message)
	setupSession.Phase, setupSession.SecretSlots = session.PhaseComplete, nil
	if err := sessions.Save(*setupSession); err != nil {
		return err
	}
	return prompter.Outro(ctx, "Setup is complete and the selected connection was verified.")
}

func collectPlanSecrets(ctx context.Context, prompter flow.SetupPrompter, plan deploymentplan.Plan) (map[string][]byte, error) {
	secrets := map[string][]byte{}
	for _, slot := range privilege.RequiredSecretSlots(plan) {
		value, err := collectPlanSecret(ctx, prompter, slot)
		if err != nil {
			clearSetupSecrets(secrets)
			return nil, err
		}
		secrets[slot] = value
	}
	return secrets, validateSetupSecretPairs(secrets)
}

func collectPlanSecret(ctx context.Context, prompter flow.SetupPrompter, slot string) ([]byte, error) {
	if strings.Contains(slot, "-client-") || strings.Contains(slot, "-approver-") {
		value := make([]byte, 32)
		if _, err := rand.Read(value); err != nil {
			return nil, err
		}
		encoded := []byte(base64.RawURLEncoding.EncodeToString(value))
		clear(value)
		return encoded, nil
	}
	if strings.Contains(slot, "github-app-private-key") {
		path, err := prompter.Text(ctx, flow.Prompt{Message: "Path to the GitHub App private key", Description: "unYOLO reads the selected PEM file once and sends it directly to the GitHub service.", Required: true})
		if err != nil {
			return nil, err
		}
		return readSetupCredentialFile(path)
	}
	if strings.Contains(slot, "github-app-id") {
		value, err := prompter.Text(ctx, flow.Prompt{Message: "GitHub App ID", Description: "Use the numeric App ID shown in the GitHub App settings.", Required: true})
		return []byte(value), err
	}
	return prompter.Secret(ctx, flow.Prompt{Message: friendlyCredentialLabel(slot), Description: "This is sent once to the selected credential service and is not saved in setup progress.", Required: true})
}

func readSetupCredentialFile(path string) ([]byte, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("credential file path must be absolute and clean")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() == 0 || info.Size() > 1024*1024 {
		return nil, errors.New("credential file must be a nonempty regular file without symbolic links")
	}
	data, err := os.ReadFile(path) // #nosec G304 -- explicit validated user-selected credential file.
	if err != nil {
		return nil, err
	}
	if !strings.Contains(string(data), "-----BEGIN") || !strings.Contains(string(data), "PRIVATE KEY-----") {
		clear(data)
		return nil, errors.New("GitHub App private key file is not PEM encoded")
	}
	return data, nil
}

func friendlyCredentialLabel(slot string) string {
	switch {
	case strings.Contains(slot, "github-app-id"):
		return "GitHub App ID"
	case strings.Contains(slot, "github-app-private-key"):
		return "GitHub App private key"
	case strings.Contains(slot, "github-webhook"):
		return "GitHub App webhook secret"
	case strings.Contains(slot, "github"):
		return "GitHub credential"
	case strings.Contains(slot, "huggingface"):
		return "Hugging Face token"
	default:
		return "Credential for " + slot
	}
}

func runClientOnly(ctx context.Context, prompter flow.SetupPrompter, store session.Store, setupSession *session.Session, options setupOptions) error {
	if !options.Capabilities.Has(capability.FeatureRemotePairing) {
		return errors.New("this release cannot connect to another computer")
	}
	invitation, err := prompter.Secret(ctx, flow.Prompt{Message: "Paste the pairing invitation", Description: "It expires after one use and identifies the server before sending credentials.", Required: true})
	if err != nil {
		return err
	}
	result, err := pairingclient.Claim(ctx, string(invitation), options.OperatorHome)
	clear(invitation)
	if err != nil {
		return err
	}
	if err := pairingclient.WaitForActive(ctx, result); err != nil {
		return err
	}
	if err := pairingclient.VerifyConnections(ctx, result); err != nil {
		return err
	}
	if err := pairingclient.MarkVerified(ctx, result); err != nil {
		return err
	}
	setupSession.Phase = session.PhaseComplete
	if err := store.Save(*setupSession); err != nil {
		return err
	}
	return prompter.Outro(ctx, "The agent connection is ready.")
}

func runAdvancedSetup(ctx context.Context, prompter flow.SetupPrompter, options setupOptions) error {
	if err := prompter.Intro(ctx, setupcopy.Title); err != nil {
		return err
	}
	snapshot, err := profile.Load(options.Profile)
	if err != nil {
		return err
	}
	if err := prompter.Note(ctx, fmt.Sprintf("Configuration: %s\nDigest: %s", snapshot.Deployment.Name, snapshot.Digest), "Advanced configuration"); err != nil {
		return err
	}
	if options.PlanOnly {
		return finishPlanOnly(ctx, prompter, options.Activate)
	}
	confirmed, err := prompter.Confirm(ctx, flow.ConfirmPrompt{Message: "Install the command and review administrator changes?", Affirmative: "Continue", Negative: "Cancel", Safe: true})
	if err != nil || !confirmed {
		if err != nil {
			return err
		}
		return flow.CancelledError{}
	}
	worker, err := prepareProtectedWorker(ctx, prompter, options.Activate, options.SourceCommit, options.GitHubCLI, startSetupWorker)
	if err != nil {
		return err
	}
	defer func() { _ = worker.Close() }()
	planned, err := worker.Plan(options.Profile)
	if err != nil {
		return err
	}
	apply, err := prompter.Confirm(ctx, flow.ConfirmPrompt{Message: "Apply these administrator changes?", Description: fmt.Sprintf("Plan digest: %s", planned.PlanDigest), Affirmative: "Apply system changes", Negative: "Cancel", Safe: true})
	if err != nil || !apply {
		_ = worker.Cancel()
		if err != nil {
			return err
		}
		return flow.CancelledError{}
	}
	secrets := map[string][]byte{}
	for _, slot := range privilege.RequiredSecretSlots(planned.Plan) {
		value, secretErr := prompter.Secret(ctx, flow.Prompt{Message: friendlyCredentialLabel(slot), Required: true})
		if secretErr != nil {
			_ = worker.Cancel()
			clearSetupSecrets(secrets)
			return secretErr
		}
		secrets[slot] = value
	}
	defer clearSetupSecrets(secrets)
	result, err := worker.Apply(planned.PlanDigest, secrets)
	if err != nil {
		return err
	}
	return prompter.Outro(ctx, result.Message)
}

func finishCommandOnly(ctx context.Context, prompter flow.SetupPrompter, store session.Store, setupSession *session.Session, activate func(context.Context) error) error {
	confirmed, err := prompter.Confirm(ctx, flow.ConfirmPrompt{Message: "Install the unYOLO command?", Description: "No administrator changes will be made.", Affirmative: "Install command", Negative: "Cancel", Safe: true})
	if err != nil || !confirmed {
		if err != nil {
			return err
		}
		return flow.CancelledError{}
	}
	if err := activateVerifiedCLI(ctx, prompter, activate); err != nil {
		return err
	}
	setupSession.Phase = session.PhaseComplete
	if err := store.Save(*setupSession); err != nil {
		return err
	}
	return prompter.Outro(ctx, "The unYOLO command is installed. No system services were changed.")
}

func chooseSession(ctx context.Context, prompter flow.SetupPrompter, store session.Store, options setupOptions) (session.Session, error) {
	build := buildinfo.Version
	if build == "" {
		build = version
	}
	if options.ResumeID != "" {
		return store.Load(options.ResumeID)
	}
	if !options.New {
		if existing, found, err := store.NewestIncomplete(build); err != nil {
			return session.Session{}, err
		} else if found {
			resume, confirmErr := prompter.Confirm(ctx, flow.ConfirmPrompt{Message: "Continue the unfinished setup?", Affirmative: "Continue", Negative: "Start over", Initial: true})
			if confirmErr != nil {
				return session.Session{}, confirmErr
			}
			if resume {
				return existing, nil
			}
		}
	}
	created, err := session.New(build, time.Now())
	if err != nil {
		return session.Session{}, err
	}
	created.CurrentStep = "goal"
	if err := store.Save(created); err != nil {
		return session.Session{}, err
	}
	return created, nil
}

func checkpoint(store session.Store, value *session.Session, step string) error {
	value.CompletedStep = appendUnique(value.CompletedStep, step)
	value.CurrentStep = step
	return store.Save(*value)
}

func chooseProviders(ctx context.Context, prompter flow.SetupPrompter, options []provider.Option) ([]string, error) {
	if len(options) == 0 {
		return nil, errors.New("verified release contains no credential services")
	}
	choices, initial := make([]flow.Option, 0, len(options)), []string{}
	for _, option := range options {
		choices = append(choices, flow.Option{Value: option.ID, Label: option.Label, Hint: option.Hint})
		if option.Selected {
			initial = append(initial, option.ID)
		}
	}
	selected, err := prompter.MultiSelect(ctx, flow.SelectPrompt{Message: "Which credential services do you want?", Description: "Select at least one.", Options: choices, InitialValues: initial, Required: true})
	if err != nil {
		return nil, err
	}
	return selected, nil
}

func selectedReleaseTemplate(options setupOptions, selected []string) (string, string, error) {
	if !filepath.IsAbs(options.DeploymentKits) || filepath.Clean(options.DeploymentKits) != options.DeploymentKits {
		return "", "", errors.New("verified release source is unavailable")
	}
	key, err := provider.SelectionKey(options.ProviderOptions, selected)
	if err != nil {
		return "", "", err
	}
	template, artifacts := filepath.Join(options.DeploymentKits, "templates", key), options.RuntimeArtifacts
	for _, path := range []string{template, artifacts} {
		info, statErr := os.Lstat(path)
		if statErr != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return "", "", errors.New("verified release is missing the selected setup source")
		}
	}
	return template, artifacts, nil
}

func validateGitHubCLI(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("verified GitHub attestation command path is invalid")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o111 == 0 {
		return errors.New("verified GitHub attestation command is missing or unsafe")
	}
	return nil
}

func installedProviderOptions() ([]provider.Option, string, error) {
	executable, err := os.Executable()
	if err != nil {
		return nil, "", err
	}
	return providerOptionsBesideExecutable(executable)
}

func providerOptionsBesideExecutable(executable string) ([]provider.Option, string, error) {
	resolved, err := filepath.EvalSymlinks(executable)
	if err != nil {
		return nil, "", err
	}
	root := filepath.Dir(resolved)
	directory := filepath.Join(root, "providers")
	if _, err := os.Lstat(directory); errors.Is(err, os.ErrNotExist) {
		return nil, root, nil
	} else if err != nil {
		return nil, "", err
	}
	options, err := provider.LoadDirectory(directory)
	return options, root, err
}

func finishPlanOnly(ctx context.Context, prompter flow.SetupPrompter, activate func(context.Context) error) error {
	if activate != nil {
		confirmed, err := prompter.Confirm(ctx, flow.ConfirmPrompt{Message: "Install the unYOLO command for later use?", Affirmative: "Install command", Negative: "Cancel", Safe: true})
		if err != nil || !confirmed {
			if err != nil {
				return err
			}
			return flow.CancelledError{}
		}
		if err := activateVerifiedCLI(ctx, prompter, activate); err != nil {
			return err
		}
	}
	return prompter.Outro(ctx, "Configuration is ready. No administrator changes were made.")
}

func activateVerifiedCLI(ctx context.Context, prompter flow.SetupPrompter, activate func(context.Context) error) error {
	if activate == nil {
		return nil
	}
	progress := prompter.Progress("Installing the verified unYOLO command")
	if err := activate(ctx); err != nil {
		progress.Fail("Command installation failed")
		return err
	}
	progress.Stop("unYOLO command installed")
	return nil
}

func prepareProtectedWorker(ctx context.Context, prompter flow.SetupPrompter, activate func(context.Context) error, sourceCommit, githubCLI string, start setupWorkerStarter) (protectedSetupWorker, error) {
	if err := activateVerifiedCLI(ctx, prompter, activate); err != nil {
		return nil, err
	}
	progress := prompter.Progress("Starting the verified administrator helper")
	worker, err := start(ctx, privilegedReleaseVersion(buildinfo.Version), sourceCommit, githubCLI, os.Stderr)
	if err != nil {
		progress.Fail("Could not start the administrator helper")
		return nil, err
	}
	progress.Stop("Administrator helper is ready")
	return worker, nil
}

func privilegedReleaseVersion(value string) string {
	if strings.HasPrefix(value, "v") {
		return value
	}
	return "v" + value
}

func runSetupStatus(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("unyolo setup status", flag.ContinueOnError)
	flags.SetOutput(stderr)
	jsonOutput := flags.Bool("json", false, "write closed JSON output")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("setup status does not accept positional arguments")
	}
	store, err := setupSessionStore()
	if err != nil {
		return err
	}
	values, err := store.List()
	if err != nil {
		return err
	}
	if *jsonOutput {
		return json.NewEncoder(stdout).Encode(struct {
			APIVersion string            `json:"api_version"`
			Sessions   []session.Session `json:"sessions"`
		}{session.APIVersion, values})
	}
	if len(values) == 0 {
		_, err = fmt.Fprintln(stdout, "No setup sessions")
		return err
	}
	for _, value := range values {
		if _, err := fmt.Fprintf(stdout, "%s\t%s\t%s\t%s\n", value.ID, value.InstallationName, value.Phase, value.UpdatedAt.UTC().Format(time.RFC3339)); err != nil {
			return err
		}
	}
	return nil
}

func runSetupCancel(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("unyolo setup cancel", flag.ContinueOnError)
	flags.SetOutput(stderr)
	confirmed := flags.Bool("confirm", false, "confirm local session removal")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 1 || !*confirmed {
		return errors.New("usage: unyolo setup cancel --confirm <session-id>")
	}
	store, err := setupSessionStore()
	if err != nil {
		return err
	}
	if err := store.Cancel(flags.Arg(0)); err != nil {
		return err
	}
	_, err = fmt.Fprintln(stdout, "Discarded the setup session")
	return err
}

func setupSessionStore() (session.Store, error) {
	directory, err := session.DefaultDirectory()
	return session.Store{Directory: directory}, err
}

func hasInteractiveTTY() bool {
	return term.IsTerminal(int(os.Stdin.Fd())) && term.IsTerminal(int(os.Stdout.Fd()))
}

func validateSetupSecretPairs(values map[string][]byte) error {
	seen := map[string]string{}
	for slot, value := range values {
		encoded := string(value)
		if previous, exists := seen[encoded]; exists {
			return fmt.Errorf("credentials for %s and %s must differ", previous, slot)
		}
		seen[encoded] = slot
	}
	return nil
}

func clearSetupSecrets(values map[string][]byte) {
	for _, value := range values {
		clear(value)
	}
}

func appendUnique(values []string, value string) []string {
	if slices.Contains(values, value) {
		return values
	}
	return append(values, value)
}
