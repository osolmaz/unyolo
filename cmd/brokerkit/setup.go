package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/osolmaz/brokerkit/deployment/flow"
	"github.com/osolmaz/brokerkit/deployment/profile"
	"github.com/osolmaz/brokerkit/deployment/session"
	"github.com/osolmaz/brokerkit/internal/buildinfo"
	"github.com/osolmaz/brokerkit/internal/host/privilege"
	terminalsetup "github.com/osolmaz/brokerkit/internal/terminal/setup"
	"golang.org/x/term"
)

var deploymentNamePattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$`)

//nolint:cyclop // Setup dispatch keeps cancellation and terminal cleanup in one lifecycle boundary.
func runGuidedSetup(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	if len(args) > 0 && args[0] == "status" {
		return runSetupStatus(args[1:], stdout, stderr)
	}
	if len(args) > 0 && args[0] == "cancel" {
		return runSetupCancel(args[1:], stdout, stderr)
	}
	flags := flag.NewFlagSet("brokerkit setup", flag.ContinueOnError)
	flags.SetOutput(stderr)
	profilePath := flags.String("profile", "", "existing deployment pack to review or repair")
	accessible := flags.Bool("accessible", false, "use screen-reader-friendly prompts")
	noOpen := flags.Bool("no-open", false, "print browser URLs instead of opening them")
	resumeID := flags.String("resume", "", "resume one setup session")
	newSession := flags.Bool("new", false, "start a new setup session")
	planOnly := flags.Bool("plan-only", false, "write and validate the pack without privileged apply")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || (*resumeID != "" && *newSession) {
		return errors.New("setup does not accept positional arguments and --resume conflicts with --new")
	}
	if os.Geteuid() == 0 {
		return errors.New("interactive setup must run as a normal trusted operator, not root")
	}
	if !*accessible && !hasInteractiveTTY() {
		return errors.New("setup requires an interactive TTY; use declarative system commands for automation")
	}
	prompter := terminalsetup.New(terminalsetup.Options{Input: os.Stdin, Output: stdout, Accessible: *accessible, NoOpen: *noOpen})
	defer func() { _ = prompter.Close() }()
	return runSetupFlow(ctx, prompter, setupOptions{Profile: *profilePath, ResumeID: *resumeID, New: *newSession, PlanOnly: *planOnly})
}

type setupOptions struct {
	Profile  string
	ResumeID string
	New      bool
	PlanOnly bool
}

//nolint:cyclop // The ordered guide deliberately keeps persisted checkpoints adjacent to each operator decision.
func runSetupFlow(ctx context.Context, prompter flow.SetupPrompter, options setupOptions) error {
	if err := prompter.Intro(ctx, "BrokerKit host setup"); err != nil {
		return err
	}
	if err := prompter.Note(ctx,
		"Setup runs as your trusted operator account. The agent remains a separate nonprivileged Unix identity. BrokerKit will show and bind one exact plan before any protected host change.",
		"Security boundary"); err != nil {
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
	if len(setupSession.Answers["mode"]) == 0 {
		mode, selectErr := prompter.Select(ctx, flow.SelectPrompt{
			Message: "How should this host be configured?", Searchable: false,
			Options: []flow.Option{
				{Value: "recommended", Label: "Recommended", Hint: "Separate agent, local sockets, approval-gated writes, skills-only OpenClaw"},
				{Value: "custom", Label: "Custom", Hint: "Review identities, endpoints, components, and integration trust"},
				{Value: "existing", Label: "Existing deployment", Hint: "Review, repair, or reapply a locked deployment pack"},
			},
			InitialValue: initialSetupMode(options.Profile),
		})
		if selectErr != nil {
			return selectErr
		}
		setupSession.Answers["mode"] = []string{mode}
		setupSession.CompletedStep = appendUnique(setupSession.CompletedStep, "mode")
		if err := store.Save(setupSession); err != nil {
			return err
		}
	}
	if setupSession.Answers["mode"][0] != "existing" {
		if err := prompter.Note(ctx,
			"The signed deployment pack carries the selected safe defaults and provider-owned enrollment profiles. This setup reviews those exact resources rather than discovering or widening live permissions.",
			"Deployment kit"); err != nil {
			return err
		}
	}
	profilePath, err := chooseProfile(ctx, prompter, options.Profile, setupSession)
	if err != nil {
		return err
	}
	setupSession.Answers["profile"] = []string{profilePath}
	setupSession.CompletedStep = appendUnique(setupSession.CompletedStep, "profile")
	setupSession.Phase = session.PhaseProfile
	if err := store.Save(setupSession); err != nil {
		return err
	}
	progress := prompter.Progress("Validating the locked deployment pack")
	snapshot, err := profile.Load(profilePath)
	if err != nil {
		progress.Fail("Deployment pack validation failed")
		return err
	}
	progress.Stop("Deployment pack is valid")
	if setupSession.Answers["mode"][0] != "existing" {
		if snapshot.Deployment.Name != setupSession.Deployment {
			return fmt.Errorf("deployment kit name %q does not match setup name %q", snapshot.Deployment.Name, setupSession.Deployment)
		}
		destination, pathErr := setupDeploymentDirectory(snapshot.Deployment.Name)
		if pathErr != nil {
			return pathErr
		}
		materialized, materializedErr := setupProfileAlreadyMaterialized(setupSession, profilePath, destination, snapshot.Digest)
		if materializedErr != nil {
			return materializedErr
		}
		if !materialized {
			materializeProgress := prompter.Progress("Materializing the operator-owned deployment pack")
			profilePath, err = profile.Materialize(snapshot, destination)
			if err != nil {
				materializeProgress.Fail("Deployment pack materialization failed")
				return err
			}
			snapshot, err = profile.Load(profilePath)
			if err != nil {
				materializeProgress.Fail("Materialized deployment pack validation failed")
				return err
			}
			materializeProgress.Stop("Operator-owned deployment pack is ready")
			setupSession.Answers["profile"] = []string{profilePath}
			setupSession.Generated[profile.EntryFilename] = snapshot.Digest
			if err := store.Save(setupSession); err != nil {
				return err
			}
		}
	}
	if err := showSetupReview(ctx, prompter, snapshot); err != nil {
		return err
	}
	if options.PlanOnly {
		return prompter.Outro(ctx, "Profile ready. Run brokerkit system plan as a trusted administrator.")
	}
	confirmed, err := prompter.Confirm(ctx, flow.ConfirmPrompt{
		Message: "Continue to protected host planning?", Description: "No host mutation occurs until the exact plan digest is shown and confirmed.", Safe: true,
	})
	if err != nil {
		return err
	}
	if !confirmed {
		return flow.CancelledError{}
	}
	workerProgress := prompter.Progress("Starting the verified root-owned setup worker")
	worker, err := privilege.Start(ctx, privilegedReleaseVersion(buildinfo.Version), os.Stderr)
	if err != nil {
		workerProgress.Fail("Could not start the verified setup worker")
		return err
	}
	defer func() { _ = worker.Close() }()
	workerProgress.Update("Inspecting protected host state")
	planned, err := worker.Plan(profilePath)
	if err != nil {
		workerProgress.Fail("Protected host planning failed")
		return err
	}
	workerProgress.Stop("Protected host plan is ready")
	setupSession.Phase = session.PhasePlanned
	if err := store.Save(setupSession); err != nil {
		_ = worker.Cancel()
		return err
	}
	if err := prompter.Note(ctx,
		fmt.Sprintf("Identity and providers are bound to the locked pack.\nServices: runtime %s\nAccess: %d reviewed actions\nVerification: real component checks\nPlan digest: %s", planned.Plan.RuntimeBundleID, len(planned.Plan.Actions), planned.PlanDigest),
		"Final host plan"); err != nil {
		_ = worker.Cancel()
		return err
	}
	apply, err := prompter.Confirm(ctx, flow.ConfirmPrompt{
		Message: "Apply this exact host plan?", Description: "The setup worker rejects any changed host state or plan digest.", Safe: true,
	})
	if err != nil || !apply {
		_ = worker.Cancel()
		if err != nil {
			return err
		}
		return flow.CancelledError{}
	}
	secrets := map[string][]byte{}
	setupSession.SecretSlots = nil
	defer clearSetupSecrets(secrets)
	for _, slot := range privilege.RequiredSecretSlots(planned.Plan) {
		value, secretErr := prompter.Secret(ctx, flow.Prompt{Message: "Credential slot: " + slot, Description: "Sent once to the owning signed adapter and never stored in setup state.", Required: true})
		if secretErr != nil {
			_ = worker.Cancel()
			return secretErr
		}
		secrets[slot] = value
		setupSession.SecretSlots = append(setupSession.SecretSlots, session.SecretSlot{ID: slot, Supplied: true})
	}
	setupSession.Phase = session.PhaseApplying
	if err := store.Save(setupSession); err != nil {
		_ = worker.Cancel()
		return err
	}
	applyProgress := prompter.Progress("Applying the reviewed host transaction")
	result, err := worker.Apply(planned.PlanDigest, secrets)
	clearSetupSecrets(secrets)
	if err != nil {
		applyProgress.Fail("Host transaction failed or was rolled back")
		return err
	}
	applyProgress.Stop(result.Message)
	setupSession.Phase = session.PhaseComplete
	setupSession.SecretSlots = nil
	if err := store.Save(setupSession); err != nil {
		return err
	}
	return prompter.Outro(ctx, fmt.Sprintf("Verified deployment %s. Run brokerkit system verify --profile %s", snapshot.Deployment.Name, profilePath))
}

//nolint:cyclop // New, explicit, and latest-session choices are one closed resume policy.
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
			resume, confirmErr := prompter.Confirm(ctx, flow.ConfirmPrompt{Message: "Resume the latest incomplete setup?", Initial: true})
			if confirmErr != nil {
				return session.Session{}, confirmErr
			}
			if resume {
				return existing, nil
			}
		}
	}
	name, err := prompter.Text(ctx, flow.Prompt{
		Message: "Deployment name", Placeholder: "my-host", Required: true,
		Validate: func(value string) error {
			if !deploymentNamePattern.MatchString(value) {
				return errors.New("use lowercase letters, digits, and interior hyphens")
			}
			return nil
		},
	})
	if err != nil {
		return session.Session{}, err
	}
	created, err := session.New(build, name, time.Now())
	if err != nil {
		return session.Session{}, err
	}
	if err := store.Save(created); err != nil {
		return session.Session{}, err
	}
	return created, nil
}

func privilegedReleaseVersion(version string) string {
	if strings.HasPrefix(version, "v") {
		return version
	}
	return "v" + version
}

func initialSetupMode(profilePath string) string {
	if profilePath != "" {
		return "existing"
	}
	return "recommended"
}

func chooseProfile(ctx context.Context, prompter flow.SetupPrompter, configured string, setupSession session.Session) (string, error) {
	if configured == "" && len(setupSession.Answers["profile"]) == 1 {
		configured = setupSession.Answers["profile"][0]
	}
	if configured == "" {
		value, err := prompter.Text(ctx, flow.Prompt{
			Message: "Deployment pack directory", Placeholder: filepath.Join("~", ".config", "brokerkit", "deployments", setupSession.Deployment), Required: true,
			Validate: func(value string) error {
				if !filepath.IsAbs(value) || filepath.Clean(value) != value {
					return errors.New("enter an absolute clean directory path")
				}
				return nil
			},
		})
		if err != nil {
			return "", err
		}
		configured = value
	}
	if !filepath.IsAbs(configured) || filepath.Clean(configured) != configured {
		return "", errors.New("setup profile path must be absolute and clean")
	}
	return configured, nil
}

func showSetupReview(ctx context.Context, prompter flow.SetupPrompter, snapshot profile.Snapshot) error {
	agents := make([]string, 0, len(snapshot.Deployment.Agents))
	for _, agent := range snapshot.Deployment.Agents {
		agents = append(agents, agent.ID+" ("+agent.UnixUser+")")
	}
	components := make([]string, 0, len(snapshot.Deployment.Components))
	for _, component := range snapshot.Deployment.Components {
		components = append(components, component.ID)
	}
	message := fmt.Sprintf("Identity\n  Agents: %s\n  Operators: %d\nProviders\n  %s\nServices\n  Runtime: %s\nVerification\n  Pack digest: %s",
		strings.Join(agents, ", "), len(snapshot.Deployment.Operators), strings.Join(components, ", "), snapshot.Manifest.BundleID, snapshot.Digest)
	return prompter.Note(ctx, message, "Deployment review")
}

func runSetupStatus(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("brokerkit setup status", flag.ContinueOnError)
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
		_, err = fmt.Fprintln(stdout, "No local setup sessions")
		return err
	}
	for _, value := range values {
		if _, err := fmt.Fprintf(stdout, "%s\t%s\t%s\t%s\n", value.ID, value.Deployment, value.Phase, value.UpdatedAt.UTC().Format(time.RFC3339)); err != nil {
			return err
		}
	}
	return nil
}

func runSetupCancel(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("brokerkit setup cancel", flag.ContinueOnError)
	flags.SetOutput(stderr)
	confirmed := flags.Bool("confirm", false, "confirm local session removal")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 1 || !*confirmed {
		return errors.New("usage: brokerkit setup cancel --confirm <session-id>")
	}
	store, err := setupSessionStore()
	if err != nil {
		return err
	}
	if err := store.Cancel(flags.Arg(0)); err != nil {
		return err
	}
	_, err = fmt.Fprintln(stdout, "Cancelled local setup session")
	return err
}

func setupProfileAlreadyMaterialized(setupSession session.Session, profilePath, destination, digest string) (bool, error) {
	if profilePath != destination {
		return false, nil
	}
	if setupSession.Generated[profile.EntryFilename] != digest {
		return false, errors.New("resumable setup materialization digest is invalid")
	}
	return true, nil
}

func setupDeploymentDirectory(name string) (string, error) {
	if !deploymentNamePattern.MatchString(name) {
		return "", errors.New("deployment name is invalid")
	}
	root, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	if !filepath.IsAbs(root) {
		return "", errors.New("user configuration directory is not absolute")
	}
	return filepath.Join(root, "brokerkit", "deployments", name), nil
}

func setupSessionStore() (session.Store, error) {
	directory, err := session.DefaultDirectory()
	return session.Store{Directory: directory}, err
}

func hasInteractiveTTY() bool {
	return term.IsTerminal(int(os.Stdin.Fd())) && term.IsTerminal(int(os.Stdout.Fd()))
}

func clearSetupSecrets(values map[string][]byte) {
	for _, value := range values {
		clear(value)
	}
}

func appendUnique(values []string, value string) []string {
	for _, current := range values {
		if current == value {
			return values
		}
	}
	return append(values, value)
}
