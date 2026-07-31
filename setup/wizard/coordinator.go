package wizard

import (
	"context"
	"errors"
	"regexp"
	"strings"

	"github.com/osolmaz/unyolo/deployment/flow"
	"github.com/osolmaz/unyolo/setup/capability"
	setupcopy "github.com/osolmaz/unyolo/setup/copy"
	"github.com/osolmaz/unyolo/setup/installation"
	setupintent "github.com/osolmaz/unyolo/setup/intent"
)

// AccountLister lists suitable existing local accounts for the current host.
type AccountLister interface {
	List(ctx context.Context) ([]Account, error)
}

// Account is a suitable existing account displayed to the user.
type Account struct {
	Name string
	Home string
}

// Persister receives the current wizard state after every transition. The
// concrete implementation writes the nonsecret session to disk.
type Persister interface {
	Save(state State, currentStep Step) error
}

// ProviderChoice describes one selectable credential-service provider. The
// coordinator receives these from the verified release catalog.
type ProviderChoice struct {
	Value    string
	Label    string
	Hint     string
	Selected bool
}

// Options configures a coordinator.
type Options struct {
	Prompter     flow.SetupPrompter
	Accounts     AccountLister
	Persist      Persister
	Capabilities capability.Snapshot
	Providers    []ProviderChoice
	Initial      State
	// InitialStep names the step to resume from. Empty means start at goal.
	InitialStep Step
	// InstallationExists mirrors [State.InstallationExists] for the initial
	// state. The wizard passes it into State on start.
	InstallationExists bool
	// CurrentAccount is the operating-system account name of the caller.
	// Used to label the current-account choice and to fill the intent when
	// the user picks that mode.
	CurrentAccount string
}

// Result is the value returned by [Coordinator.Run] once the wizard has
// walked to the end of its state machine.
type Result struct {
	Intent           setupintent.Intent
	InstallationName string
	// Edited reports whether the user pressed Edit on the review screen at
	// least once. Callers may use this to log the transition.
	Edited bool
}

var installationNamePattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$`)

// Coordinator drives the state machine through a [flow.SetupPrompter].
type Coordinator struct {
	options Options
}

// New constructs a coordinator with the given options.
func New(options Options) *Coordinator {
	return &Coordinator{options: options}
}

// Run walks the state machine until the user reaches [StepDone] or cancels.
//
//nolint:cyclop,gocognit // The coordinator maps every step in one place; splitting hurts readability.
func (c *Coordinator) Run(ctx context.Context) (Result, error) {
	state := c.options.Initial
	if state.Intent.APIVersion == "" {
		state.Intent.APIVersion = setupintent.APIVersion
	}
	state.Capabilities = c.options.Capabilities
	state.InstallationExists = c.options.InstallationExists
	step := c.options.InitialStep
	if step == "" || !Applies(state, step) {
		step = StepGoal
	}
	edited := false
	for step != StepDone {
		if err := ctx.Err(); err != nil {
			return Result{}, flow.CancelledError{Cause: err}
		}
		next, err := c.runStep(ctx, &state, step)
		if err != nil {
			var navigation flow.NavigationError
			if errors.As(err, &navigation) {
				switch navigation.Direction {
				case "back":
					step = Previous(state, step)
					InvalidateAfter(&state, step)
					if err := c.persist(state, step); err != nil {
						return Result{}, err
					}
					continue
				case "edit":
					edited = true
					// The direction carries a target step in Cause when set;
					// for now, treat Edit as Back to the first applicable
					// screen after Goal.
					step = StepGoal
					if err := c.persist(state, step); err != nil {
						return Result{}, err
					}
					continue
				}
			}
			return Result{}, err
		}
		step = next
		if err := c.persist(state, step); err != nil {
			return Result{}, err
		}
	}
	if state.InstallationName == "" {
		state.InstallationName = installation.DefaultName
	}
	return Result{Intent: state.Intent, InstallationName: state.InstallationName, Edited: edited}, nil
}

func (c *Coordinator) persist(state State, step Step) error {
	if c.options.Persist == nil {
		return nil
	}
	return c.options.Persist.Save(state, step)
}

//nolint:cyclop // Each branch drives one screen; a switch is the clearest form.
func (c *Coordinator) runStep(ctx context.Context, state *State, step Step) (Step, error) {
	switch step {
	case StepGoal:
		return c.stepGoal(ctx, state)
	case StepServiceLocation:
		return c.stepServiceLocation(ctx, state)
	case StepProviders:
		return c.stepProviders(ctx, state)
	case StepAgentLocation:
		return c.stepAgentLocation(ctx, state)
	case StepAccount:
		return c.stepAccount(ctx, state)
	case StepIsolationWarn:
		return c.stepIsolationWarning(ctx, state)
	case StepInstallName:
		return c.stepInstallationName(ctx, state)
	case StepReview:
		return c.stepReview(ctx, state)
	case StepDone:
		return StepDone, nil
	}
	return StepDone, nil
}

func (c *Coordinator) stepGoal(ctx context.Context, state *State) (Step, error) {
	choices := GoalChoices(c.options.Capabilities)
	if len(choices) == 0 {
		return "", ErrNoPath
	}
	value, err := c.options.Prompter.Select(ctx, flow.SelectPrompt{
		Message:      screenMessage(setupcopy.ScreenGoal),
		Description:  screenReason(setupcopy.ScreenGoal),
		Options:      toFlowOptions(choices),
		InitialValue: firstMatch(choices, string(state.Intent.Goal)),
		Navigation:   flow.Navigation{CanGoBack: false},
	})
	if err != nil {
		return "", err
	}
	if state.Intent.Goal != setupintent.Goal(value) {
		state.Intent.Goal = setupintent.Goal(value)
		InvalidateAfter(state, StepGoal)
	}
	return Next(*state, StepGoal), nil
}

func (c *Coordinator) stepServiceLocation(ctx context.Context, state *State) (Step, error) {
	choices := ServiceLocationChoices(c.options.Capabilities)
	if len(choices) == 0 {
		return "", errors.New("this release cannot install credential services on this computer")
	}
	current := ""
	if state.Intent.CredentialService != nil {
		current = string(state.Intent.CredentialService.Location)
	}
	value, err := c.options.Prompter.Select(ctx, flow.SelectPrompt{
		Message:      screenMessage(setupcopy.ScreenServiceLocation),
		Description:  screenReason(setupcopy.ScreenServiceLocation),
		Options:      toFlowOptions(choices),
		InitialValue: firstMatch(choices, current),
		Navigation:   flow.Navigation{CanGoBack: true},
	})
	if err != nil {
		return "", err
	}
	location := setupintent.ServiceLocation(value)
	if state.Intent.CredentialService == nil || state.Intent.CredentialService.Location != location {
		state.Intent.CredentialService = &setupintent.CredentialService{Location: location}
		InvalidateAfter(state, StepServiceLocation)
	}
	return Next(*state, StepServiceLocation), nil
}

func (c *Coordinator) stepProviders(ctx context.Context, state *State) (Step, error) {
	if len(c.options.Providers) == 0 {
		return "", errors.New("verified release contains no credential services")
	}
	initial := providerInitialValues(state.Intent.CredentialService, c.options.Providers)
	value, err := c.options.Prompter.MultiSelect(ctx, flow.SelectPrompt{
		Message:       screenMessage(setupcopy.ScreenProviders),
		Description:   screenReason(setupcopy.ScreenProviders),
		Options:       providerOptions(c.options.Providers),
		InitialValues: initial,
		Required:      true,
		Navigation:    flow.Navigation{CanGoBack: true},
	})
	if err != nil {
		return "", err
	}
	if state.Intent.CredentialService == nil {
		state.Intent.CredentialService = &setupintent.CredentialService{Location: setupintent.ServiceNative}
	}
	state.Intent.CredentialService.Providers = value
	return Next(*state, StepProviders), nil
}

func (c *Coordinator) stepAgentLocation(ctx context.Context, state *State) (Step, error) {
	choices := AgentLocationChoices(c.options.Capabilities)
	choices = availableForGoal(choices, state.Intent.Goal)
	if len(choices) == 0 {
		return "", errors.New("this release cannot connect an agent on this computer")
	}
	current := ""
	if state.Intent.Agent != nil {
		current = intentAgentLocationValue(state.Intent.Agent)
	}
	value, err := c.options.Prompter.Select(ctx, flow.SelectPrompt{
		Message:      screenMessage(setupcopy.ScreenAgentLocation),
		Description:  screenReason(setupcopy.ScreenAgentLocation),
		Options:      toFlowOptions(choices),
		InitialValue: firstMatch(choices, current),
		Navigation:   flow.Navigation{CanGoBack: true},
	})
	if err != nil {
		return "", err
	}
	if intentAgentLocationValue(state.Intent.Agent) != value {
		c.setAgentLocation(state, value)
	}
	return Next(*state, StepAgentLocation), nil
}

func (c *Coordinator) setAgentLocation(state *State, choice string) {
	agent := &setupintent.Agent{Location: setupintent.AgentLocalAccount}
	switch choice {
	case "current":
		agent.Account = &setupintent.Account{Mode: setupintent.AccountCurrent}
		agent.ConnectionName = c.options.CurrentAccount
	case "existing":
		agent.Account = &setupintent.Account{Mode: setupintent.AccountExisting}
	case "managed":
		agent.Account = &setupintent.Account{Mode: setupintent.AccountManaged, Name: "unyolo-agent"}
		agent.ConnectionName = "unyolo-agent"
	case "container":
		agent.Location = setupintent.AgentContainer
	case "remote":
		agent.Location = setupintent.AgentRemote
	}
	state.Intent.Agent = agent
	if choice == "container" || choice == "remote" {
		state.Intent.Connection = nil
		return
	}
	state.Intent.Connection = &setupintent.Connection{Transport: setupintent.TransportLocalSocket}
}

func (c *Coordinator) stepAccount(ctx context.Context, state *State) (Step, error) {
	if state.Intent.Agent == nil || state.Intent.Agent.Account == nil {
		return "", errors.New("wizard: agent selection is missing")
	}
	switch state.Intent.Agent.Account.Mode {
	case setupintent.AccountCurrent:
		state.Intent.Agent.ConnectionName = c.options.CurrentAccount
		return Next(*state, StepAccount), nil
	case setupintent.AccountManaged:
		if state.Intent.Agent.ConnectionName == "" {
			state.Intent.Agent.ConnectionName = "unyolo-agent"
		}
		if state.Intent.Agent.Account.Name == "" {
			state.Intent.Agent.Account.Name = state.Intent.Agent.ConnectionName
		}
		return Next(*state, StepAccount), nil
	case setupintent.AccountExisting:
		return c.stepExistingAccount(ctx, state)
	}
	return "", errors.New("wizard: unknown account mode")
}

func (c *Coordinator) stepExistingAccount(ctx context.Context, state *State) (Step, error) {
	if c.options.Accounts == nil {
		return "", errors.New("wizard: existing accounts are unavailable")
	}
	accounts, err := c.options.Accounts.List(ctx)
	if err != nil {
		return "", err
	}
	if len(accounts) == 0 {
		return "", errors.New("no existing accounts are available on this computer")
	}
	options := make([]flow.Option, 0, len(accounts))
	for _, account := range accounts {
		options = append(options, flow.Option{Value: account.Name, Label: account.Name, Hint: account.Home})
	}
	initial := firstOptionValue(options)
	if state.Intent.Agent.Account.Name != "" {
		initial = state.Intent.Agent.Account.Name
	}
	value, err := c.options.Prompter.Select(ctx, flow.SelectPrompt{
		Message:      screenMessage(setupcopy.ScreenAccount),
		Description:  screenReason(setupcopy.ScreenAccount),
		Options:      options,
		InitialValue: initial,
		Searchable:   true,
		Navigation:   flow.Navigation{CanGoBack: true},
	})
	if err != nil {
		return "", err
	}
	state.Intent.Agent.Account.Name = value
	state.Intent.Agent.ConnectionName = value
	return Next(*state, StepAccount), nil
}

func (c *Coordinator) stepIsolationWarning(ctx context.Context, state *State) (Step, error) {
	screen := setupcopy.Screens[setupcopy.ScreenIsolationWarn]
	confirmed, err := c.options.Prompter.Confirm(ctx, flow.ConfirmPrompt{
		Message:     screen.Question,
		Description: screen.Reason,
		Affirmative: screen.Primary,
		Negative:    screen.Secondary,
		Safe:        true,
		Navigation:  flow.Navigation{CanGoBack: true},
	})
	if err != nil {
		return "", err
	}
	if !confirmed {
		// Declining the reduced-isolation warning discards the agent
		// choice so the user can pick a different placement or account.
		state.Intent.Agent = nil
		state.Intent.Connection = nil
		return StepAgentLocation, nil
	}
	return Next(*state, StepIsolationWarn), nil
}

func (c *Coordinator) stepInstallationName(ctx context.Context, state *State) (Step, error) {
	screen := setupcopy.Screens[setupcopy.ScreenInstallName]
	initial := state.InstallationName
	if initial == "" {
		initial = installation.DefaultName + "-2"
	}
	value, err := c.options.Prompter.Text(ctx, flow.Prompt{
		Message:      screen.Question,
		Description:  screen.Reason,
		InitialValue: initial,
		Required:     true,
		Navigation:   flow.Navigation{CanGoBack: true},
		Validate: func(value string) error {
			if !installationNamePattern.MatchString(value) {
				return errors.New("use lowercase letters, digits, and hyphens between them; 1-64 characters")
			}
			if value == installation.DefaultName {
				return errors.New("that name is already taken; choose another")
			}
			return nil
		},
	})
	if err != nil {
		return "", err
	}
	state.InstallationName = value
	return Next(*state, StepInstallName), nil
}

func (c *Coordinator) stepReview(ctx context.Context, state *State) (Step, error) {
	summary := ReviewSummary(*state)
	if err := c.options.Prompter.Note(ctx, summary, setupcopy.Screens[setupcopy.ScreenReview].Question); err != nil {
		return "", err
	}
	confirmed, err := c.options.Prompter.Confirm(ctx, flow.ConfirmPrompt{
		Message:     "Ready to continue?",
		Description: setupcopy.Screens[setupcopy.ScreenReview].Reason,
		Affirmative: setupcopy.Screens[setupcopy.ScreenReview].Primary,
		Negative:    "Edit",
		Safe:        true,
		Navigation:  flow.Navigation{CanGoBack: true},
	})
	if err != nil {
		return "", err
	}
	if !confirmed {
		return "", flow.NavigationError{Direction: "edit"}
	}
	return StepDone, nil
}

// ReviewSummary renders the plain-language review summary for the intent.
//
// It never uses forbidden internal terms and is safe to snapshot.
func ReviewSummary(state State) string {
	var lines []string
	if state.Intent.CredentialService != nil {
		location := "on this computer"
		if state.Intent.CredentialService.Location == setupintent.ServiceDocker {
			location = "in Docker on this computer"
		}
		lines = append(lines, "Credential services: "+location)
		if len(state.Intent.CredentialService.Providers) > 0 {
			lines = append(lines, "  "+strings.Join(state.Intent.CredentialService.Providers, ", "))
		}
	} else {
		lines = append(lines, "No credential services will be installed")
	}
	if state.Intent.Agent != nil {
		lines = append(lines, "Agent")
		lines = append(lines, "  Placement: "+describeAgentLocation(state.Intent.Agent))
		if state.Intent.Agent.ConnectionName != "" {
			lines = append(lines, "  Connection name: "+state.Intent.Agent.ConnectionName)
		}
		if state.Intent.Agent.Account != nil && state.Intent.Agent.Account.Mode == setupintent.AccountCurrent {
			lines = append(lines, "  Isolation: reduced (shares your account)")
		}
	} else {
		lines = append(lines, "No agent connection will be made")
	}
	if state.InstallationName != "" {
		lines = append(lines, "Installation name: "+state.InstallationName)
	}
	return strings.Join(lines, "\n")
}

func describeAgentLocation(agent *setupintent.Agent) string {
	switch agent.Location {
	case setupintent.AgentContainer:
		return "Docker container on this computer"
	case setupintent.AgentRemote:
		return "another computer"
	case setupintent.AgentLocalAccount:
		if agent.Account == nil {
			return "local account on this computer"
		}
		switch agent.Account.Mode {
		case setupintent.AccountCurrent:
			return "current account"
		case setupintent.AccountManaged:
			return "new separate account: " + agent.Account.Name
		case setupintent.AccountExisting:
			return "existing account: " + agent.Account.Name
		}
	}
	return "local account on this computer"
}

func availableForGoal(choices []Choice, goal setupintent.Goal) []Choice {
	if goal != setupintent.GoalCompleteLocal {
		return choices
	}
	// Complete-local setup only supports local-account targets today; the
	// container and remote paths ship in later slices.
	filtered := make([]Choice, 0, len(choices))
	for _, choice := range choices {
		if choice.Value == "container" || choice.Value == "remote" {
			continue
		}
		filtered = append(filtered, choice)
	}
	return filtered
}

func intentAgentLocationValue(agent *setupintent.Agent) string {
	if agent == nil {
		return ""
	}
	switch agent.Location {
	case setupintent.AgentContainer:
		return "container"
	case setupintent.AgentRemote:
		return "remote"
	case setupintent.AgentLocalAccount:
		if agent.Account == nil {
			return ""
		}
		switch agent.Account.Mode {
		case setupintent.AccountCurrent:
			return "current"
		case setupintent.AccountManaged:
			return "managed"
		case setupintent.AccountExisting:
			return "existing"
		}
	}
	return ""
}

func screenMessage(id string) string {
	if screen, exists := setupcopy.Screens[id]; exists {
		return screen.Question
	}
	return id
}

func screenReason(id string) string {
	if screen, exists := setupcopy.Screens[id]; exists {
		return screen.Reason
	}
	return ""
}

func toFlowOptions(choices []Choice) []flow.Option {
	options := make([]flow.Option, 0, len(choices))
	for _, choice := range choices {
		options = append(options, flow.Option{Value: choice.Value, Label: choice.Label, Hint: choice.Hint})
	}
	return options
}

func providerOptions(providers []ProviderChoice) []flow.Option {
	options := make([]flow.Option, 0, len(providers))
	for _, provider := range providers {
		options = append(options, flow.Option{Value: provider.Value, Label: provider.Label, Hint: provider.Hint})
	}
	return options
}

func providerInitialValues(current *setupintent.CredentialService, providers []ProviderChoice) []string {
	if current != nil && len(current.Providers) > 0 {
		return append([]string(nil), current.Providers...)
	}
	var initial []string
	for _, provider := range providers {
		if provider.Selected {
			initial = append(initial, provider.Value)
		}
	}
	return initial
}

func firstMatch(choices []Choice, value string) string {
	if HasChoice(choices, value) {
		return value
	}
	if len(choices) > 0 {
		return choices[0].Value
	}
	return ""
}

func firstOptionValue(options []flow.Option) string {
	if len(options) == 0 {
		return ""
	}
	return options[0].Value
}

// Ensure capability import is not accidentally dropped.
var _ capability.Snapshot
