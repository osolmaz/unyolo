// Package wizard defines the guided-setup state machine.
//
// The state machine is a pure function of the current intent and capability
// snapshot. It decides which step to show next, whether Back is available,
// and which answers become invalid when the user edits an earlier answer.
// Renderers and orchestration live in [Coordinator] and its collaborators.
package wizard

import (
	"errors"
	"slices"

	"github.com/osolmaz/unyolo/setup/capability"
	setupcopy "github.com/osolmaz/unyolo/setup/copy"
	setupintent "github.com/osolmaz/unyolo/setup/intent"
)

// Step identifies one guided-setup step.
type Step string

// Ordered wizard steps.
const (
	StepGoal            Step = "goal"
	StepServiceLocation Step = "service_location"
	StepProviders       Step = "providers"
	StepAgentLocation   Step = "agent_location"
	StepAccount         Step = "account"
	StepIsolationWarn   Step = "isolation_warning"
	StepInstallName     Step = "installation_name"
	StepReview          Step = "review"
	StepDone            Step = "done"
)

// Order lists every step from first to last. Steps that do not apply to the
// current intent are simply skipped by [Next].
var Order = []Step{
	StepGoal,
	StepServiceLocation,
	StepProviders,
	StepAgentLocation,
	StepAccount,
	StepIsolationWarn,
	StepInstallName,
	StepReview,
	StepDone,
}

// State captures every input the state machine needs.
type State struct {
	Intent       setupintent.Intent
	Capabilities capability.Snapshot
	// InstallationExists reports whether the store already contains one
	// installation with the reserved default name. When true the user is
	// asked for a different installation name.
	InstallationExists bool
	// InstallationName holds the name chosen for the new installation. It
	// remains empty until the user answers [StepInstallName]. When
	// InstallationExists is false the wizard reserves the default name and
	// never asks for a name.
	InstallationName string
}

// Choice is one selectable option surfaced by the wizard.
type Choice struct {
	Value string
	Label string
	Hint  string
}

// ErrNoPath signals that the release contains no completed setup path for
// the current platform.
var ErrNoPath = errors.New("this release has no completed setup path")

// Next returns the next step the wizard should present.
//
// It skips steps that do not apply to the current intent. The special
// [StepDone] value marks completion.
func Next(state State, current Step) Step {
	if state.Intent.APIVersion == "" {
		state.Intent.APIVersion = setupintent.APIVersion
	}
	index := indexOf(current)
	if index < 0 {
		return StepGoal
	}
	for _, candidate := range Order[index+1:] {
		if Applies(state, candidate) {
			return candidate
		}
	}
	return StepDone
}

// Previous returns the previous step the wizard should present. The user
// pressed Back on [current].
func Previous(state State, current Step) Step {
	index := indexOf(current)
	if index <= 0 {
		return current
	}
	for cursor := index - 1; cursor >= 0; cursor-- {
		if Applies(state, Order[cursor]) {
			return Order[cursor]
		}
	}
	return current
}

// Applies reports whether the state machine should present step [step]
// given the current intent.
//
//nolint:cyclop // The applicability rules follow the closed goal+location matrix.
func Applies(state State, step Step) bool {
	goal := state.Intent.Goal
	switch step {
	case StepGoal:
		return true
	case StepServiceLocation:
		return goal == setupintent.GoalCredentialService || goal == setupintent.GoalCompleteLocal
	case StepProviders:
		return goal == setupintent.GoalCredentialService || goal == setupintent.GoalCompleteLocal
	case StepAgentLocation:
		return goal == setupintent.GoalAgentConnection || goal == setupintent.GoalCompleteLocal
	case StepAccount:
		if goal != setupintent.GoalAgentConnection && goal != setupintent.GoalCompleteLocal {
			return false
		}
		return state.Intent.Agent != nil && state.Intent.Agent.Location == setupintent.AgentLocalAccount
	case StepIsolationWarn:
		return state.Intent.Agent != nil && state.Intent.Agent.Location == setupintent.AgentLocalAccount &&
			state.Intent.Agent.Account != nil && state.Intent.Agent.Account.Mode == setupintent.AccountCurrent
	case StepInstallName:
		return goal != setupintent.GoalCommandOnly && state.InstallationExists
	case StepReview:
		return goal != setupintent.GoalCommandOnly
	case StepDone:
		return true
	}
	return false
}

// InvalidateAfter clears answers derived from step [step].
//
// The state machine invalidates aggressively so that an edited earlier
// answer never leaves inconsistent derived answers behind.
func InvalidateAfter(state *State, step Step) {
	switch step {
	case StepGoal:
		state.Intent.CredentialService, state.Intent.Agent, state.Intent.Connection, state.Intent.Integrations = nil, nil, nil, nil
		state.InstallationName = ""
	case StepServiceLocation:
		if state.Intent.CredentialService != nil {
			state.Intent.CredentialService.Providers = nil
		}
		state.Intent.Agent, state.Intent.Connection, state.Intent.Integrations = nil, nil, nil
	case StepProviders:
		state.Intent.Agent, state.Intent.Connection, state.Intent.Integrations = nil, nil, nil
	case StepAgentLocation, StepAccount:
		state.Intent.Connection, state.Intent.Integrations = nil, nil
	case StepInstallName:
		state.InstallationName = ""
	case StepIsolationWarn, StepReview, StepDone:
		// No derived answers to clear.
	}
}

// GoalChoices returns the goal choices that are complete for the current
// release and host.
func GoalChoices(capabilities capability.Snapshot) []Choice {
	available := map[setupintent.Goal]bool{setupintent.GoalCommandOnly: true}
	native := capabilities.Has(capability.FeatureNativeService) && capabilities.Has(capability.FeatureLocalSocket)
	if native {
		available[setupintent.GoalCredentialService] = true
		if capabilities.Has(capability.FeatureLocalAccounts) {
			available[setupintent.GoalCompleteLocal] = true
		}
	}
	if capabilities.Has(capability.FeatureLocalSocket) || capabilities.Has(capability.FeatureRemotePairing) {
		available[setupintent.GoalAgentConnection] = true
	}
	result := make([]Choice, 0, len(setupcopy.Goals))
	for _, goal := range setupcopy.Goals {
		if available[setupintent.Goal(goal.Value)] {
			result = append(result, Choice{Value: goal.Value, Label: goal.Label, Hint: goal.Hint})
		}
	}
	return result
}

// ServiceLocationChoices returns the available credential-service locations.
func ServiceLocationChoices(capabilities capability.Snapshot) []Choice {
	result := make([]Choice, 0, len(setupcopy.Services))
	for _, service := range setupcopy.Services {
		if service.Value == "native" && !capabilities.Has(capability.FeatureNativeService) {
			continue
		}
		if service.Value == "docker" && !capabilities.Has(capability.FeatureDockerServices) {
			continue
		}
		result = append(result, Choice{Value: service.Value, Label: service.Label, Hint: service.Hint})
	}
	return result
}

// AgentLocationChoices returns the agent placements available on this host.
//
//nolint:cyclop // Availability follows the capability matrix; a switch is clearest.
func AgentLocationChoices(capabilities capability.Snapshot) []Choice {
	result := make([]Choice, 0, len(setupcopy.AgentLocations))
	for _, location := range setupcopy.AgentLocations {
		switch location.Value {
		case "managed", "existing":
			if !capabilities.Has(capability.FeatureLocalAccounts) {
				continue
			}
		case "current":
			if !capabilities.Has(capability.FeatureLocalSocket) {
				continue
			}
		case "container":
			if !capabilities.Has(capability.FeatureDockerAgent) {
				continue
			}
		case "remote":
			if !capabilities.Has(capability.FeatureRemotePairing) {
				continue
			}
		}
		result = append(result, Choice{Value: location.Value, Label: location.Label, Hint: location.Hint})
	}
	return result
}

// HasChoice reports whether [values] contains a choice with [value].
func HasChoice(values []Choice, value string) bool {
	return slices.ContainsFunc(values, func(choice Choice) bool { return choice.Value == value })
}

func indexOf(step Step) int {
	for index, entry := range Order {
		if entry == step {
			return index
		}
	}
	return -1
}
