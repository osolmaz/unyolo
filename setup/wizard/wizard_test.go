package wizard

import (
	"testing"

	"github.com/osolmaz/unyolo/setup/capability"
	setupintent "github.com/osolmaz/unyolo/setup/intent"
)

func TestGoalChoicesHideIncompletePaths(t *testing.T) {
	t.Parallel()
	commandOnly := capability.Snapshot{}
	if choices := GoalChoices(commandOnly); len(choices) != 1 || choices[0].Value != "command_only" {
		t.Fatalf("command-only choices = %#v", choices)
	}
	complete := capability.Snapshot{Features: []capability.Feature{capability.FeatureNativeService, capability.FeatureLocalSocket, capability.FeatureLocalAccounts}}
	choices := GoalChoices(complete)
	for _, value := range []string{"complete_local", "credential_service", "agent_connection", "command_only"} {
		if !HasChoice(choices, value) {
			t.Fatalf("choice %q is missing from %#v", value, choices)
		}
	}
}

func TestApplyMatrix(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		state   State
		step    Step
		applies bool
	}{
		{"goal always applies", State{}, StepGoal, true},
		{"service on command_only skips", stateWithGoal(setupintent.GoalCommandOnly), StepServiceLocation, false},
		{"service on server applies", stateWithGoal(setupintent.GoalCredentialService), StepServiceLocation, true},
		{"providers on complete applies", stateWithGoal(setupintent.GoalCompleteLocal), StepProviders, true},
		{"agent location on server skips", stateWithGoal(setupintent.GoalCredentialService), StepAgentLocation, false},
		{"account on remote skips", func() State {
			s := stateWithGoal(setupintent.GoalAgentConnection)
			s.Intent.Agent = &setupintent.Agent{Location: setupintent.AgentRemote}
			return s
		}(), StepAccount, false},
		{"isolation warning on current applies", func() State {
			s := stateWithGoal(setupintent.GoalAgentConnection)
			s.Intent.Agent = &setupintent.Agent{Location: setupintent.AgentLocalAccount, Account: &setupintent.Account{Mode: setupintent.AccountCurrent}}
			return s
		}(), StepIsolationWarn, true},
		{"isolation warning on managed skips", func() State {
			s := stateWithGoal(setupintent.GoalAgentConnection)
			s.Intent.Agent = &setupintent.Agent{Location: setupintent.AgentLocalAccount, Account: &setupintent.Account{Mode: setupintent.AccountManaged, Name: "unyolo-agent"}}
			return s
		}(), StepIsolationWarn, false},
		{"install name only when collision", func() State {
			s := stateWithGoal(setupintent.GoalCredentialService)
			s.InstallationExists = true
			return s
		}(), StepInstallName, true},
		{"install name skipped when no collision", stateWithGoal(setupintent.GoalCredentialService), StepInstallName, false},
		{"review skipped on command_only", stateWithGoal(setupintent.GoalCommandOnly), StepReview, false},
	}
	for _, test := range cases {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := Applies(test.state, test.step); got != test.applies {
				t.Fatalf("Applies(%v) = %v, want %v", test.step, got, test.applies)
			}
		})
	}
}

func TestNextSkipsInapplicableSteps(t *testing.T) {
	t.Parallel()
	state := stateWithGoal(setupintent.GoalCommandOnly)
	if got := Next(state, StepGoal); got != StepDone {
		t.Fatalf("command-only Next(goal) = %v", got)
	}
	server := stateWithGoal(setupintent.GoalCredentialService)
	if got := Next(server, StepGoal); got != StepServiceLocation {
		t.Fatalf("server Next(goal) = %v", got)
	}
	// Providers step exists but agent location does not for server-only.
	if got := Next(server, StepProviders); got != StepReview {
		t.Fatalf("server Next(providers) = %v", got)
	}
}

func TestPreviousReachesEarlierApplicableStep(t *testing.T) {
	t.Parallel()
	state := stateWithGoal(setupintent.GoalCompleteLocal)
	state.Intent.Agent = &setupintent.Agent{Location: setupintent.AgentLocalAccount, Account: &setupintent.Account{Mode: setupintent.AccountCurrent}}
	if got := Previous(state, StepIsolationWarn); got != StepAccount {
		t.Fatalf("Previous(isolation_warning) = %v", got)
	}
	if got := Previous(state, StepAccount); got != StepAgentLocation {
		t.Fatalf("Previous(account) = %v", got)
	}
	if got := Previous(state, StepGoal); got != StepGoal {
		t.Fatalf("Previous(goal) = %v", got)
	}
}

func TestInvalidateAfterClearsDerivedAnswers(t *testing.T) {
	t.Parallel()
	state := State{
		Intent: setupintent.Intent{
			APIVersion:        setupintent.APIVersion,
			Goal:              setupintent.GoalCompleteLocal,
			CredentialService: &setupintent.CredentialService{Location: setupintent.ServiceNative, Providers: []string{"github"}},
			Agent:             &setupintent.Agent{Location: setupintent.AgentLocalAccount, ConnectionName: "bob", Account: &setupintent.Account{Mode: setupintent.AccountExisting, Name: "bob"}},
			Connection:        &setupintent.Connection{Transport: setupintent.TransportLocalSocket},
			Integrations:      []string{"openclaw"},
		},
		InstallationName: "custom",
	}
	InvalidateAfter(&state, StepProviders)
	if state.Intent.Agent != nil || state.Intent.Connection != nil || len(state.Intent.Integrations) != 0 || state.Intent.CredentialService == nil {
		t.Fatalf("invalidated intent = %#v", state.Intent)
	}
	InvalidateAfter(&state, StepGoal)
	if state.Intent.CredentialService != nil || state.InstallationName != "" {
		t.Fatalf("goal invalidation preserved derived answers: %#v", state)
	}
}

func stateWithGoal(goal setupintent.Goal) State {
	return State{Intent: setupintent.Intent{APIVersion: setupintent.APIVersion, Goal: goal}}
}
