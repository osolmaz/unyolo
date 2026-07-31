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

func TestInvalidateAfterClearsDerivedAnswers(t *testing.T) {
	t.Parallel()
	value := setupintent.Intent{
		APIVersion: setupintent.APIVersion, Goal: setupintent.GoalCompleteLocal,
		CredentialService: &setupintent.CredentialService{Location: setupintent.ServiceNative, Providers: []string{"github"}},
		Agent:             &setupintent.Agent{Location: setupintent.AgentLocalAccount, ConnectionName: "bob", Account: &setupintent.Account{Mode: setupintent.AccountExisting, Name: "bob"}},
		Connection:        &setupintent.Connection{Transport: setupintent.TransportLocalSocket}, Integrations: []string{"openclaw"},
	}
	InvalidateAfter(&value, "providers")
	if value.Agent != nil || value.Connection != nil || len(value.Integrations) != 0 || value.CredentialService == nil {
		t.Fatalf("invalidated intent = %#v", value)
	}
}
