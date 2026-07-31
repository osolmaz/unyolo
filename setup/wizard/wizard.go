// Package wizard defines deterministic guided-setup choices and invalidation.
package wizard

import (
	"slices"

	"github.com/osolmaz/unyolo/setup/capability"
	setupcopy "github.com/osolmaz/unyolo/setup/copy"
	setupintent "github.com/osolmaz/unyolo/setup/intent"
)

type Choice struct {
	Value string
	Label string
	Hint  string
}

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

func AgentLocationChoices(capabilities capability.Snapshot) []Choice {
	var result []Choice
	if capabilities.Has(capability.FeatureLocalAccounts) {
		result = append(result,
			Choice{Value: "managed", Label: "Create a restricted account", Hint: "Recommended for a local agent"},
			Choice{Value: "existing", Label: "Use an existing account", Hint: "Connect an account that already exists"},
			Choice{Value: "current", Label: "Use my account", Hint: "Works, but provides less isolation"},
		)
	}
	if capabilities.Has(capability.FeatureDockerAgent) {
		result = append(result, Choice{Value: "container", Label: "Use a Docker container", Hint: "Connect one Compose service"})
	}
	if capabilities.Has(capability.FeatureRemotePairing) {
		result = append(result, Choice{Value: "remote", Label: "Use another computer", Hint: "Create a short-lived pairing invitation"})
	}
	return result
}

// InvalidateAfter clears answers derived from the named step.
func InvalidateAfter(value *setupintent.Intent, step string) {
	switch step {
	case "goal":
		value.CredentialService, value.Agent, value.Connection, value.Integrations = nil, nil, nil, nil
	case "service-location":
		if value.CredentialService != nil {
			value.CredentialService.Providers = nil
		}
		value.Agent, value.Connection, value.Integrations = nil, nil, nil
	case "providers":
		value.Agent, value.Connection, value.Integrations = nil, nil, nil
	case "agent-location", "account":
		value.Connection, value.Integrations = nil, nil
	case "connection":
		value.Integrations = nil
	}
}

func HasChoice(values []Choice, value string) bool {
	return slices.ContainsFunc(values, func(choice Choice) bool { return choice.Value == value })
}
