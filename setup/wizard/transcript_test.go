package wizard

import (
	"context"
	"strings"
	"testing"

	setupcopy "github.com/osolmaz/unyolo/setup/copy"
	setupintent "github.com/osolmaz/unyolo/setup/intent"
)

// TestNormalTranscriptContainsNoForbiddenTerms drives the coordinator with
// every supported goal-and-target combination and verifies the accumulated
// transcript never mentions internal deployment names.
func TestNormalTranscriptContainsNoForbiddenTerms(t *testing.T) {
	scripts := []struct {
		name    string
		answers []scriptedAnswer
		options Options
	}{
		{
			name: "command_only",
			answers: []scriptedAnswer{
				{kind: "select", stringValue: "command_only"},
			},
			options: Options{Capabilities: nativeCompleteSnapshot()},
		},
		{
			name: "credential_service_native",
			answers: []scriptedAnswer{
				{kind: "select", stringValue: "credential_service"},
				{kind: "select", stringValue: "native"},
				{kind: "multiselect", stringSlice: []string{"github", "huggingface"}},
				{kind: "confirm", boolValue: true},
			},
			options: Options{
				Capabilities: nativeCompleteSnapshot(),
				Providers:    []ProviderChoice{{Value: "github", Label: "GitHub"}, {Value: "huggingface", Label: "Hugging Face"}},
			},
		},
		{
			name: "complete_local_existing_account",
			answers: []scriptedAnswer{
				{kind: "select", stringValue: "complete_local"},
				{kind: "select", stringValue: "native"},
				{kind: "multiselect", stringSlice: []string{"github"}},
				{kind: "select", stringValue: "existing"},
				{kind: "select", stringValue: "bob"},
				{kind: "confirm", boolValue: true},
			},
			options: Options{
				Capabilities: nativeCompleteSnapshot(),
				Providers:    []ProviderChoice{{Value: "github", Label: "GitHub"}},
				Accounts:     staticAccounts{items: []Account{{Name: "bob", Home: "/home/bob"}}},
			},
		},
		{
			name: "complete_local_current_account_with_warning",
			answers: []scriptedAnswer{
				{kind: "select", stringValue: "complete_local"},
				{kind: "select", stringValue: "native"},
				{kind: "multiselect", stringSlice: []string{"github"}},
				{kind: "select", stringValue: "current"},
				{kind: "confirm", boolValue: true, expectMessage: setupcopy.Screens[setupcopy.ScreenIsolationWarn].Question},
				{kind: "confirm", boolValue: true},
			},
			options: Options{
				Capabilities:   nativeCompleteSnapshot(),
				Providers:      []ProviderChoice{{Value: "github", Label: "GitHub"}},
				CurrentAccount: "onur",
			},
		},
	}
	for _, script := range scripts {
		script := script
		t.Run(script.name, func(t *testing.T) {
			prompter := &scriptedPrompter{t: t, answers: script.answers}
			options := script.options
			options.Prompter = prompter
			coordinator := New(options)
			if _, err := coordinator.Run(context.Background()); err != nil {
				t.Fatal(err)
			}
			transcript := strings.ToLower(prompter.transcript.String())
			for _, forbidden := range setupcopy.ForbiddenNormalTerms {
				if strings.Contains(transcript, strings.ToLower(forbidden)) {
					t.Fatalf("transcript contains forbidden term %q: %s", forbidden, prompter.transcript.String())
				}
			}
		})
	}
}

func TestReviewSummaryReportsReducedIsolationForCurrentAccount(t *testing.T) {
	summary := ReviewSummary(State{Intent: setupintent.Intent{
		APIVersion: setupintent.APIVersion, Goal: setupintent.GoalCompleteLocal,
		CredentialService: &setupintent.CredentialService{Location: setupintent.ServiceNative, Providers: []string{"github"}},
		Agent: &setupintent.Agent{
			Location: setupintent.AgentLocalAccount, ConnectionName: "onur",
			Account: &setupintent.Account{Mode: setupintent.AccountCurrent},
		},
	}})
	if !strings.Contains(strings.ToLower(summary), "reduced") {
		t.Fatalf("review summary missing reduced-isolation label: %s", summary)
	}
}
