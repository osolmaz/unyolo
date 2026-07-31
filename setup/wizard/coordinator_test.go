package wizard

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/osolmaz/unyolo/deployment/flow"
	"github.com/osolmaz/unyolo/setup/capability"
	setupcopy "github.com/osolmaz/unyolo/setup/copy"
	"github.com/osolmaz/unyolo/setup/installation"
	setupintent "github.com/osolmaz/unyolo/setup/intent"
)

// scriptedPrompter drives the coordinator with an ordered script of
// prompter results. Each call to a prompt method consumes the next entry.
type scriptedPrompter struct {
	t          *testing.T
	answers    []scriptedAnswer
	transcript strings.Builder
}

type scriptedAnswer struct {
	kind          string
	stringValue   string
	stringSlice   []string
	boolValue     bool
	err           error
	expectMessage string
}

func (p *scriptedPrompter) next(t *testing.T, kind, message string) scriptedAnswer {
	t.Helper()
	if len(p.answers) == 0 {
		t.Fatalf("unexpected %s prompt %q; script empty", kind, message)
	}
	answer := p.answers[0]
	p.answers = p.answers[1:]
	if answer.kind != kind {
		t.Fatalf("wanted %s prompt for %q, got script %s", kind, message, answer.kind)
	}
	if answer.expectMessage != "" && !strings.Contains(message, answer.expectMessage) {
		t.Fatalf("prompt message %q does not contain %q", message, answer.expectMessage)
	}
	return answer
}

func (p *scriptedPrompter) Intro(_ context.Context, title string) error {
	p.transcript.WriteString(title + "\n")
	return nil
}
func (p *scriptedPrompter) Outro(_ context.Context, message string) error {
	p.transcript.WriteString(message + "\n")
	return nil
}
func (p *scriptedPrompter) Note(_ context.Context, message, title string) error {
	if title != "" {
		p.transcript.WriteString(title + "\n")
	}
	p.transcript.WriteString(message + "\n")
	return nil
}
func (p *scriptedPrompter) Select(_ context.Context, prompt flow.SelectPrompt) (string, error) {
	answer := p.next(p.t, "select", prompt.Message)
	p.transcript.WriteString(prompt.Message + " -> " + answer.stringValue + "\n")
	return answer.stringValue, answer.err
}
func (p *scriptedPrompter) MultiSelect(_ context.Context, prompt flow.SelectPrompt) ([]string, error) {
	answer := p.next(p.t, "multiselect", prompt.Message)
	p.transcript.WriteString(prompt.Message + " -> " + strings.Join(answer.stringSlice, ",") + "\n")
	return append([]string(nil), answer.stringSlice...), answer.err
}
func (p *scriptedPrompter) Text(_ context.Context, prompt flow.Prompt) (string, error) {
	answer := p.next(p.t, "text", prompt.Message)
	p.transcript.WriteString(prompt.Message + " -> " + answer.stringValue + "\n")
	return answer.stringValue, answer.err
}
func (p *scriptedPrompter) Secret(_ context.Context, prompt flow.Prompt) ([]byte, error) {
	answer := p.next(p.t, "secret", prompt.Message)
	return []byte(answer.stringValue), answer.err
}
func (p *scriptedPrompter) Confirm(_ context.Context, prompt flow.ConfirmPrompt) (bool, error) {
	answer := p.next(p.t, "confirm", prompt.Message)
	label := "no"
	if answer.boolValue {
		label = "yes"
	}
	p.transcript.WriteString(prompt.Message + " -> " + label + "\n")
	return answer.boolValue, answer.err
}
func (p *scriptedPrompter) DeviceCode(context.Context, flow.DeviceCodePrompt) error { return nil }
func (p *scriptedPrompter) OpenURL(context.Context, string) error                   { return nil }
func (p *scriptedPrompter) Progress(string) flow.Progress                           { return dummyProgress{} }
func (p *scriptedPrompter) Close() error                                            { return nil }

type dummyProgress struct{}

func (dummyProgress) Update(string) {}
func (dummyProgress) Stop(string)   {}
func (dummyProgress) Fail(string)   {}

type recordingPersister struct {
	states []State
	steps  []Step
}

func (r *recordingPersister) Save(state State, step Step) error {
	r.states = append(r.states, state)
	r.steps = append(r.steps, step)
	return nil
}

type staticAccounts struct{ items []Account }

func (s staticAccounts) List(context.Context) ([]Account, error) {
	return append([]Account(nil), s.items...), nil
}

func nativeCompleteSnapshot() capability.Snapshot {
	return capability.Snapshot{Features: []capability.Feature{capability.FeatureNativeService, capability.FeatureLocalSocket, capability.FeatureLocalAccounts}}
}

func TestCoordinatorCompleteLocalHappyPath(t *testing.T) {
	prompter := &scriptedPrompter{t: t, answers: []scriptedAnswer{
		{kind: "select", stringValue: "complete_local", expectMessage: setupcopy.Screens[setupcopy.ScreenGoal].Question},
		{kind: "select", stringValue: "native", expectMessage: setupcopy.Screens[setupcopy.ScreenServiceLocation].Question},
		{kind: "multiselect", stringSlice: []string{"github"}, expectMessage: setupcopy.Screens[setupcopy.ScreenProviders].Question},
		{kind: "select", stringValue: "managed", expectMessage: setupcopy.Screens[setupcopy.ScreenAgentLocation].Question},
		{kind: "confirm", boolValue: true, expectMessage: "Ready to continue?"},
	}}
	persister := &recordingPersister{}
	coordinator := New(Options{
		Prompter:     prompter,
		Persist:      persister,
		Capabilities: nativeCompleteSnapshot(),
		Providers:    []ProviderChoice{{Value: "github", Label: "GitHub", Selected: true}, {Value: "huggingface", Label: "Hugging Face", Selected: true}},
		Initial:      State{Intent: setupintent.Intent{APIVersion: setupintent.APIVersion}},
	})
	result, err := coordinator.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if result.Intent.Goal != setupintent.GoalCompleteLocal {
		t.Fatalf("goal = %q", result.Intent.Goal)
	}
	if result.Intent.CredentialService == nil || result.Intent.CredentialService.Providers[0] != "github" {
		t.Fatalf("credential service = %#v", result.Intent.CredentialService)
	}
	if result.Intent.Agent == nil || result.Intent.Agent.Account.Mode != setupintent.AccountManaged {
		t.Fatalf("agent = %#v", result.Intent.Agent)
	}
	if result.InstallationName != installation.DefaultName {
		t.Fatalf("installation name = %q", result.InstallationName)
	}
	if len(persister.steps) == 0 || persister.steps[len(persister.steps)-1] != StepDone {
		t.Fatalf("last step = %v", persister.steps)
	}
	transcript := prompter.transcript.String()
	for _, forbidden := range setupcopy.ForbiddenNormalTerms {
		if strings.Contains(strings.ToLower(transcript), forbidden) {
			t.Fatalf("transcript contains forbidden term %q: %s", forbidden, transcript)
		}
	}
}

func TestCoordinatorBackClearsDerivedAnswers(t *testing.T) {
	prompter := &scriptedPrompter{t: t, answers: []scriptedAnswer{
		{kind: "select", stringValue: "complete_local"},
		{kind: "select", stringValue: "native"},
		// User goes back from providers.
		{kind: "multiselect", err: flow.NavigationError{Direction: "back"}},
		// Back should now land the coordinator on service location.
		{kind: "select", stringValue: "native"},
		// Re-answer providers.
		{kind: "multiselect", stringSlice: []string{"github", "huggingface"}},
		{kind: "select", stringValue: "existing"},
		{kind: "select", stringValue: "bob"},
		{kind: "confirm", boolValue: true},
	}}
	coordinator := New(Options{
		Prompter:     prompter,
		Capabilities: nativeCompleteSnapshot(),
		Providers:    []ProviderChoice{{Value: "github", Label: "GitHub"}, {Value: "huggingface", Label: "Hugging Face"}},
		Accounts:     staticAccounts{items: []Account{{Name: "bob", Home: "/home/bob"}}},
	})
	result, err := coordinator.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Intent.CredentialService.Providers) != 2 {
		t.Fatalf("providers = %v", result.Intent.CredentialService.Providers)
	}
	if result.Intent.Agent.Account.Name != "bob" {
		t.Fatalf("agent = %#v", result.Intent.Agent)
	}
}

func TestCoordinatorAsksInstallationNameOnCollision(t *testing.T) {
	prompter := &scriptedPrompter{t: t, answers: []scriptedAnswer{
		{kind: "select", stringValue: "credential_service"},
		{kind: "select", stringValue: "native"},
		{kind: "multiselect", stringSlice: []string{"github"}},
		{kind: "text", stringValue: "second"},
		{kind: "confirm", boolValue: true},
	}}
	coordinator := New(Options{
		Prompter:           prompter,
		Capabilities:       nativeCompleteSnapshot(),
		Providers:          []ProviderChoice{{Value: "github", Label: "GitHub"}},
		InstallationExists: true,
	})
	result, err := coordinator.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if result.InstallationName != "second" {
		t.Fatalf("installation name = %q", result.InstallationName)
	}
}

func TestCoordinatorReviewEditRestartsAtGoal(t *testing.T) {
	prompter := &scriptedPrompter{t: t, answers: []scriptedAnswer{
		{kind: "select", stringValue: "credential_service"},
		{kind: "select", stringValue: "native"},
		{kind: "multiselect", stringSlice: []string{"github"}},
		// Edit at review.
		{kind: "confirm", boolValue: false},
		{kind: "select", stringValue: "credential_service"},
		{kind: "select", stringValue: "native"},
		{kind: "multiselect", stringSlice: []string{"github", "huggingface"}},
		{kind: "confirm", boolValue: true},
	}}
	coordinator := New(Options{
		Prompter:     prompter,
		Capabilities: nativeCompleteSnapshot(),
		Providers:    []ProviderChoice{{Value: "github", Label: "GitHub"}, {Value: "huggingface", Label: "Hugging Face"}},
	})
	result, err := coordinator.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !result.Edited {
		t.Fatal("Edited flag was not set")
	}
	if len(result.Intent.CredentialService.Providers) != 2 {
		t.Fatalf("providers = %v", result.Intent.CredentialService.Providers)
	}
}

func TestCoordinatorCommandOnlyReturnsWithoutReview(t *testing.T) {
	prompter := &scriptedPrompter{t: t, answers: []scriptedAnswer{
		{kind: "select", stringValue: "command_only"},
	}}
	coordinator := New(Options{Prompter: prompter, Capabilities: capability.Snapshot{}})
	result, err := coordinator.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if result.Intent.Goal != setupintent.GoalCommandOnly {
		t.Fatalf("goal = %q", result.Intent.Goal)
	}
	if result.InstallationName != installation.DefaultName {
		t.Fatalf("installation name = %q", result.InstallationName)
	}
	if len(prompter.answers) != 0 {
		t.Fatalf("unused prompter answers: %#v", prompter.answers)
	}
}

func TestCoordinatorIsolationWarningCancelsToAgentLocation(t *testing.T) {
	prompter := &scriptedPrompter{t: t, answers: []scriptedAnswer{
		{kind: "select", stringValue: "agent_connection"},
		{kind: "select", stringValue: "current"},
		{kind: "confirm", boolValue: false, expectMessage: setupcopy.Screens[setupcopy.ScreenIsolationWarn].Question},
		{kind: "select", stringValue: "managed"},
		{kind: "confirm", boolValue: true, expectMessage: "Ready to continue?"},
	}}
	coordinator := New(Options{
		Prompter:       prompter,
		Capabilities:   nativeCompleteSnapshot(),
		CurrentAccount: "onur",
	})
	result, err := coordinator.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if result.Intent.Agent.Account.Mode != setupintent.AccountManaged {
		t.Fatalf("agent mode = %q", result.Intent.Agent.Account.Mode)
	}
}

func TestReviewSummaryOmitsForbiddenInternalTerms(t *testing.T) {
	state := State{Intent: setupintent.Intent{
		APIVersion: setupintent.APIVersion, Goal: setupintent.GoalCompleteLocal,
		CredentialService: &setupintent.CredentialService{Location: setupintent.ServiceNative, Providers: []string{"github"}},
		Agent:             &setupintent.Agent{Location: setupintent.AgentLocalAccount, ConnectionName: "bob", Account: &setupintent.Account{Mode: setupintent.AccountExisting, Name: "bob"}},
	}}
	summary := ReviewSummary(state)
	for _, forbidden := range setupcopy.ForbiddenNormalTerms {
		if strings.Contains(strings.ToLower(summary), forbidden) {
			t.Fatalf("review contains forbidden term %q: %s", forbidden, summary)
		}
	}
	if !strings.Contains(summary, "bob") {
		t.Fatalf("summary missing account name: %s", summary)
	}
}

func TestCoordinatorReturnsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	coordinator := New(Options{
		Prompter:     &scriptedPrompter{t: t},
		Capabilities: nativeCompleteSnapshot(),
	})
	_, err := coordinator.Run(ctx)
	var cancelled flow.CancelledError
	if !errors.As(err, &cancelled) {
		t.Fatalf("expected cancellation, got %v", err)
	}
}
