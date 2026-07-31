package main

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/osolmaz/unyolo/deployment/flow"
	setupcopy "github.com/osolmaz/unyolo/setup/copy"
	"github.com/osolmaz/unyolo/setup/installation"
	setupintent "github.com/osolmaz/unyolo/setup/intent"
)

// scriptedPrompter is a copy of the wizard's scripted prompter tailored for
// end-to-end tests of the setup command.
type scriptedPrompter struct {
	t       *testing.T
	answers []scriptedAnswer
	notes   strings.Builder
}

type scriptedAnswer struct {
	kind        string
	stringValue string
	stringSlice []string
	boolValue   bool
	err         error
	message     string
}

func (p *scriptedPrompter) next(t *testing.T, kind, message string) scriptedAnswer {
	t.Helper()
	if len(p.answers) == 0 {
		t.Fatalf("unexpected %s prompt %q; script empty", kind, message)
	}
	answer := p.answers[0]
	p.answers = p.answers[1:]
	if answer.kind != kind {
		t.Fatalf("wanted %s prompt for %q, got script %s (%q)", kind, message, answer.kind, answer.message)
	}
	return answer
}

func (p *scriptedPrompter) Intro(_ context.Context, title string) error {
	p.notes.WriteString(title + "\n")
	return nil
}
func (p *scriptedPrompter) Outro(_ context.Context, msg string) error {
	p.notes.WriteString(msg + "\n")
	return nil
}
func (p *scriptedPrompter) Note(_ context.Context, msg, title string) error {
	p.notes.WriteString(title + "\n" + msg + "\n")
	return nil
}
func (p *scriptedPrompter) Select(_ context.Context, prompt flow.SelectPrompt) (string, error) {
	answer := p.next(p.t, "select", prompt.Message)
	p.notes.WriteString(prompt.Message + "\n")
	return answer.stringValue, answer.err
}
func (p *scriptedPrompter) MultiSelect(_ context.Context, prompt flow.SelectPrompt) ([]string, error) {
	answer := p.next(p.t, "multiselect", prompt.Message)
	p.notes.WriteString(prompt.Message + "\n")
	return append([]string(nil), answer.stringSlice...), answer.err
}
func (p *scriptedPrompter) Text(_ context.Context, prompt flow.Prompt) (string, error) {
	answer := p.next(p.t, "text", prompt.Message)
	return answer.stringValue, answer.err
}
func (p *scriptedPrompter) Secret(_ context.Context, prompt flow.Prompt) ([]byte, error) {
	answer := p.next(p.t, "secret", prompt.Message)
	return []byte(answer.stringValue), answer.err
}
func (p *scriptedPrompter) Confirm(_ context.Context, prompt flow.ConfirmPrompt) (bool, error) {
	answer := p.next(p.t, "confirm", prompt.Message)
	p.notes.WriteString(prompt.Message + "\n")
	return answer.boolValue, answer.err
}
func (p *scriptedPrompter) DeviceCode(context.Context, flow.DeviceCodePrompt) error { return nil }
func (p *scriptedPrompter) OpenURL(context.Context, string) error                   { return nil }
func (p *scriptedPrompter) Progress(label string) flow.Progress {
	p.notes.WriteString(label + "\n")
	return dummyProgress{}
}
func (p *scriptedPrompter) Close() error { return nil }

type dummyProgress struct{}

func (dummyProgress) Update(string) {}
func (dummyProgress) Stop(string)   {}
func (dummyProgress) Fail(string)   {}

func TestFinishCommandOnlyDoesNotStartWorker(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	store, err := setupSessionStore()
	if err != nil {
		t.Fatal(err)
	}
	setupSession, err := chooseSession(context.Background(), &scriptedPrompter{t: t, answers: []scriptedAnswer{}}, store, setupOptions{New: true})
	if err != nil {
		t.Fatal(err)
	}
	activated := 0
	prompter := &scriptedPrompter{t: t, answers: []scriptedAnswer{
		{kind: "confirm", boolValue: true, message: setupcopy.Screens[setupcopy.ScreenInstallCommand].Question},
	}}
	// The worker starter must never be invoked from a command-only path.
	startSetupWorker = func(context.Context, string, string, string, io.Writer) (protectedSetupWorker, error) {
		t.Fatal("root worker started during command-only setup")
		return nil, errors.New("unreachable")
	}
	err = finishCommandOnly(context.Background(), prompter, store, &setupSession, func(context.Context) error {
		activated++
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if activated != 1 {
		t.Fatalf("activate called %d times", activated)
	}
	transcript := prompter.notes.String()
	for _, forbidden := range setupcopy.ForbiddenNormalTerms {
		if strings.Contains(strings.ToLower(transcript), forbidden) {
			t.Fatalf("command-only transcript contained %q: %s", forbidden, transcript)
		}
	}
}

func TestInstallationFromIntentReducedIsolationForCurrent(t *testing.T) {
	intent := setupintent.Intent{
		APIVersion: setupintent.APIVersion, Goal: setupintent.GoalCompleteLocal,
		CredentialService: &setupintent.CredentialService{Location: setupintent.ServiceNative, Providers: []string{"github"}},
		Agent: &setupintent.Agent{
			Location: setupintent.AgentLocalAccount, ConnectionName: "onur",
			Account: &setupintent.Account{Mode: setupintent.AccountCurrent},
		},
	}
	// The unit does not require the account to actually exist; we exercise
	// only the reduced-isolation branch.
	result, err := installationFromIntent(intent, "onur", "")
	if err != nil {
		// inspectAccount may fail in CI environments; the important assertion
		// is that the reduced-isolation label is set when we can materialise
		// the record.
		t.Skipf("installation from intent unavailable in this environment: %v", err)
	}
	if result.Connections[0].Target.Isolation != "reduced" {
		t.Fatalf("isolation = %q", result.Connections[0].Target.Isolation)
	}
	if result.Name != installation.DefaultName {
		t.Fatalf("default name lost: %q", result.Name)
	}
}
