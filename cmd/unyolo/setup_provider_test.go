package main

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/osolmaz/unyolo/deployment/flow"
	"github.com/osolmaz/unyolo/deployment/provider"
	"github.com/osolmaz/unyolo/internal/host/privilege"
)

func TestChooseSessionSelectsProvidersBeforeCreatingState(t *testing.T) {
	state := t.TempDir()
	t.Setenv("XDG_STATE_HOME", state)
	prompter := &recordingPrompter{providers: []string{"github", "huggingface"}, name: "test-host"}
	store, err := setupSessionStore()
	if err != nil {
		t.Fatal(err)
	}
	value, err := chooseSession(t.Context(), prompter, store, setupOptions{New: true, ProviderOptions: testProviderOptions()})
	if err != nil {
		t.Fatal(err)
	}
	if len(prompter.calls) < 2 || prompter.calls[0] != "providers" || prompter.calls[1] != "name" {
		t.Fatalf("prompt order = %v", prompter.calls)
	}
	if len(value.Answers["providers"]) != 2 || value.Answers["providers"][0] != "github" {
		t.Fatalf("providers = %v", value.Answers["providers"])
	}
	if _, err := store.Load(value.ID); err != nil {
		t.Fatalf("saved session: %v", err)
	}
}

func TestProviderCancellationLeavesNoSetupState(t *testing.T) {
	state := t.TempDir()
	t.Setenv("XDG_STATE_HOME", state)
	prompter := &recordingPrompter{providerErr: flow.CancelledError{}}
	store, err := setupSessionStore()
	if err != nil {
		t.Fatal(err)
	}
	_, err = chooseSession(t.Context(), prompter, store, setupOptions{New: true, ProviderOptions: testProviderOptions()})
	var cancelled flow.CancelledError
	if !errors.As(err, &cancelled) {
		t.Fatalf("cancellation = %v", err)
	}
	entries, readErr := os.ReadDir(filepath.Join(state, "unyolo", "setup"))
	if readErr == nil && len(entries) != 0 {
		t.Fatalf("setup state after cancellation = %v", entries)
	}
	if readErr != nil && !errors.Is(readErr, os.ErrNotExist) {
		t.Fatal(readErr)
	}
}

func TestProtectedWorkerStartsOnlyAfterActivation(t *testing.T) {
	var events []string
	worker := &fakeProtectedWorker{}
	started, err := prepareProtectedWorker(t.Context(), &recordingPrompter{}, func(context.Context) error {
		events = append(events, "activate")
		return nil
	}, func(context.Context, string, io.Writer) (protectedSetupWorker, error) {
		events = append(events, "start")
		return worker, nil
	})
	if err != nil || started != worker || strings.Join(events, ",") != "activate,start" {
		t.Fatalf("protected order = %v, %v", events, err)
	}

	events = nil
	activationErr := errors.New("activation failed")
	_, err = prepareProtectedWorker(t.Context(), &recordingPrompter{}, func(context.Context) error {
		events = append(events, "activate")
		return activationErr
	}, func(context.Context, string, io.Writer) (protectedSetupWorker, error) {
		events = append(events, "start")
		return worker, nil
	})
	if !errors.Is(err, activationErr) || strings.Join(events, ",") != "activate" {
		t.Fatalf("failed activation order = %v, %v", events, err)
	}
}

func TestSetupModeOptionsHideExistingForBootstrapSelection(t *testing.T) {
	options := setupModeOptions(setupOptions{ProviderOptions: testProviderOptions()})
	if len(options) != 2 || options[0].Value != "recommended" || options[1].Value != "custom" {
		t.Fatalf("bootstrap modes = %+v", options)
	}
	options = setupModeOptions(setupOptions{})
	if len(options) != 3 || options[2].Value != "existing" {
		t.Fatalf("ordinary modes = %+v", options)
	}
}

func testProviderOptions() []provider.Option {
	return []provider.Option{
		{APIVersion: provider.APIVersion, ID: "github", Label: "GitHub", Selected: true},
		{APIVersion: provider.APIVersion, ID: "huggingface", Label: "Hugging Face", Selected: true},
	}
}

type fakeProtectedWorker struct{}

func (*fakeProtectedWorker) Plan(string) (privilege.Response, error) {
	return privilege.Response{}, nil
}
func (*fakeProtectedWorker) Apply(string, map[string][]byte) (privilege.Result, error) {
	return privilege.Result{}, nil
}
func (*fakeProtectedWorker) Cancel() error { return nil }
func (*fakeProtectedWorker) Close() error  { return nil }

type recordingPrompter struct {
	providers   []string
	providerErr error
	name        string
	calls       []string
}

func (prompter *recordingPrompter) Intro(context.Context, string) error        { return nil }
func (prompter *recordingPrompter) Outro(context.Context, string) error        { return nil }
func (prompter *recordingPrompter) Note(context.Context, string, string) error { return nil }
func (prompter *recordingPrompter) Select(context.Context, flow.SelectPrompt) (string, error) {
	return "recommended", nil
}
func (prompter *recordingPrompter) MultiSelect(_ context.Context, _ flow.SelectPrompt) ([]string, error) {
	prompter.calls = append(prompter.calls, "providers")
	return prompter.providers, prompter.providerErr
}
func (prompter *recordingPrompter) Text(_ context.Context, _ flow.Prompt) (string, error) {
	prompter.calls = append(prompter.calls, "name")
	return prompter.name, nil
}
func (prompter *recordingPrompter) Secret(context.Context, flow.Prompt) ([]byte, error) {
	return nil, errors.New("unexpected secret prompt")
}
func (prompter *recordingPrompter) Confirm(context.Context, flow.ConfirmPrompt) (bool, error) {
	return false, errors.New("unexpected confirm prompt")
}
func (prompter *recordingPrompter) DeviceCode(context.Context, flow.DeviceCodePrompt) error {
	return errors.New("unexpected device code prompt")
}
func (prompter *recordingPrompter) OpenURL(context.Context, string) error {
	return errors.New("unexpected URL prompt")
}
func (prompter *recordingPrompter) Progress(string) flow.Progress { return testProgress{} }
func (prompter *recordingPrompter) Close() error                  { return nil }

type testProgress struct{}

func (testProgress) Update(string) {}
func (testProgress) Stop(string)   {}
func (testProgress) Fail(string)   {}
