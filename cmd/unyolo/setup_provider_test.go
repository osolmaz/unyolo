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
	"github.com/osolmaz/unyolo/deployment/session"
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

func TestChooseSessionKeepsExplicitProfileInExistingMode(t *testing.T) {
	state := t.TempDir()
	t.Setenv("XDG_STATE_HOME", state)
	prompter := &recordingPrompter{name: "existing-host", providerErr: errors.New("provider selection must not run")}
	store, err := setupSessionStore()
	if err != nil {
		t.Fatal(err)
	}
	value, err := chooseSession(t.Context(), prompter, store, setupOptions{
		New: true, Profile: "/tmp/existing-pack", ProviderOptions: testProviderOptions(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(prompter.calls, ","); got != "name" {
		t.Fatalf("explicit profile prompt order = %q", got)
	}
	if got := value.Answers["mode"]; len(got) != 1 || got[0] != "existing" || len(value.Answers["providers"]) != 0 {
		t.Fatalf("explicit profile answers = %+v", value.Answers)
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

func TestProviderOptionsLoadBesideInstalledExecutable(t *testing.T) {
	root := t.TempDir()
	providers := filepath.Join(root, "providers")
	if err := os.Mkdir(providers, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "unyolo"), []byte("binary"), 0o700); err != nil {
		t.Fatal(err)
	}
	catalog := `{"api_version":"unyolo.io/setup-provider/v1","id":"github","label":"GitHub","selected":true}`
	if err := os.WriteFile(filepath.Join(providers, "github.json"), []byte(catalog), 0o600); err != nil {
		t.Fatal(err)
	}
	options, releaseRoot, err := providerOptionsBesideExecutable(filepath.Join(root, "unyolo"))
	if err != nil || releaseRoot != root || len(options) != 1 || options[0].ID != "github" {
		t.Fatalf("installed provider options = %+v, %q, %v", options, releaseRoot, err)
	}
}

func TestChooseSetupProfileUsesSelectedVerifiedReleaseKit(t *testing.T) {
	root := t.TempDir()
	template := filepath.Join(root, "templates", "github+huggingface")
	artifacts := filepath.Join(root, "artifacts")
	for _, path := range []string{template, artifacts} {
		if err := os.MkdirAll(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	value := session.Session{Answers: map[string][]string{"providers": {"huggingface", "github"}}}
	path, releaseTemplate, artifactRoot, err := chooseSetupProfile(t.Context(), &recordingPrompter{}, setupOptions{
		ProviderOptions: testProviderOptions(), DeploymentKits: root, RuntimeArtifacts: artifacts,
	}, value)
	if err != nil || !releaseTemplate || path != template || artifactRoot != artifacts {
		t.Fatalf("selected release kit = %q, %v, %q, %v", path, releaseTemplate, artifactRoot, err)
	}
	if _, _, _, err := chooseSetupProfile(t.Context(), &recordingPrompter{}, setupOptions{
		ProviderOptions: testProviderOptions(), DeploymentKits: filepath.Join(root, "missing"), RuntimeArtifacts: artifacts,
	}, value); err == nil {
		t.Fatal("missing selected release kit was accepted")
	}
}

func TestProtectedWorkerStartsOnlyAfterActivation(t *testing.T) {
	var events []string
	worker := &fakeProtectedWorker{}
	sourceCommit := strings.Repeat("a", 40)
	started, err := prepareProtectedWorker(t.Context(), &recordingPrompter{}, func(context.Context) error {
		events = append(events, "activate")
		return nil
	}, sourceCommit, "verified-gh", func(_ context.Context, _ string, source, _ string, _ io.Writer) (protectedSetupWorker, error) {
		if source != sourceCommit {
			t.Fatalf("source commit = %q", source)
		}
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
	}, sourceCommit, "verified-gh", func(context.Context, string, string, string, io.Writer) (protectedSetupWorker, error) {
		events = append(events, "start")
		return worker, nil
	})
	if !errors.Is(err, activationErr) || strings.Join(events, ",") != "activate" {
		t.Fatalf("failed activation order = %v, %v", events, err)
	}
}

func TestPlanOnlyActivatesBeforeReportingFollowUpCommand(t *testing.T) {
	activated := false
	if err := finishPlanOnly(t.Context(), &confirmingPrompter{}, func(context.Context) error {
		activated = true
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !activated {
		t.Fatal("plan-only bootstrap did not activate the verified CLI")
	}
}

func TestSetupModeOptionsPreserveExplicitExistingProfile(t *testing.T) {
	options := setupModeOptions(setupOptions{ProviderOptions: testProviderOptions()})
	if len(options) != 2 || options[0].Value != "recommended" || options[1].Value != "custom" {
		t.Fatalf("bootstrap modes = %+v", options)
	}
	for _, setup := range []setupOptions{{}, {Profile: "/tmp/existing", ProviderOptions: testProviderOptions()}} {
		options = setupModeOptions(setup)
		if len(options) != 3 || options[2].Value != "existing" {
			t.Fatalf("existing profile modes = %+v", options)
		}
	}
}

func testProviderOptions() []provider.Option {
	return []provider.Option{
		{APIVersion: provider.APIVersion, ID: "github", Label: "GitHub", Selected: true},
		{APIVersion: provider.APIVersion, ID: "huggingface", Label: "Hugging Face", Selected: true},
	}
}

type confirmingPrompter struct{ recordingPrompter }

func (*confirmingPrompter) Confirm(context.Context, flow.ConfirmPrompt) (bool, error) {
	return true, nil
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
