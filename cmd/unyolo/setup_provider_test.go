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

func TestChooseSessionUsesDefaultWithoutNamePrompt(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	store, err := setupSessionStore()
	if err != nil {
		t.Fatal(err)
	}
	value, err := chooseSession(t.Context(), &recordingPrompter{}, store, setupOptions{New: true})
	if err != nil {
		t.Fatal(err)
	}
	if value.InstallationName != "default" || value.CurrentStep != "goal" {
		t.Fatalf("session = %#v", value)
	}
	if _, err := store.Load(value.ID); err != nil {
		t.Fatal(err)
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

func TestSelectedReleaseTemplateUsesProviderSet(t *testing.T) {
	root := t.TempDir()
	template := filepath.Join(root, "templates", "github+huggingface")
	artifacts := filepath.Join(root, "artifacts")
	for _, path := range []string{template, artifacts} {
		if err := os.MkdirAll(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	selected, artifactRoot, err := selectedReleaseTemplate(setupOptions{ProviderOptions: testProviderOptions(), DeploymentKits: root, RuntimeArtifacts: artifacts}, []string{"huggingface", "github"})
	if err != nil || selected != template || artifactRoot != artifacts {
		t.Fatalf("selected setup source = %q, %q, %v", selected, artifactRoot, err)
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
}

func TestPlanOnlyActivatesBeforeCompletion(t *testing.T) {
	activated := false
	if err := finishPlanOnly(t.Context(), &confirmingPrompter{}, func(context.Context) error {
		activated = true
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !activated {
		t.Fatal("plan-only path did not install the command")
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
func (*fakeProtectedWorker) PlanInstallation(string, string) (privilege.Response, error) {
	return privilege.Response{}, nil
}
func (*fakeProtectedWorker) PlanRemoval(bool) (privilege.Response, error) {
	return privilege.Response{}, nil
}
func (*fakeProtectedWorker) Apply(string, map[string][]byte) (privilege.Result, error) {
	return privilege.Result{}, nil
}
func (*fakeProtectedWorker) ApplyRemoval() (privilege.Result, error) {
	return privilege.Result{}, nil
}
func (*fakeProtectedWorker) Cancel() error { return nil }
func (*fakeProtectedWorker) Close() error  { return nil }

type recordingPrompter struct{}

func (*recordingPrompter) Intro(context.Context, string) error        { return nil }
func (*recordingPrompter) Outro(context.Context, string) error        { return nil }
func (*recordingPrompter) Note(context.Context, string, string) error { return nil }
func (*recordingPrompter) Select(context.Context, flow.SelectPrompt) (string, error) {
	return "", errors.New("unexpected select prompt")
}
func (*recordingPrompter) MultiSelect(context.Context, flow.SelectPrompt) ([]string, error) {
	return nil, errors.New("unexpected multi-select prompt")
}
func (*recordingPrompter) Text(context.Context, flow.Prompt) (string, error) {
	return "", errors.New("unexpected text prompt")
}
func (*recordingPrompter) Secret(context.Context, flow.Prompt) ([]byte, error) {
	return nil, errors.New("unexpected secret prompt")
}
func (*recordingPrompter) Confirm(context.Context, flow.ConfirmPrompt) (bool, error) {
	return false, errors.New("unexpected confirm prompt")
}
func (*recordingPrompter) DeviceCode(context.Context, flow.DeviceCodePrompt) error {
	return errors.New("unexpected device code prompt")
}
func (*recordingPrompter) OpenURL(context.Context, string) error {
	return errors.New("unexpected URL prompt")
}
func (*recordingPrompter) Progress(string) flow.Progress { return testProgress{} }
func (*recordingPrompter) Close() error                  { return nil }

type testProgress struct{}

func (testProgress) Update(string) {}
func (testProgress) Stop(string)   {}
func (testProgress) Fail(string)   {}
