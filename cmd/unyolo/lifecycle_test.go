package main

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/osolmaz/unyolo/deployment/provider"
	"github.com/osolmaz/unyolo/deployment/session"
	"github.com/osolmaz/unyolo/setup/installation"
	setupintent "github.com/osolmaz/unyolo/setup/intent"
)

func installationWithProviders() installation.Installation {
	return installation.Installation{
		APIVersion: installation.APIVersion, Name: installation.DefaultName,
		CredentialService: setupintent.CredentialService{
			Location: setupintent.ServiceNative, Providers: []string{"github", "huggingface"},
		},
		Approvers: []installation.Approver{{ID: "onur", Account: "onur"}},
	}
}

func TestIntentFromInstallationPreservesEditableChoices(t *testing.T) {
	t.Parallel()
	value := installationWithProviders()
	value.Connections = []installation.Connection{{
		ID: "bob", ClientID: "bob", Providers: []string{"github", "huggingface"}, Integrations: []string{"openclaw"},
		Target: installation.Target{Kind: installation.TargetLocalAccount, Isolation: "separate", AccountMode: setupintent.AccountExisting, Account: "bob", Home: "/home/bob", Shell: "/bin/bash", UID: 1001, GID: 1001},
	}}
	intent, err := intentFromInstallation(value)
	if err != nil {
		t.Fatal(err)
	}
	if intent.Goal != setupintent.GoalCompleteLocal || intent.Agent == nil || intent.Agent.Account == nil ||
		intent.Agent.Account.Name != "bob" || len(intent.Integrations) != 1 || len(intent.CredentialService.Providers) != 2 {
		t.Fatalf("reconfigure intent = %#v", intent)
	}
}

func TestIntentFromInstallationRejectsAmbiguousMultiConnectionEdit(t *testing.T) {
	t.Parallel()
	value := installationWithProviders()
	connection := installation.Connection{
		ID: "bob", ClientID: "bob", Providers: []string{"github"},
		Target: installation.Target{Kind: installation.TargetLocalAccount, Isolation: "separate", AccountMode: setupintent.AccountExisting, Account: "bob", Home: "/home/bob", Shell: "/bin/bash", UID: 1001, GID: 1001},
	}
	value.Connections = []installation.Connection{connection, connection}
	value.Connections[1].ID, value.Connections[1].ClientID = "alice", "alice"
	if _, err := intentFromInstallation(value); err == nil {
		t.Fatal("multi-connection reconfigure was accepted by a single-connection editor")
	}
}

func TestEditInstallationChangesProvidersApproversAndConnections(t *testing.T) {
	t.Parallel()
	value := installationWithProviders()
	value.Connections = []installation.Connection{{
		ID: "bob", ClientID: "bob", Providers: []string{"github", "huggingface"},
		Target: installation.Target{Kind: installation.TargetLocalAccount, Isolation: "separate", AccountMode: setupintent.AccountExisting, Account: "bob", Home: "/home/bob", Shell: "/bin/bash", UID: 1001, GID: 1001},
	}}
	prompter := &scriptedPrompter{t: t, answers: []scriptedAnswer{
		{kind: "select", stringValue: "providers"},
		{kind: "multiselect", stringSlice: []string{"github"}},
		{kind: "select", stringValue: "add-approver"},
		{kind: "text", stringValue: "alice"},
		{kind: "select", stringValue: "remove-connection"},
		{kind: "select", stringValue: "bob"},
		{kind: "select", stringValue: "done"},
	}}
	updated, err := editInstallation(t.Context(), prompter, value, setupOptions{ProviderOptions: []provider.Option{
		{APIVersion: provider.APIVersion, ID: "github", Label: "GitHub"},
		{APIVersion: provider.APIVersion, ID: "huggingface", Label: "Hugging Face"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if len(updated.CredentialService.Providers) != 1 || updated.CredentialService.Providers[0] != "github" {
		t.Fatalf("providers = %#v", updated.CredentialService.Providers)
	}
	if len(updated.Approvers) != 2 || updated.Approvers[1].Account != "alice" {
		t.Fatalf("approvers = %#v", updated.Approvers)
	}
	if len(updated.Connections) != 0 {
		t.Fatalf("connections = %#v", updated.Connections)
	}
}

func TestSetupDiscardRequiresConfirm(t *testing.T) {
	t.Parallel()
	if err := runSetupDiscard(nil, &bytes.Buffer{}, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "--confirm") {
		t.Fatalf("discard without --confirm error = %v", err)
	}
}

func TestSetupDiscardRemovesNamedSession(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	store, err := setupSessionStore()
	if err != nil {
		t.Fatal(err)
	}
	value, err := session.New("build", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Save(value); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := runSetupDiscard([]string{"--confirm", value.ID}, &output, &output); err != nil {
		t.Fatalf("discard = %v", err)
	}
	if !strings.Contains(output.String(), "Discarded") {
		t.Fatalf("discard output = %q", output.String())
	}
	if _, err := store.Load(value.ID); err == nil {
		t.Fatal("session survived discard")
	}
}

func TestSetupDiscardAllRemovesIncomplete(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	store, err := setupSessionStore()
	if err != nil {
		t.Fatal(err)
	}
	// Two incomplete sessions.
	for range 2 {
		value, err := session.New("build", time.Now())
		if err != nil {
			t.Fatal(err)
		}
		if err := store.Save(value); err != nil {
			t.Fatal(err)
		}
	}
	// One completed session; discard --all must leave it alone.
	value, err := session.New("build", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	value.Phase = session.PhaseComplete
	if err := store.Save(value); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := runSetupDiscard([]string{"--confirm", "--all"}, &output, &output); err != nil {
		t.Fatalf("discard --all = %v", err)
	}
	if !strings.Contains(output.String(), "Discarded 2") {
		t.Fatalf("discard --all output = %q", output.String())
	}
	remaining, err := store.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(remaining) != 1 || remaining[0].Phase != session.PhaseComplete {
		t.Fatalf("completed session did not survive discard --all: %#v", remaining)
	}
}

func TestJoinProvidersRenders(t *testing.T) {
	t.Parallel()
	if got := joinProviders(installationWithProviders()); got != "github, huggingface" {
		t.Fatalf("joined = %q", got)
	}
}
