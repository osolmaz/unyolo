package main

import (
	"bytes"
	"strings"
	"testing"
	"time"

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

func TestSetupLifecycleUsageError(t *testing.T) {
	usage := systemUsageError()
	if !strings.Contains(usage.Error(), "reconfigure") || !strings.Contains(usage.Error(), "remove") || !strings.Contains(usage.Error(), "repair") || !strings.Contains(usage.Error(), "discard") {
		t.Fatalf("usage error missing lifecycle verbs: %q", usage.Error())
	}
}

func TestJoinProvidersRenders(t *testing.T) {
	t.Parallel()
	if got := joinProviders(installationWithProviders()); got != "github, huggingface" {
		t.Fatalf("joined = %q", got)
	}
}
