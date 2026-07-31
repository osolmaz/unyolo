package session

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	setupintent "github.com/osolmaz/unyolo/setup/intent"
)

func TestSessionRoundTripAndResume(t *testing.T) {
	now := time.Date(2026, 7, 26, 1, 2, 3, 0, time.UTC)
	store := Store{Directory: filepath.Join(t.TempDir(), "state"), Now: func() time.Time { return now }}
	value, err := New("build-1", now)
	if err != nil {
		t.Fatal(err)
	}
	value.Intent.Goal = "credential_service"
	value.Intent.CredentialService = &setupintent.CredentialService{Location: setupintent.ServiceNative, Providers: []string{"github"}}
	value.SecretSlots = []SecretSlot{{ID: "github-token", Supplied: true}}
	value.CompletedStep = []string{"goal", "providers"}
	value.CurrentStep = "review"
	value.CapabilityDigest = "sha256:" + strings.Repeat("a", 64)
	value.Phase = PhaseEnrolling
	if err := store.Save(value); err != nil {
		t.Fatal(err)
	}
	loaded, err := store.Load(value.ID)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Intent.Goal != setupintent.GoalCredentialService || loaded.SecretSlots[0].Supplied {
		t.Fatalf("loaded = %#v", loaded)
	}
	resumed, found, err := store.NewestIncomplete("build-1")
	if err != nil || !found || resumed.ID != value.ID {
		t.Fatalf("NewestIncomplete() = %#v, %v, %v", resumed, found, err)
	}
	data, err := os.ReadFile(filepath.Join(store.Directory, value.ID+".json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "credential-value") {
		t.Fatal("session persisted a credential canary")
	}
	if err := store.Cancel(value.ID); err != nil {
		t.Fatal(err)
	}
}

func TestUnreadableSessionRequiresExplicitDiscard(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "state")
	store := Store{Directory: directory}
	valid, err := New("build", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Save(valid); err != nil {
		t.Fatal(err)
	}
	oldID := strings.Repeat("a", 32)
	old := `{"api_version":"unyolo.io/setup-session/v1","id":"` + oldID + `","build_id":"v0.6.3","deployment":"default"}`
	if err := os.WriteFile(filepath.Join(directory, oldID+".json"), []byte(old), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.NewestIncomplete("build"); err == nil {
		t.Fatal("unreadable setup progress was ignored")
	} else {
		var unreadable *UnreadableSessionsError
		if !errors.As(err, &unreadable) || !slices.Equal(unreadable.SessionIDs(), []string{oldID}) {
			t.Fatalf("NewestIncomplete() error = %T %v", err, err)
		}
		if err := store.DiscardUnreadable(unreadable.SessionIDs()); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := os.Stat(filepath.Join(directory, oldID+".json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("old setup progress still exists: %v", err)
	}
	if loaded, err := store.Load(valid.ID); err != nil || loaded.ID != valid.ID {
		t.Fatalf("valid setup progress changed: %#v, %v", loaded, err)
	}
	if err := store.DiscardUnreadable([]string{valid.ID}); err == nil {
		t.Fatal("readable setup progress was discarded")
	}
}

func TestSessionValidationAndDefaultDirectory(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	directory, err := DefaultDirectory()
	if err != nil || !strings.HasSuffix(directory, filepath.Join("unyolo", "setup")) {
		t.Fatalf("DefaultDirectory() = %q, %v", directory, err)
	}
	t.Setenv("XDG_STATE_HOME", "relative")
	if _, err := DefaultDirectory(); err == nil {
		t.Fatal("relative XDG_STATE_HOME was accepted")
	}
	if _, err := New("", time.Now()); err == nil {
		t.Fatal("empty build was accepted")
	}
	base, err := New("build", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		edit func(*Session)
	}{
		{"version", func(value *Session) { value.APIVersion = "old" }},
		{"ID", func(value *Session) { value.ID = "bad" }},
		{"build", func(value *Session) { value.BuildID = "" }},
		{"phase", func(value *Session) { value.Phase = "bad" }},
		{"step", func(value *Session) { value.CompletedStep = []string{"bad step"} }},
		{"intent", func(value *Session) {
			value.Intent.Goal = setupintent.GoalCommandOnly
			value.Intent.Integrations = []string{"openclaw"}
		}},
		{"current step", func(value *Session) { value.CurrentStep = "bad step" }},
		{"capability", func(value *Session) { value.CapabilityDigest = "bad" }},
		{"slot", func(value *Session) { value.SecretSlots = []SecretSlot{{ID: "bad slot"}} }},
		{"digest", func(value *Session) { value.Generated = map[string]string{"file": "bad"} }},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			value := base
			test.edit(&value)
			if err := value.Validate(); err == nil {
				t.Fatal("invalid session was accepted")
			}
		})
	}
}

func TestSessionListNewestAndActiveCancellation(t *testing.T) {
	now := time.Now().UTC()
	tick := 0
	store := Store{Directory: filepath.Join(t.TempDir(), "state"), Now: func() time.Time { tick++; return now.Add(time.Duration(tick) * time.Second) }}
	for _, phase := range []Phase{PhaseStarted, PhaseComplete, PhaseApplying} {
		value, err := New("build", now)
		if err != nil {
			t.Fatal(err)
		}
		value.Phase = phase
		if err := store.Save(value); err != nil {
			t.Fatal(err)
		}
		if phase == PhaseApplying {
			if err := store.Cancel(value.ID); err == nil {
				t.Fatal("active setup was cancelled locally")
			}
		}
	}
	values, err := store.List()
	if err != nil || len(values) != 3 {
		t.Fatalf("List() = %d, %v", len(values), err)
	}
	newest, found, err := store.NewestIncomplete("build")
	if err != nil || !found || newest.Phase != PhaseApplying {
		t.Fatalf("NewestIncomplete() = %#v, %v, %v", newest, found, err)
	}
	if _, found, err := store.NewestIncomplete("other"); err != nil || found {
		t.Fatalf("other build = %v, %v", found, err)
	}
}

func TestSessionRejectsUnsafeDirectoryMode(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	value, err := New("build", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := (Store{Directory: directory}).Save(value); err == nil {
		t.Fatal("Save() succeeded for unsafe directory")
	}
}
