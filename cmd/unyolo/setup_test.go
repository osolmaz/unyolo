package main

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/osolmaz/unyolo/deployment/session"
)

func TestSetupSessionStatusAndCancellation(t *testing.T) {
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
	if err := runSetupStatus(nil, &output, &output); err != nil || !strings.Contains(output.String(), value.ID+"\tdefault") {
		t.Fatalf("status = %q, %v", output.String(), err)
	}
	if err := runSetupCancel([]string{"--confirm", value.ID}, &output, &output); err != nil {
		t.Fatal(err)
	}
}

func TestSetupSecretSeparation(t *testing.T) {
	one := []byte(strings.Repeat("a", 32))
	two := []byte(strings.Repeat("b", 32))
	if err := validateSetupSecretPairs(map[string][]byte{"one": one, "two": two}); err != nil {
		t.Fatal(err)
	}
	if err := validateSetupSecretPairs(map[string][]byte{"one": one, "two": one}); err == nil {
		t.Fatal("reused setup secret was accepted")
	}
	values := map[string][]byte{"one": append([]byte(nil), one...)}
	clearSetupSecrets(values)
	if strings.Trim(string(values["one"]), "\x00") != "" {
		t.Fatal("setup secret was not cleared")
	}
}

func TestSetupHelpersAndNoninteractiveRefusal(t *testing.T) {
	if got := privilegedReleaseVersion("0.6.3"); got != "v0.6.3" {
		t.Fatalf("privilegedReleaseVersion = %q", got)
	}
	if got := privilegedReleaseVersion("v0.6.3"); got != "v0.6.3" {
		t.Fatalf("prefixed privilegedReleaseVersion = %q", got)
	}
	if err := runGuidedSetup(t.Context(), []string{"--new"}, &bytes.Buffer{}, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "interactive TTY") {
		t.Fatalf("noninteractive setup error = %v", err)
	}
}
