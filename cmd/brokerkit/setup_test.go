package main

import (
	"bytes"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/osolmaz/brokerkit/deployment/session"
)

func TestSetupSessionStatusAndCancellation(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	store, err := setupSessionStore()
	if err != nil {
		t.Fatal(err)
	}
	value, err := session.New("dev", "host", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Save(value); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if err := runSetupStatus([]string{"--json"}, &stdout, &stderr); err != nil || !strings.Contains(stdout.String(), value.ID) {
		t.Fatalf("status = %q, %v", stdout.String(), err)
	}
	stdout.Reset()
	if err := runSetupCancel([]string{"--confirm", value.ID}, &stdout, &stderr); err != nil || !strings.Contains(stdout.String(), "Cancelled") {
		t.Fatalf("cancel = %q, %v", stdout.String(), err)
	}
	if _, err := store.Load(value.ID); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("cancelled session remains: %v", err)
	}
	for _, args := range [][]string{{"extra"}, {"--bad"}} {
		if err := runSetupStatus(args, &stdout, &stderr); err == nil {
			t.Fatalf("status accepted %v", args)
		}
	}
	if err := runSetupCancel(nil, &stdout, &stderr); err == nil {
		t.Fatal("cancel accepted no session ID")
	}
}

func TestSetupHelpersAndNoninteractiveRefusal(t *testing.T) {
	if initialSetupMode("") != "recommended" || initialSetupMode("/tmp/profile") != "existing" {
		t.Fatal("initial setup mode is incorrect")
	}
	values := appendUnique(nil, "one")
	values = appendUnique(values, "one")
	if len(values) != 1 {
		t.Fatalf("values = %v", values)
	}
	secrets := map[string][]byte{"token": []byte("secret")}
	clearSetupSecrets(secrets)
	for _, value := range secrets["token"] {
		if value != 0 {
			t.Fatal("setup secret was not cleared")
		}
	}
	if err := runGuidedSetup(t.Context(), nil, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
		t.Fatal("guided setup accepted a noninteractive terminal")
	}
}
