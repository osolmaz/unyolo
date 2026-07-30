package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/osolmaz/unyolo/deployment/profile"
	"github.com/osolmaz/unyolo/deployment/session"
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

func TestSetupDeploymentDirectory(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	path, err := setupDeploymentDirectory("test-host")
	if err != nil || !strings.HasSuffix(path, filepath.Join("unyolo", "deployments", "test-host")) {
		t.Fatalf("setupDeploymentDirectory() = %q, %v", path, err)
	}
	if _, err := setupDeploymentDirectory("bad name"); err == nil {
		t.Fatal("invalid deployment name was accepted")
	}
}

func TestSetupMaterializationResume(t *testing.T) {
	destination := "/tmp/generated-pack"
	digest := "sha256:" + strings.Repeat("a", 64)
	value := session.Session{Generated: map[string]string{profile.EntryFilename: digest}}
	if ready, err := setupProfileAlreadyMaterialized(value, destination, destination, digest); err != nil || !ready {
		t.Fatalf("matching materialization = %v, %v", ready, err)
	}
	if ready, err := setupProfileAlreadyMaterialized(value, "/tmp/source-pack", destination, digest); err != nil || ready {
		t.Fatalf("source materialization = %v, %v", ready, err)
	}
	value.Generated[profile.EntryFilename] = "sha256:" + strings.Repeat("b", 64)
	if ready, err := setupProfileAlreadyMaterialized(value, destination, destination, digest); err == nil || ready {
		t.Fatal("changed materialization digest was accepted")
	}
}

func TestSetupHelpersAndNoninteractiveRefusal(t *testing.T) {
	if privilegedReleaseVersion("1.2.3") != "v1.2.3" || privilegedReleaseVersion("v1.2.3") != "v1.2.3" {
		t.Fatal("privileged worker release version is incorrect")
	}
	if initialSetupMode("") != "recommended" || initialSetupMode("/tmp/profile") != "existing" {
		t.Fatal("initial setup mode is incorrect")
	}
	values := appendUnique(nil, "one")
	values = appendUnique(values, "one")
	if len(values) != 1 {
		t.Fatalf("values = %v", values)
	}
	if err := validateSetupSecretPairs(map[string][]byte{
		"github-agent-secret": []byte("same"), "github-operator-secret": []byte("same"),
	}); err == nil {
		t.Fatal("matching agent and operator credentials were accepted")
	}
	if err := validateSetupSecretPairs(map[string][]byte{
		"github-agent-secret": []byte("agent"), "github-operator-secret": []byte("operator"),
	}); err != nil {
		t.Fatal(err)
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
