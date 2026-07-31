package container

import (
	"bytes"
	"strings"
	"testing"
)

func testOptions() OverrideOptions {
	return OverrideOptions{
		ProjectName:          "demo",
		AgentService:         "agent",
		InitImage:            "example/init:1.0" + validDigest,
		SharedVolume:         "unyolo-client-config",
		ClientConfigTarget:   "/etc/unyolo",
		InvitationSecretName: "unyolo-invitation",
		InvitationSecretFile: "secrets/unyolo-invitation",
		VolumeLabels:         map[string]string{"io.unyolo.installation": "default"},
	}
}

func TestBuildAgentOverrideDeterministic(t *testing.T) {
	first, err := BuildAgentOverride(testOptions())
	if err != nil {
		t.Fatalf("BuildAgentOverride: %v", err)
	}
	firstYAML, err := first.Render()
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	second, err := BuildAgentOverride(testOptions())
	if err != nil {
		t.Fatalf("BuildAgentOverride: %v", err)
	}
	secondYAML, err := second.Render()
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if !bytes.Equal(firstYAML, secondYAML) {
		t.Fatalf("override render is not deterministic\nfirst:\n%s\nsecond:\n%s", firstYAML, secondYAML)
	}
}

func TestBuildAgentOverrideValidatesInputs(t *testing.T) {
	invalid := testOptions()
	invalid.AgentService = ""
	if _, err := BuildAgentOverride(invalid); err == nil {
		t.Fatal("expected empty agent service to be rejected")
	}
	invalid = testOptions()
	invalid.InitImage = "example/init:1.0"
	if _, err := BuildAgentOverride(invalid); err == nil {
		t.Fatal("expected unpinned image to be rejected")
	}
	invalid = testOptions()
	invalid.InvitationSecretFile = "/etc/passwd"
	if _, err := BuildAgentOverride(invalid); err == nil {
		t.Fatal("expected absolute invitation path to be rejected")
	}
	invalid = testOptions()
	invalid.InvitationSecretFile = "../escape"
	if _, err := BuildAgentOverride(invalid); err == nil {
		t.Fatal("expected traversal to be rejected")
	}
}

func TestOverrideYAMLHasRequiredStructure(t *testing.T) {
	override, err := BuildAgentOverride(testOptions())
	if err != nil {
		t.Fatalf("BuildAgentOverride: %v", err)
	}
	rendered, err := override.Render()
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	got := string(rendered)
	for _, want := range []string{
		"name: demo",
		"services:",
		"agent:",
		"depends_on:",
		"unyolo-client-init:",
		"condition: service_completed_successfully",
		"user: \"10001:10001\"",
		"security_opt:",
		"no-new-privileges:true",
		"cap_drop:",
		"- ALL",
		"secrets:",
		"unyolo-invitation:",
		"file: secrets/unyolo-invitation",
		"volumes:",
		"unyolo-client-config:",
		"io.unyolo.installation",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("rendered override missing %q\n%s", want, got)
		}
	}
	// The init image must appear pinned by digest.
	if !strings.Contains(got, validDigest) {
		t.Errorf("expected init image to be pinned by digest, got:\n%s", got)
	}
}
