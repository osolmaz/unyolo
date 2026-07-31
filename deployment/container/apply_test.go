package container

import (
	"os"
	"path/filepath"
	"testing"
)

func writeCompose(t *testing.T, directory string) {
	t.Helper()
	data := []byte("services:\n  agent:\n    image: example/agent:1.0\n")
	if err := os.WriteFile(filepath.Join(directory, "compose.yaml"), data, 0o600); err != nil {
		t.Fatalf("write compose: %v", err)
	}
}

func TestPlanAgentApplyWritesFiles(t *testing.T) {
	directory := t.TempDir()
	writeCompose(t, directory)
	override, err := BuildAgentOverride(OverrideOptions{
		AgentService:         "agent",
		InitImage:            "example/init:1.0" + validDigest,
		SharedVolume:         "unyolo-client-config",
		ClientConfigTarget:   "/etc/unyolo",
		InvitationSecretName: "unyolo-invitation",
		InvitationSecretFile: "secrets/unyolo-invitation",
	})
	if err != nil {
		t.Fatalf("BuildAgentOverride: %v", err)
	}
	inputs := AgentApplyInputs{
		Options:    ProjectOptions{Directory: directory},
		Override:   override,
		Invitation: []byte("unyolo-pair-v1.example"),
	}
	result, rollback, err := PlanAgentApply(inputs)
	if err != nil {
		t.Fatalf("PlanAgentApply: %v", err)
	}
	if _, err := os.Stat(result.OverridePath); err != nil {
		t.Fatalf("override missing: %v", err)
	}
	if _, err := os.Stat(result.InvitationPath); err != nil {
		t.Fatalf("invitation missing: %v", err)
	}
	// Rollback must remove the files when they did not previously exist.
	if err := rollback(); err != nil {
		t.Fatalf("rollback: %v", err)
	}
	if _, err := os.Stat(result.OverridePath); !os.IsNotExist(err) {
		t.Fatalf("override should be removed by rollback, got: %v", err)
	}
	if _, err := os.Stat(result.InvitationPath); !os.IsNotExist(err) {
		t.Fatalf("invitation should be removed by rollback, got: %v", err)
	}
}

func TestPlanAgentApplyRestoresExistingOverride(t *testing.T) {
	directory := t.TempDir()
	writeCompose(t, directory)
	existing := []byte("existing: yes\n")
	overridePath := filepath.Join(directory, OverrideFilename)
	if err := os.WriteFile(overridePath, existing, 0o600); err != nil {
		t.Fatalf("seed override: %v", err)
	}
	override, err := BuildAgentOverride(OverrideOptions{
		AgentService:         "agent",
		InitImage:            "example/init:1.0" + validDigest,
		SharedVolume:         "unyolo-client-config",
		ClientConfigTarget:   "/etc/unyolo",
		InvitationSecretName: "unyolo-invitation",
		InvitationSecretFile: "secrets/unyolo-invitation",
	})
	if err != nil {
		t.Fatalf("BuildAgentOverride: %v", err)
	}
	inputs := AgentApplyInputs{
		Options:    ProjectOptions{Directory: directory},
		Override:   override,
		Invitation: []byte("unyolo-pair-v1.example"),
	}
	_, rollback, err := PlanAgentApply(inputs)
	if err != nil {
		t.Fatalf("PlanAgentApply: %v", err)
	}
	if err := rollback(); err != nil {
		t.Fatalf("rollback: %v", err)
	}
	got, err := os.ReadFile(overridePath)
	if err != nil {
		t.Fatalf("read restored override: %v", err)
	}
	if string(got) != string(existing) {
		t.Fatalf("override not restored to previous content, got: %q want: %q", got, existing)
	}
}
