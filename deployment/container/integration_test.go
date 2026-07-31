//go:build docker_integration

// Package container docker_integration tests exercise a real docker compose CLI
// on a Compose project we materialize on disk. They are gated by a build tag
// so the normal unit test run does not require Docker.
//
// Run with:
//
//	GOWORK=off go test -tags docker_integration ./deployment/container/...
package container

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func skipIfNoDocker(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker CLI not available")
	}
	output, err := exec.Command("docker", "compose", "version", "--short").Output()
	if err != nil || strings.TrimSpace(string(output)) == "" {
		t.Skip("docker compose plugin not available")
	}
}

// TestComposeInspectAgainstRealDocker generates a minimal Compose project on
// disk, drops the override we compile for a container agent connection, and
// runs `docker compose config` to prove that the docker CLI accepts both the
// project and our override together.
func TestComposeInspectAgainstRealDocker(t *testing.T) {
	skipIfNoDocker(t)
	directory := t.TempDir()
	compose := []byte(`services:
  agent:
    image: hello-world:linux
    command: ["-"]
    restart: "no"
`)
	if err := os.WriteFile(filepath.Join(directory, "compose.yaml"), compose, 0o600); err != nil {
		t.Fatalf("write compose: %v", err)
	}
	// Seed an invitation secret file that the override references.
	if err := os.MkdirAll(filepath.Join(directory, "secrets"), 0o700); err != nil {
		t.Fatalf("mkdir secrets: %v", err)
	}
	if err := os.WriteFile(filepath.Join(directory, "secrets", "unyolo-invitation"), []byte("unyolo-pair-v1.placeholder"), 0o600); err != nil {
		t.Fatalf("seed invitation: %v", err)
	}
	override, err := BuildAgentOverride(OverrideOptions{
		AgentService:         "agent",
		InitImage:            "hello-world:linux" + validDigest,
		SharedVolume:         "unyolo-client-config",
		ClientConfigTarget:   "/etc/unyolo",
		InvitationSecretName: "unyolo-invitation",
		InvitationSecretFile: "secrets/unyolo-invitation",
	})
	if err != nil {
		t.Fatalf("BuildAgentOverride: %v", err)
	}
	if _, _, err := PlanAgentApply(AgentApplyInputs{
		Options:    ProjectOptions{Directory: directory},
		Override:   override,
		Invitation: []byte("unyolo-pair-v1.placeholder"),
	}); err != nil {
		t.Fatalf("PlanAgentApply: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	// docker compose accepts our combined project when using both files.
	overridePath := filepath.Join(directory, OverrideFilename)
	arguments := []string{
		"compose",
		"-f", filepath.Join(directory, "compose.yaml"),
		"-f", overridePath,
		"config", "--format", "json",
	}
	cmd := exec.CommandContext(ctx, "docker", arguments...)
	cmd.Dir = directory
	stdout, err := cmd.Output()
	if err != nil {
		t.Fatalf("docker compose config with override: %v (%s)", err, stderrOf(err))
	}
	if !strings.Contains(string(stdout), "unyolo-client-init") {
		t.Fatalf("expected docker compose to resolve unyolo-client-init service, got:\n%s", stdout)
	}
	if strings.Contains(string(stdout), "docker.sock") {
		t.Fatalf("resolved project must not reference docker.sock:\n%s", stdout)
	}
}

// TestServicesInspectAgainstRealDocker renders a credential-service compose
// project and runs `docker compose config` to prove docker parses it as-is.
func TestServicesInspectAgainstRealDocker(t *testing.T) {
	skipIfNoDocker(t)
	directory := t.TempDir()
	// Compose needs the referenced secret files to exist on disk.
	if err := os.MkdirAll(filepath.Join(directory, "secrets"), 0o700); err != nil {
		t.Fatalf("mkdir secrets: %v", err)
	}
	for _, name := range []string{"gh-broker-agent-secret", "hf-broker-agent-secret"} {
		if err := os.WriteFile(filepath.Join(directory, "secrets", name), []byte("secret"), 0o600); err != nil {
			t.Fatalf("seed secret %s: %v", name, err)
		}
	}
	project, err := BuildServicesProject(ServicesOptions{
		ProjectName:      "unyolo-services",
		NetworkName:      "unyolo-net",
		InstallationName: "default",
		Brokers:          []BrokerService{brokerFixture("gh-broker"), brokerFixture("hf-broker")},
	})
	if err != nil {
		t.Fatalf("BuildServicesProject: %v", err)
	}
	planResult, _, err := PlanServices(ServicesPlanInputs{Directory: directory, Project: project})
	if err != nil {
		t.Fatalf("PlanServices: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "docker", "compose", "-f", planResult.ComposePath, "config", "--format", "json") // #nosec G204 -- test-controlled inputs.
	cmd.Dir = directory
	stdout, err := cmd.Output()
	if err != nil {
		t.Fatalf("docker compose config: %v (%s)", err, stderrOf(err))
	}
	got := string(stdout)
	for _, want := range []string{"gh-broker", "hf-broker", "unyolo-net"} {
		if !strings.Contains(got, want) {
			t.Errorf("services compose config missing %q\n%s", want, got)
		}
	}
	if strings.Contains(got, "docker.sock") {
		t.Fatalf("services must not reference docker.sock:\n%s", got)
	}
}

func stderrOf(err error) string {
	if exitErr, ok := err.(*exec.ExitError); ok {
		return strings.TrimSpace(string(exitErr.Stderr))
	}
	return ""
}
