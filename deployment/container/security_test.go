package container

import (
	"strings"
	"testing"
)

const validDigest = "@sha256:" + "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func TestVerifyPinnedImage(t *testing.T) {
	if err := VerifyPinnedImage("example/agent:1.0" + validDigest); err != nil {
		t.Fatalf("expected pinned image to be accepted: %v", err)
	}
	if err := VerifyPinnedImage("example/agent:1.0"); err == nil {
		t.Fatal("expected unpinned image to be rejected")
	}
	if err := VerifyPinnedImage("example/agent"); err == nil {
		t.Fatal("expected untagged image without digest to be rejected")
	}
}

func TestCheckAgentServiceRejectsDockerSocket(t *testing.T) {
	project := ProjectInspection{Services: map[string]ServiceInspection{
		"agent": {Volumes: []VolumeMountInspection{{Type: "bind", Source: "/var/run/docker.sock", Target: "/var/run/docker.sock"}}},
	}}
	findings, err := CheckAgentService(project, "agent")
	if err != nil {
		t.Fatalf("CheckAgentService: %v", err)
	}
	if err := findings.Err(); err == nil || !strings.Contains(err.Error(), "docker_socket_mount") {
		t.Fatalf("expected docker socket to be flagged, got: %v", err)
	}
}

func TestCheckAgentServiceRejectsProviderCredentials(t *testing.T) {
	project := ProjectInspection{Services: map[string]ServiceInspection{
		"agent": {Volumes: []VolumeMountInspection{{Type: "bind", Source: "/etc/gh-broker", Target: "/etc/gh-broker"}}},
	}}
	findings, err := CheckAgentService(project, "agent")
	if err != nil {
		t.Fatalf("CheckAgentService: %v", err)
	}
	if err := findings.Err(); err == nil || !strings.Contains(err.Error(), "provider_credential_mount") {
		t.Fatalf("expected provider credential mount to be flagged, got: %v", err)
	}
}

func TestCheckAgentServiceRejectsPrivileged(t *testing.T) {
	project := ProjectInspection{Services: map[string]ServiceInspection{
		"agent": {Privileged: true, PidMode: "host", NetworkMode: "host"},
	}}
	findings, err := CheckAgentService(project, "agent")
	if err != nil {
		t.Fatalf("CheckAgentService: %v", err)
	}
	err = findings.Err()
	if err == nil {
		t.Fatal("expected privileged/host to be flagged")
	}
	for _, expected := range []string{"privileged", "pid_mode", "network_mode"} {
		if !strings.Contains(err.Error(), expected) {
			t.Errorf("expected rule %s in error: %v", expected, err)
		}
	}
}

func TestCheckAgentServiceMissingReturnsError(t *testing.T) {
	project := ProjectInspection{Services: map[string]ServiceInspection{}}
	if _, err := CheckAgentService(project, "agent"); err == nil {
		t.Fatal("expected missing service error")
	}
}

func TestCheckOverrideServicesRequiresDigest(t *testing.T) {
	override := &AgentOverride{APIVersion: OverrideAPIVersion, InitService: InitService{Image: "example/init:1.0"}}
	if err := CheckOverrideServices(override); err == nil {
		t.Fatal("expected unpinned init image to be rejected")
	}
	override.InitService.Image = "example/init:1.0" + validDigest
	if err := CheckOverrideServices(override); err != nil {
		t.Fatalf("expected pinned override to pass: %v", err)
	}
}

func TestCheckOverrideRejectsSocketMount(t *testing.T) {
	override := &AgentOverride{
		APIVersion: OverrideAPIVersion,
		InitService: InitService{
			Image:   "example/init:1.0" + validDigest,
			Volumes: []OverrideMount{{Type: "bind", Source: "/var/run/docker.sock", Target: "/var/run/docker.sock"}},
		},
	}
	if err := CheckOverrideServices(override); err == nil {
		t.Fatal("expected socket mount rejection")
	}
}
