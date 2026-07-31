package compiler

import (
	"strings"
	"testing"

	"github.com/osolmaz/unyolo/deployment/container"
	"github.com/osolmaz/unyolo/setup/installation"
	setupintent "github.com/osolmaz/unyolo/setup/intent"
)

const testDigest = "@sha256:" + "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func dockerInstallationWithAgent() installation.Installation {
	return installation.Installation{
		APIVersion: installation.APIVersion, Name: installation.DefaultName,
		CredentialService: setupintent.CredentialService{Location: setupintent.ServiceDocker, Providers: []string{"gh-broker", "hf-broker"}},
		Approvers:         []installation.Approver{{ID: "onur", Account: "onur"}},
		Connections: []installation.Connection{
			{ID: "docker-agent", ClientID: "docker-agent", Target: installation.Target{Kind: installation.TargetContainer, Isolation: "container", ProjectDirectory: "/srv/agent", Service: "agent"}, Providers: []string{"gh-broker"}},
			{ID: "bob", ClientID: "bob", Target: installation.Target{Kind: installation.TargetLocalAccount, Isolation: "separate", AccountMode: setupintent.AccountExisting, Account: "bob", Home: "/home/bob", Shell: "/bin/bash"}, Providers: []string{"gh-broker"}},
		},
	}
}

func TestRenderDockerProducesServicesAndAgentOverride(t *testing.T) {
	options := RenderDockerOptions{
		Installation:     dockerInstallationWithAgent(),
		InstallationName: "default",
		Images: DockerImageCatalog{
			"gh-broker": "ghcr.io/osolmaz/gh-broker:1.0" + testDigest,
			"hf-broker": "ghcr.io/osolmaz/hf-broker:1.0" + testDigest,
		},
		ClientInitImage: "ghcr.io/osolmaz/unyolo-client-init:1.0" + testDigest,
	}
	render, err := RenderDocker(options)
	if err != nil {
		t.Fatalf("RenderDocker: %v", err)
	}
	if render.Services == nil {
		t.Fatal("expected services render for docker location")
	}
	yaml, err := render.Services.Project.Render()
	if err != nil {
		t.Fatalf("services render: %v", err)
	}
	if !strings.Contains(string(yaml), "gh-broker:") || !strings.Contains(string(yaml), "hf-broker:") {
		t.Fatalf("expected both brokers in services YAML:\n%s", yaml)
	}
	if len(render.Agents) != 1 || render.Agents[0].ConnectionID != "docker-agent" {
		t.Fatalf("expected one container agent override, got %+v", render.Agents)
	}
	overrideYAML, err := render.Agents[0].Override.Render()
	if err != nil {
		t.Fatalf("override render: %v", err)
	}
	got := string(overrideYAML)
	if !strings.Contains(got, "unyolo-client-init:") {
		t.Fatalf("agent override should include init service:\n%s", got)
	}
	if !strings.Contains(got, "unyolo-invitation-docker-agent:") {
		t.Fatalf("agent override should include per-connection invitation secret:\n%s", got)
	}
}

func TestRenderDockerRejectsUnpinnedImage(t *testing.T) {
	options := RenderDockerOptions{
		Installation:     dockerInstallationWithAgent(),
		InstallationName: "default",
		Images: DockerImageCatalog{
			"gh-broker": "ghcr.io/osolmaz/gh-broker:1.0",
			"hf-broker": "ghcr.io/osolmaz/hf-broker:1.0" + testDigest,
		},
		ClientInitImage: "ghcr.io/osolmaz/unyolo-client-init:1.0" + testDigest,
	}
	if _, err := RenderDocker(options); err == nil {
		t.Fatal("expected unpinned broker image to be rejected")
	}
}

func TestRenderDockerSkipsAgentWhenNoContainerConnection(t *testing.T) {
	source := dockerInstallationWithAgent()
	// Keep only the local account connection.
	source.Connections = source.Connections[1:]
	render, err := RenderDocker(RenderDockerOptions{
		Installation:     source,
		InstallationName: "default",
		Images: DockerImageCatalog{
			"gh-broker": "ghcr.io/osolmaz/gh-broker:1.0" + testDigest,
			"hf-broker": "ghcr.io/osolmaz/hf-broker:1.0" + testDigest,
		},
		ClientInitImage: "ghcr.io/osolmaz/unyolo-client-init:1.0" + testDigest,
	})
	if err != nil {
		t.Fatalf("RenderDocker: %v", err)
	}
	if render.Services == nil {
		t.Fatal("expected services render")
	}
	if len(render.Agents) != 0 {
		t.Fatalf("expected no container agent overrides, got %+v", render.Agents)
	}
}

func TestRenderDockerRequiresClientInitForContainerAgent(t *testing.T) {
	options := RenderDockerOptions{
		Installation:     dockerInstallationWithAgent(),
		InstallationName: "default",
		Images: DockerImageCatalog{
			"gh-broker": "ghcr.io/osolmaz/gh-broker:1.0" + testDigest,
			"hf-broker": "ghcr.io/osolmaz/hf-broker:1.0" + testDigest,
		},
	}
	if _, err := RenderDocker(options); err == nil {
		t.Fatal("expected missing client-init image to be rejected")
	}
}

func TestDefaultBrokerServiceMatchesPolicy(t *testing.T) {
	broker := DefaultBrokerService("gh-broker", "ghcr.io/osolmaz/gh-broker:1.0"+testDigest)
	if broker.User != "10001:10001" {
		t.Errorf("expected nonroot user, got %q", broker.User)
	}
	if broker.StateVolume == broker.ConfigVolume {
		t.Errorf("state and config volumes must differ")
	}
	if err := container.VerifyPinnedImage(broker.Image); err != nil {
		t.Errorf("default image must be pinned by digest: %v", err)
	}
}
