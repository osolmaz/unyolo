package compiler

import (
	"errors"
	"fmt"
	"path/filepath"

	"github.com/osolmaz/unyolo/deployment/container"
	"github.com/osolmaz/unyolo/deployment/profile"
	"github.com/osolmaz/unyolo/internal/host/bundle"
	"github.com/osolmaz/unyolo/setup/installation"
)

// DockerImageCatalog maps official broker names to their pinned image
// references (repository:tag@sha256:...). The compiler refuses to emit
// Compose fragments unless every broker referenced by the installation is
// present in the catalog.
type DockerImageCatalog map[string]string

// AgentConnectionRender is one Compose override the compiler produced for one
// container agent connection.
type AgentConnectionRender struct {
	ConnectionID string
	Override     *container.AgentOverride
}

// ServicesRender is the credential-service Compose project the compiler
// produced. It is nil when the installation is not a Docker credential
// deployment.
type ServicesRender struct {
	Project *container.ServicesProject
}

// DockerRender bundles every Docker-shaped output produced from one
// installation.
type DockerRender struct {
	Services *ServicesRender
	Agents   []AgentConnectionRender
}

// RenderDockerOptions configures the Docker render pass. It is a peer to the
// existing native compilation.
type RenderDockerOptions struct {
	// Installation is the durable server-side record.
	Installation installation.Installation
	// Deployment is the compiled host deployment (containing agents +
	// components) used to look up target metadata.
	Deployment profile.Deployment
	// Manifest is the signed runtime manifest for the current release.
	Manifest bundle.Manifest
	// InstallationName is the deployment name; also used as installation
	// label on named volumes.
	InstallationName string
	// Images pin every broker and helper image the compiler will reference.
	Images DockerImageCatalog
	// ClientInitImage is the pinned unyolo-client-init image.
	ClientInitImage string
	// PairingBroker, when nonempty, is added to the credential service
	// project so the pairing service runs alongside brokers.
	PairingBroker string
	// InvitationSecretName is the Compose secret name used by init services.
	InvitationSecretName string
	// InvitationSecretFile is the host-relative path each project stores its
	// pending invitation under.
	InvitationSecretFile string
	// ComposeNetwork is the internal network used by credential services.
	ComposeNetwork string
	// ProjectPrefix is prepended to Compose project names for isolation.
	ProjectPrefix string
}

// RenderDocker produces every Docker-shaped output for one installation.
func RenderDocker(options RenderDockerOptions) (*DockerRender, error) {
	if err := options.Installation.Validate(); err != nil {
		return nil, err
	}
	if options.InstallationName == "" {
		options.InstallationName = options.Installation.Name
	}
	result := &DockerRender{}
	if options.Installation.CredentialService.Location == "docker" {
		services, err := renderDockerServices(options)
		if err != nil {
			return nil, err
		}
		result.Services = &ServicesRender{Project: services}
	}
	for _, connection := range options.Installation.Connections {
		if connection.Target.Kind != installation.TargetContainer {
			continue
		}
		override, err := renderContainerAgent(options, connection)
		if err != nil {
			return nil, fmt.Errorf("connection %q: %w", connection.ID, err)
		}
		result.Agents = append(result.Agents, AgentConnectionRender{ConnectionID: connection.ID, Override: override})
	}
	return result, nil
}

func renderDockerServices(options RenderDockerOptions) (*container.ServicesProject, error) {
	if len(options.Images) == 0 {
		return nil, errors.New("docker services require a pinned image catalog")
	}
	brokers := append([]string(nil), options.Installation.CredentialService.Providers...)
	if options.PairingBroker != "" {
		brokers = append(brokers, options.PairingBroker)
	}
	fragments := make([]container.BrokerService, 0, len(brokers))
	for _, provider := range brokers {
		image, ok := options.Images[provider]
		if !ok {
			return nil, fmt.Errorf("docker image catalog missing broker %q", provider)
		}
		fragments = append(fragments, DefaultBrokerService(provider, image))
	}
	projectName := composeProject(options.ProjectPrefix, options.InstallationName, "services")
	network := options.ComposeNetwork
	if network == "" {
		network = "unyolo-net"
	}
	return container.BuildServicesProject(container.ServicesOptions{
		ProjectName: projectName, NetworkName: network,
		InstallationName: options.InstallationName, Brokers: fragments,
	})
}

// DefaultBrokerService returns the canonical Compose fragment for one broker.
// Provider adapters may override this by supplying their own container.BrokerService.
func DefaultBrokerService(provider, image string) container.BrokerService {
	stateVolume := "unyolo-" + provider + "-state"
	configVolume := "unyolo-" + provider + "-config"
	stateTarget := "/var/lib/" + provider
	configTarget := "/etc/" + provider
	return container.BrokerService{
		Name:         provider,
		Image:        image,
		User:         "10001:10001",
		StateVolume:  stateVolume,
		StateTarget:  stateTarget,
		ConfigVolume: configVolume,
		ConfigTarget: configTarget,
		Secrets: []container.BrokerSecret{{
			Name: provider + "-agent-secret", File: "secrets/" + provider + "-agent-secret",
		}},
		ListenerPort:   8443,
		HealthArgs:     []string{"CMD", "/usr/local/bin/" + provider, "-health-check"},
		HealthInterval: "10s",
	}
}

func renderContainerAgent(options RenderDockerOptions, connection installation.Connection) (*container.AgentOverride, error) {
	if options.ClientInitImage == "" {
		return nil, errors.New("client-init image is required for container connections")
	}
	if !filepath.IsAbs(connection.Target.ProjectDirectory) {
		return nil, errors.New("container connection project directory must be absolute")
	}
	sharedVolume := "unyolo-client-" + connection.ID
	invitationSecretName := options.InvitationSecretName
	if invitationSecretName == "" {
		invitationSecretName = "unyolo-invitation-" + connection.ID
	}
	invitationSecretFile := options.InvitationSecretFile
	if invitationSecretFile == "" {
		invitationSecretFile = "secrets/" + invitationSecretName
	}
	projectName := composeProject(options.ProjectPrefix, options.InstallationName, "agent-"+connection.ID)
	return container.BuildAgentOverride(container.OverrideOptions{
		ProjectName:          projectName,
		AgentService:         connection.Target.Service,
		InitImage:            options.ClientInitImage,
		SharedVolume:         sharedVolume,
		ClientConfigTarget:   "/etc/unyolo",
		InvitationSecretName: invitationSecretName,
		InvitationSecretFile: invitationSecretFile,
		VolumeLabels: map[string]string{
			"io.unyolo.installation": options.InstallationName,
			"io.unyolo.connection":   connection.ID,
		},
	})
}

func composeProject(prefix, installationName, role string) string {
	parts := []string{}
	if prefix != "" {
		parts = append(parts, prefix)
	}
	parts = append(parts, installationName, role)
	joined := parts[0]
	for _, part := range parts[1:] {
		joined = joined + "-" + part
	}
	return joined
}
