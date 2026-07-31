package container

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// ServicesAPIVersion identifies the credential-service compose document we
// produce.
const ServicesAPIVersion = "unyolo.io/services-compose/v1"

// InstallationBrokerNamePattern is the pattern applied to broker names inside
// generated Compose services.
var installationBrokerPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9_-]{0,62}[a-z0-9])?$`)

// BrokerService describes one broker's fragment inside the credential-service
// Compose stack. Every field is required except the ones marked optional in
// the plan.
type BrokerService struct {
	// Name is the service name inside the generated compose.yaml, and the
	// short broker identifier (github, huggingface, sudo, pairing).
	Name string
	// Image is the pinned image digest for this broker.
	Image string
	// User is the container user (uid:gid) the broker runs as.
	User string
	// StateVolume is the named Docker volume that stores broker state.
	StateVolume string
	// StateTarget is the container path that state is mounted at.
	StateTarget string
	// ConfigVolume is the named Docker volume that stores rendered nonsecret
	// config files. It is populated by an init sidecar at first run.
	ConfigVolume string
	// ConfigTarget is the container path the config volume is mounted at.
	ConfigTarget string
	// Secrets is the ordered list of Compose secrets mounted read-only into
	// the container. Each secret is a separate file on the host.
	Secrets []BrokerSecret
	// ListenerPort is the TCP port the broker exposes inside the network for
	// TLS. Zero means no port is published; brokers communicate over the
	// unyolo network.
	ListenerPort int
	// Environment is the ordered list of environment variables. Secrets are
	// never passed via environment.
	Environment []EnvironmentEntry
	// HealthArgs is the shell-free command used as the docker health check.
	HealthArgs []string
	// HealthInterval is the Compose interval string (e.g. "10s").
	HealthInterval string
	// Command overrides the image entrypoint arguments.
	Command []string
}

// BrokerSecret describes one Compose secret consumed by a broker.
type BrokerSecret struct {
	Name string
	File string
}

// ServicesProject is the closed credential-service Compose document.
type ServicesProject struct {
	APIVersion  string
	ProjectName string
	// NetworkName is the fixed internal Compose network used by all brokers.
	NetworkName string
	// Brokers ordered deterministically by name.
	Brokers []BrokerService
	// SharedVolumes lists all named volumes referenced by any broker. Each
	// volume is labeled with the installation for later removal.
	SharedVolumes []SharedVolume
	// Secrets lists all Compose secret files referenced by brokers.
	Secrets []SecretFile
}

// ServicesOptions is the input to the credential-service compiler.
type ServicesOptions struct {
	ProjectName      string
	NetworkName      string
	InstallationName string
	Brokers          []BrokerService
}

// Validate rejects unsafe or duplicate broker definitions.
func (options ServicesOptions) Validate() error {
	if !composeProjectNamePattern.MatchString(options.ProjectName) {
		return errors.New("credential services project name is invalid")
	}
	if !composeServiceNamePattern.MatchString(options.NetworkName) {
		return errors.New("credential services network name is invalid")
	}
	if !installationBrokerPattern.MatchString(options.InstallationName) {
		return errors.New("installation name is invalid")
	}
	if len(options.Brokers) == 0 {
		return errors.New("credential services require at least one broker")
	}
	seen := map[string]bool{}
	volumeIndex := map[string]string{}
	secretIndex := map[string]string{}
	for _, broker := range options.Brokers {
		if err := broker.validate(seen, volumeIndex, secretIndex); err != nil {
			return err
		}
	}
	return nil
}

func (broker BrokerService) validate(seen map[string]bool, volumes, secrets map[string]string) error {
	if !installationBrokerPattern.MatchString(broker.Name) || seen[broker.Name] {
		return fmt.Errorf("broker %q is invalid or duplicated", broker.Name)
	}
	if err := VerifyPinnedImage(broker.Image); err != nil {
		return fmt.Errorf("broker %q: %w", broker.Name, err)
	}
	if !userPattern.MatchString(broker.User) {
		return fmt.Errorf("broker %q user must be uid:gid", broker.Name)
	}
	if !isValidVolumeName(broker.StateVolume) || !isValidVolumeName(broker.ConfigVolume) {
		return fmt.Errorf("broker %q volume name is invalid", broker.Name)
	}
	if broker.StateVolume == broker.ConfigVolume {
		return fmt.Errorf("broker %q state and config volumes must differ", broker.Name)
	}
	if !isValidContainerPath(broker.StateTarget) || !isValidContainerPath(broker.ConfigTarget) {
		return fmt.Errorf("broker %q container target is invalid", broker.Name)
	}
	if existing, ok := volumes[broker.StateVolume]; ok && existing != broker.Name {
		return fmt.Errorf("broker %q state volume conflicts with broker %q", broker.Name, existing)
	}
	if existing, ok := volumes[broker.ConfigVolume]; ok && existing != broker.Name {
		return fmt.Errorf("broker %q config volume conflicts with broker %q", broker.Name, existing)
	}
	volumes[broker.StateVolume] = broker.Name
	volumes[broker.ConfigVolume] = broker.Name
	for _, secret := range broker.Secrets {
		if !isValidComposeName(secret.Name) || !isValidRelativePath(secret.File) {
			return fmt.Errorf("broker %q secret %q is invalid", broker.Name, secret.Name)
		}
		if existing, ok := secrets[secret.Name]; ok && existing != broker.Name {
			return fmt.Errorf("secret %q is shared between brokers %q and %q", secret.Name, broker.Name, existing)
		}
		secrets[secret.Name] = broker.Name
	}
	if broker.ListenerPort < 0 || broker.ListenerPort > 65535 {
		return fmt.Errorf("broker %q listener port is invalid", broker.Name)
	}
	for _, entry := range broker.Environment {
		if !envKeyPattern.MatchString(entry.Name) {
			return fmt.Errorf("broker %q environment key %q is invalid", broker.Name, entry.Name)
		}
	}
	if len(broker.HealthArgs) == 0 {
		return fmt.Errorf("broker %q health check is required", broker.Name)
	}
	seen[broker.Name] = true
	return nil
}

var (
	userPattern   = regexp.MustCompile(`^[0-9]+:[0-9]+$`)
	envKeyPattern = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)
)

// BuildServicesProject compiles broker fragments into a deterministic
// credential-service Compose project. It never adds a Docker socket, never
// mounts one broker's state into another, and never inlines secrets in the
// environment.
func BuildServicesProject(options ServicesOptions) (*ServicesProject, error) {
	if err := options.Validate(); err != nil {
		return nil, err
	}
	sorted := append([]BrokerService(nil), options.Brokers...)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })
	volumes := map[string]SharedVolume{}
	for _, broker := range sorted {
		labels := map[string]string{
			"io.unyolo.installation": options.InstallationName,
			"io.unyolo.broker":       broker.Name,
		}
		volumes[broker.StateVolume] = SharedVolume{Name: broker.StateVolume, Labels: mergeLabels(labels, map[string]string{"io.unyolo.role": "state"})}
		volumes[broker.ConfigVolume] = SharedVolume{Name: broker.ConfigVolume, Labels: mergeLabels(labels, map[string]string{"io.unyolo.role": "config"})}
	}
	names := make([]string, 0, len(volumes))
	for name := range volumes {
		names = append(names, name)
	}
	sort.Strings(names)
	sharedVolumes := make([]SharedVolume, 0, len(volumes))
	for _, name := range names {
		sharedVolumes = append(sharedVolumes, volumes[name])
	}
	secretIndex := map[string]SecretFile{}
	for _, broker := range sorted {
		for _, secret := range broker.Secrets {
			secretIndex[secret.Name] = SecretFile{Name: secret.Name, File: secret.File}
		}
	}
	secretNames := make([]string, 0, len(secretIndex))
	for name := range secretIndex {
		secretNames = append(secretNames, name)
	}
	sort.Strings(secretNames)
	secrets := make([]SecretFile, 0, len(secretNames))
	for _, name := range secretNames {
		secrets = append(secrets, secretIndex[name])
	}
	project := &ServicesProject{
		APIVersion: ServicesAPIVersion, ProjectName: options.ProjectName, NetworkName: options.NetworkName,
		Brokers: sorted, SharedVolumes: sharedVolumes, Secrets: secrets,
	}
	if err := CheckServicesSecurity(project); err != nil {
		return nil, err
	}
	return project, nil
}

func mergeLabels(base, extras map[string]string) map[string]string {
	result := make(map[string]string, len(base)+len(extras))
	for key, value := range base {
		result[key] = value
	}
	for key, value := range extras {
		result[key] = value
	}
	return result
}

// CheckServicesSecurity enforces the credential-service isolation rules: no
// broker mounts the Docker socket, no broker mounts another broker's state or
// credential path, and no secret is shared between brokers.
func CheckServicesSecurity(project *ServicesProject) error {
	if project == nil {
		return errors.New("services project is nil")
	}
	seenSecrets := map[string]string{}
	for _, broker := range project.Brokers {
		if strings.EqualFold(broker.NetworkMode(), "host") {
			return fmt.Errorf("broker %q must not use host network mode", broker.Name)
		}
		for _, secret := range broker.Secrets {
			if existing, ok := seenSecrets[secret.Name]; ok && existing != broker.Name {
				return fmt.Errorf("secret %q is shared between brokers %q and %q", secret.Name, broker.Name, existing)
			}
			seenSecrets[secret.Name] = broker.Name
		}
	}
	return nil
}

// NetworkMode always returns the empty string. Broker services never use host
// network mode.
func (broker BrokerService) NetworkMode() string { return "" }

// Render serializes the credential-service project to a deterministic Compose
// YAML document.
func (project *ServicesProject) Render() ([]byte, error) {
	if project.APIVersion != ServicesAPIVersion {
		return nil, errors.New("services project API version is invalid")
	}
	var builder strings.Builder
	fmt.Fprintf(&builder, "# %s — generated by unYOLO. Edit installation.json instead.\n", project.APIVersion)
	fmt.Fprintf(&builder, "name: %s\n", project.ProjectName)
	builder.WriteString("services:\n")
	for _, broker := range project.Brokers {
		renderBrokerService(&builder, project.NetworkName, broker)
	}
	renderNamedVolumes(&builder, project.SharedVolumes)
	renderNamedSecrets(&builder, project.Secrets)
	fmt.Fprintf(&builder, "networks:\n  %s:\n    driver: bridge\n    internal: false\n", project.NetworkName)
	return []byte(builder.String()), nil
}

func renderBrokerService(builder *strings.Builder, network string, broker BrokerService) {
	fmt.Fprintf(builder, "  %s:\n", broker.Name)
	fmt.Fprintf(builder, "    image: %s\n", broker.Image)
	fmt.Fprintf(builder, "    user: %q\n", broker.User)
	builder.WriteString("    read_only: true\n")
	builder.WriteString("    restart: unless-stopped\n")
	builder.WriteString("    stop_grace_period: 10s\n")
	builder.WriteString("    cap_drop:\n      - ALL\n")
	builder.WriteString("    security_opt:\n      - no-new-privileges:true\n")
	fmt.Fprintf(builder, "    networks:\n      - %s\n", network)
	if broker.ListenerPort > 0 {
		fmt.Fprintf(builder, "    expose:\n      - \"%d\"\n", broker.ListenerPort)
	}
	if len(broker.Command) > 0 {
		builder.WriteString("    command:\n")
		for _, arg := range broker.Command {
			fmt.Fprintf(builder, "      - %q\n", arg)
		}
	}
	if len(broker.Environment) > 0 {
		sorted := append([]EnvironmentEntry(nil), broker.Environment...)
		sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })
		builder.WriteString("    environment:\n")
		for _, entry := range sorted {
			fmt.Fprintf(builder, "      %s: %q\n", entry.Name, entry.Value)
		}
	}
	builder.WriteString("    volumes:\n")
	fmt.Fprintf(builder, "      - type: volume\n        source: %s\n        target: %s\n", broker.StateVolume, broker.StateTarget)
	fmt.Fprintf(builder, "      - type: volume\n        source: %s\n        target: %s\n        read_only: true\n", broker.ConfigVolume, broker.ConfigTarget)
	if len(broker.Secrets) > 0 {
		sorted := append([]BrokerSecret(nil), broker.Secrets...)
		sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })
		builder.WriteString("    secrets:\n")
		for _, secret := range sorted {
			fmt.Fprintf(builder, "      - %s\n", secret.Name)
		}
	}
	builder.WriteString("    healthcheck:\n")
	interval := broker.HealthInterval
	if interval == "" {
		interval = "10s"
	}
	builder.WriteString("      test:\n")
	for _, arg := range broker.HealthArgs {
		fmt.Fprintf(builder, "        - %q\n", arg)
	}
	fmt.Fprintf(builder, "      interval: %s\n      timeout: 5s\n      retries: 6\n", interval)
}

func renderNamedVolumes(builder *strings.Builder, volumes []SharedVolume) {
	if len(volumes) == 0 {
		return
	}
	builder.WriteString("volumes:\n")
	for _, volume := range volumes {
		fmt.Fprintf(builder, "  %s:\n", volume.Name)
		if len(volume.Labels) > 0 {
			names := make([]string, 0, len(volume.Labels))
			for name := range volume.Labels {
				names = append(names, name)
			}
			sort.Strings(names)
			builder.WriteString("    labels:\n")
			for _, name := range names {
				fmt.Fprintf(builder, "      %s: %q\n", name, volume.Labels[name])
			}
		}
	}
}

func renderNamedSecrets(builder *strings.Builder, secrets []SecretFile) {
	if len(secrets) == 0 {
		return
	}
	builder.WriteString("secrets:\n")
	for _, secret := range secrets {
		fmt.Fprintf(builder, "  %s:\n", secret.Name)
		fmt.Fprintf(builder, "    file: %s\n", secret.File)
	}
}
