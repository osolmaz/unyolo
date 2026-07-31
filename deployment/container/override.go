package container

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// OverrideAPIVersion identifies the override document we produce.
const OverrideAPIVersion = "unyolo.io/agent-compose-override/v1"

// InitServiceName is the fixed name of the init service we inject.
const InitServiceName = "unyolo-client-init"

// AgentOverride is the deterministic Compose override we generate to attach an
// existing agent service to unYOLO through a one-shot init container.
type AgentOverride struct {
	APIVersion    string
	ProjectName   string
	AgentService  string
	InitService   InitService
	SharedVolumes []SharedVolume
	SecretFiles   []SecretFile
	Networks      []string
}

// InitService is the closed init service description.
type InitService struct {
	Image         string
	Command       []string
	Environment   []EnvironmentEntry
	Volumes       []OverrideMount
	Secrets       []string
	Networks      []string
	Privileged    bool
	PidHost       bool
	NetworkHost   bool
	Restart       string
	RunOnce       bool
	StopGrace     string
	ReadOnlyRoot  bool
	Capabilities  []string
	CapabilityAdd []string
	CapabilityDel []string
	User          string
}

// EnvironmentEntry is a Compose environment key/value pair.
type EnvironmentEntry struct {
	Name  string
	Value string
}

// SharedVolume is a named Compose volume we own.
type SharedVolume struct {
	Name   string
	Labels map[string]string
}

// SecretFile is a Compose secret file entry.
type SecretFile struct {
	Name string
	File string
}

// OverrideMount is a mount into either the init service or the agent service.
type OverrideMount struct {
	Type     string
	Source   string
	Target   string
	ReadOnly bool
}

// OverrideOptions describes the desired override.
type OverrideOptions struct {
	// ProjectName is the Compose project the override belongs to. Optional.
	ProjectName string
	// AgentService is the existing service we attach unYOLO to.
	AgentService string
	// InitImage is the pinned digest of the unyolo-client-init image.
	InitImage string
	// InitCommand overrides the default entrypoint arguments. Empty means the
	// image entrypoint is used.
	InitCommand []string
	// SharedVolume is the name of the client config volume we write.
	SharedVolume string
	// ClientConfigTarget is the container path the agent expects.
	ClientConfigTarget string
	// InvitationSecretName is the Compose secret containing the pairing
	// invitation for the init container.
	InvitationSecretName string
	// InvitationSecretFile is the host path (relative to the project directory)
	// that holds the pairing invitation.
	InvitationSecretFile string
	// Networks lists Compose networks the init service should join.
	Networks []string
	// Labels are applied to the shared volume for later removal.
	VolumeLabels map[string]string
}

// Validate rejects unsafe options.
func (options OverrideOptions) Validate() error {
	if !composeServiceNamePattern.MatchString(options.AgentService) {
		return errors.New("agent service name is invalid")
	}
	if options.ProjectName != "" && !composeProjectNamePattern.MatchString(options.ProjectName) {
		return errors.New("compose project name is invalid")
	}
	if err := VerifyPinnedImage(options.InitImage); err != nil {
		return err
	}
	if !isValidVolumeName(options.SharedVolume) {
		return errors.New("shared volume name is invalid")
	}
	if !isValidContainerPath(options.ClientConfigTarget) {
		return errors.New("client config target path is invalid")
	}
	if !isValidComposeName(options.InvitationSecretName) {
		return errors.New("invitation secret name is invalid")
	}
	if !isValidRelativePath(options.InvitationSecretFile) {
		return errors.New("invitation secret file path is invalid")
	}
	for _, network := range options.Networks {
		if !composeServiceNamePattern.MatchString(network) {
			return errors.New("network name is invalid")
		}
	}
	return nil
}

// BuildAgentOverride returns the closed override for an agent Compose project.
func BuildAgentOverride(options OverrideOptions) (*AgentOverride, error) {
	if err := options.Validate(); err != nil {
		return nil, err
	}
	override := &AgentOverride{
		APIVersion:   OverrideAPIVersion,
		ProjectName:  options.ProjectName,
		AgentService: options.AgentService,
		InitService: InitService{
			Image:        options.InitImage,
			Command:      append([]string(nil), options.InitCommand...),
			Volumes:      []OverrideMount{{Type: "volume", Source: options.SharedVolume, Target: options.ClientConfigTarget}},
			Secrets:      []string{options.InvitationSecretName},
			Networks:     append([]string(nil), options.Networks...),
			Restart:      "no",
			RunOnce:      true,
			StopGrace:    "5s",
			ReadOnlyRoot: true,
			User:         "10001:10001",
		},
		SharedVolumes: []SharedVolume{{Name: options.SharedVolume, Labels: options.VolumeLabels}},
		SecretFiles:   []SecretFile{{Name: options.InvitationSecretName, File: options.InvitationSecretFile}},
		Networks:      append([]string(nil), options.Networks...),
	}
	if err := CheckOverrideServices(override); err != nil {
		return nil, err
	}
	return override, nil
}

var (
	volumeNamePattern    = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9_-]{0,62}[a-z0-9])?$`)
	composeNamePattern   = regexp.MustCompile(`^[a-zA-Z0-9](?:[a-zA-Z0-9._-]{0,62}[a-zA-Z0-9])?$`)
	relativePathPattern  = regexp.MustCompile(`^[a-zA-Z0-9._-]+(?:/[a-zA-Z0-9._-]+)*$`)
	containerPathPattern = regexp.MustCompile(`^/[a-zA-Z0-9](?:/?[a-zA-Z0-9._-])*$`)
)

func isValidVolumeName(value string) bool {
	return len(value) <= 64 && volumeNamePattern.MatchString(value)
}

func isValidComposeName(value string) bool {
	return len(value) <= 64 && composeNamePattern.MatchString(value)
}

func isValidRelativePath(value string) bool {
	return len(value) <= 256 && relativePathPattern.MatchString(value) && !strings.Contains(value, "..")
}

func isValidContainerPath(value string) bool {
	return len(value) <= 256 && containerPathPattern.MatchString(value) && !strings.Contains(value, "..")
}

// Render serializes the override to a deterministic Compose YAML document.
// Field order is fixed, keys and lists are sorted where Compose is
// order-insensitive. Two calls with the same input produce byte-identical
// output.
func (override *AgentOverride) Render() ([]byte, error) {
	if override.APIVersion != OverrideAPIVersion {
		return nil, errors.New("override API version is invalid")
	}
	var builder strings.Builder
	fmt.Fprintf(&builder, "# %s — generated by unYOLO. Edit installation.json instead.\n", override.APIVersion)
	if override.ProjectName != "" {
		fmt.Fprintf(&builder, "name: %s\n", override.ProjectName)
	}
	renderServices(&builder, override)
	renderVolumes(&builder, override)
	renderSecrets(&builder, override)
	renderNetworks(&builder, override)
	return []byte(builder.String()), nil
}

func renderServices(builder *strings.Builder, override *AgentOverride) {
	builder.WriteString("services:\n")
	// Existing agent service depends on the init service completing.
	fmt.Fprintf(builder, "  %s:\n", override.AgentService)
	builder.WriteString("    depends_on:\n")
	fmt.Fprintf(builder, "      %s:\n", InitServiceName)
	builder.WriteString("        condition: service_completed_successfully\n")
	if len(override.SharedVolumes) > 0 {
		builder.WriteString("    volumes:\n")
		for _, mount := range override.InitService.Volumes {
			fmt.Fprintf(builder, "      - type: %s\n", mount.Type)
			fmt.Fprintf(builder, "        source: %s\n", mount.Source)
			fmt.Fprintf(builder, "        target: %s\n", mount.Target)
			builder.WriteString("        read_only: true\n")
		}
	}
	// Init service definition.
	fmt.Fprintf(builder, "  %s:\n", InitServiceName)
	fmt.Fprintf(builder, "    image: %s\n", override.InitService.Image)
	fmt.Fprintf(builder, "    restart: %s\n", override.InitService.Restart)
	fmt.Fprintf(builder, "    user: %q\n", override.InitService.User)
	builder.WriteString("    read_only: true\n")
	builder.WriteString("    stop_grace_period: " + override.InitService.StopGrace + "\n")
	builder.WriteString("    cap_drop:\n      - ALL\n")
	builder.WriteString("    security_opt:\n      - no-new-privileges:true\n")
	if len(override.InitService.Command) > 0 {
		builder.WriteString("    command:\n")
		for _, arg := range override.InitService.Command {
			fmt.Fprintf(builder, "      - %q\n", arg)
		}
	}
	if len(override.InitService.Environment) > 0 {
		sorted := append([]EnvironmentEntry(nil), override.InitService.Environment...)
		sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })
		builder.WriteString("    environment:\n")
		for _, entry := range sorted {
			fmt.Fprintf(builder, "      %s: %q\n", entry.Name, entry.Value)
		}
	}
	if len(override.InitService.Volumes) > 0 {
		builder.WriteString("    volumes:\n")
		for _, mount := range override.InitService.Volumes {
			fmt.Fprintf(builder, "      - type: %s\n", mount.Type)
			fmt.Fprintf(builder, "        source: %s\n", mount.Source)
			fmt.Fprintf(builder, "        target: %s\n", mount.Target)
			if mount.ReadOnly {
				builder.WriteString("        read_only: true\n")
			}
		}
	}
	if len(override.InitService.Secrets) > 0 {
		sorted := append([]string(nil), override.InitService.Secrets...)
		sort.Strings(sorted)
		builder.WriteString("    secrets:\n")
		for _, name := range sorted {
			fmt.Fprintf(builder, "      - %s\n", name)
		}
	}
	if len(override.InitService.Networks) > 0 {
		sorted := append([]string(nil), override.InitService.Networks...)
		sort.Strings(sorted)
		builder.WriteString("    networks:\n")
		for _, name := range sorted {
			fmt.Fprintf(builder, "      - %s\n", name)
		}
	}
}

func renderVolumes(builder *strings.Builder, override *AgentOverride) {
	if len(override.SharedVolumes) == 0 {
		return
	}
	sorted := append([]SharedVolume(nil), override.SharedVolumes...)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })
	builder.WriteString("volumes:\n")
	for _, volume := range sorted {
		fmt.Fprintf(builder, "  %s:\n", volume.Name)
		if len(volume.Labels) > 0 {
			builder.WriteString("    labels:\n")
			names := make([]string, 0, len(volume.Labels))
			for name := range volume.Labels {
				names = append(names, name)
			}
			sort.Strings(names)
			for _, name := range names {
				fmt.Fprintf(builder, "      %s: %q\n", name, volume.Labels[name])
			}
		}
	}
}

func renderSecrets(builder *strings.Builder, override *AgentOverride) {
	if len(override.SecretFiles) == 0 {
		return
	}
	sorted := append([]SecretFile(nil), override.SecretFiles...)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })
	builder.WriteString("secrets:\n")
	for _, secret := range sorted {
		fmt.Fprintf(builder, "  %s:\n", secret.Name)
		fmt.Fprintf(builder, "    file: %s\n", secret.File)
	}
}

func renderNetworks(builder *strings.Builder, override *AgentOverride) {
	if len(override.Networks) == 0 {
		return
	}
	sorted := append([]string(nil), override.Networks...)
	sort.Strings(sorted)
	builder.WriteString("networks:\n")
	for _, name := range sorted {
		fmt.Fprintf(builder, "  %s:\n", name)
		builder.WriteString("    external: true\n")
	}
}
