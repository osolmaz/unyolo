package container

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

// MaxComposeConfigBytes bounds the docker compose config output that we accept.
const MaxComposeConfigBytes = 4 * 1024 * 1024

var (
	// composeProjectNamePattern accepts Compose project names.
	composeProjectNamePattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9_-]{0,62}[a-z0-9])?$`)
	// composeServiceNamePattern accepts Compose service names.
	composeServiceNamePattern = regexp.MustCompile(`^[a-zA-Z0-9](?:[a-zA-Z0-9._-]{0,62}[a-zA-Z0-9])?$`)
)

// Runner runs docker CLI commands. It exists so tests can inject a fake.
type Runner interface {
	// Run invokes docker with the given arguments and returns stdout and
	// stderr. The command must not need stdin.
	Run(ctx context.Context, workingDirectory string, arguments ...string) (stdout []byte, stderr []byte, err error)
}

// CLIRunner runs the docker binary discovered on PATH.
type CLIRunner struct{}

// Run invokes the docker CLI with the supplied arguments.
func (CLIRunner) Run(ctx context.Context, workingDirectory string, arguments ...string) ([]byte, []byte, error) {
	if len(arguments) == 0 {
		return nil, nil, errors.New("docker command requires at least one argument")
	}
	if workingDirectory == "" || !filepath.IsAbs(workingDirectory) || filepath.Clean(workingDirectory) != workingDirectory {
		return nil, nil, errors.New("docker working directory must be absolute and clean")
	}
	command := exec.CommandContext(ctx, "docker", arguments...) // #nosec G204 -- fixed docker binary; arguments are validated by callers.
	command.Dir = workingDirectory
	// Env inherits from parent so operator-set DOCKER_HOST and PATH work.
	// Callers must ensure no secret is exported to the parent process.
	var stdout, stderr bytes.Buffer
	command.Stdout, command.Stderr = &stdout, &stderr
	err := command.Run()
	return stdout.Bytes(), stderr.Bytes(), err
}

// ProjectInspection is the parsed docker compose config output.
type ProjectInspection struct {
	Name     string
	Services map[string]ServiceInspection
	Raw      map[string]any
}

// ServiceInspection is a subset of a Compose service we validate.
type ServiceInspection struct {
	Image       string
	Volumes     []VolumeMountInspection
	SecurityOpt []string
	Privileged  bool
	PidMode     string
	IpcMode     string
	UserNSMode  string
	NetworkMode string
}

// VolumeMountInspection is a single mount entry parsed from compose config.
type VolumeMountInspection struct {
	Type   string
	Source string
	Target string
}

// ProjectOptions configures Compose project inspection.
type ProjectOptions struct {
	// Directory is the absolute project directory.
	Directory string
	// ProjectName, when nonempty, is passed as `-p`.
	ProjectName string
}

// Validate rejects unsafe project options.
func (options ProjectOptions) Validate() error {
	if options.Directory == "" || !filepath.IsAbs(options.Directory) || filepath.Clean(options.Directory) != options.Directory {
		return errors.New("compose project directory must be absolute and clean")
	}
	if options.ProjectName != "" && !composeProjectNamePattern.MatchString(options.ProjectName) {
		return errors.New("compose project name is invalid")
	}
	return nil
}

// Inspect runs `docker compose config --format json` and parses the result. It
// does not resolve environment overrides beyond what docker itself does; it
// never executes user templates or fetches images.
func Inspect(ctx context.Context, runner Runner, options ProjectOptions) (ProjectInspection, error) {
	if runner == nil {
		runner = CLIRunner{}
	}
	if err := options.Validate(); err != nil {
		return ProjectInspection{}, err
	}
	arguments := []string{"compose"}
	if options.ProjectName != "" {
		arguments = append(arguments, "-p", options.ProjectName)
	}
	arguments = append(arguments, "config", "--format", "json")
	stdout, stderr, err := runner.Run(ctx, options.Directory, arguments...)
	if err != nil {
		return ProjectInspection{}, fmt.Errorf("docker compose config: %w: %s", err, strings.TrimSpace(string(stderr)))
	}
	if len(stdout) > MaxComposeConfigBytes {
		return ProjectInspection{}, errors.New("docker compose config output is too large")
	}
	return parseInspection(stdout)
}

func parseInspection(data []byte) (ProjectInspection, error) {
	var raw map[string]any
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := decoder.Decode(&raw); err != nil {
		return ProjectInspection{}, fmt.Errorf("decode compose config: %w", err)
	}
	name, _ := raw["name"].(string)
	if name != "" && !composeProjectNamePattern.MatchString(name) {
		return ProjectInspection{}, errors.New("compose project name is invalid")
	}
	services, _ := raw["services"].(map[string]any)
	if services == nil {
		return ProjectInspection{}, errors.New("compose project has no services")
	}
	parsed := make(map[string]ServiceInspection, len(services))
	for key, value := range services {
		if !composeServiceNamePattern.MatchString(key) {
			return ProjectInspection{}, fmt.Errorf("compose service %q has an invalid name", key)
		}
		serviceMap, ok := value.(map[string]any)
		if !ok {
			return ProjectInspection{}, fmt.Errorf("compose service %q is malformed", key)
		}
		service, err := parseService(serviceMap)
		if err != nil {
			return ProjectInspection{}, fmt.Errorf("compose service %q: %w", key, err)
		}
		parsed[key] = service
	}
	return ProjectInspection{Name: name, Services: parsed, Raw: raw}, nil
}

func parseService(value map[string]any) (ServiceInspection, error) {
	service := ServiceInspection{}
	if image, ok := value["image"].(string); ok {
		service.Image = image
	}
	if entries, ok := value["volumes"].([]any); ok {
		for index, entry := range entries {
			mount, err := parseMount(entry)
			if err != nil {
				return ServiceInspection{}, fmt.Errorf("volume %d: %w", index, err)
			}
			service.Volumes = append(service.Volumes, mount)
		}
	}
	if entries, ok := value["security_opt"].([]any); ok {
		for _, entry := range entries {
			if text, ok := entry.(string); ok {
				service.SecurityOpt = append(service.SecurityOpt, text)
			}
		}
	}
	if privileged, ok := value["privileged"].(bool); ok {
		service.Privileged = privileged
	}
	if pid, ok := value["pid"].(string); ok {
		service.PidMode = pid
	}
	if ipc, ok := value["ipc"].(string); ok {
		service.IpcMode = ipc
	}
	if userns, ok := value["userns_mode"].(string); ok {
		service.UserNSMode = userns
	}
	if network, ok := value["network_mode"].(string); ok {
		service.NetworkMode = network
	}
	return service, nil
}

func parseMount(entry any) (VolumeMountInspection, error) {
	switch typed := entry.(type) {
	case string:
		return parseMountString(typed)
	case map[string]any:
		mount := VolumeMountInspection{}
		if kind, ok := typed["type"].(string); ok {
			mount.Type = kind
		}
		if source, ok := typed["source"].(string); ok {
			mount.Source = source
		}
		if target, ok := typed["target"].(string); ok {
			mount.Target = target
		}
		return mount, nil
	default:
		return VolumeMountInspection{}, errors.New("mount entry has an unsupported shape")
	}
}

func parseMountString(value string) (VolumeMountInspection, error) {
	parts := strings.Split(value, ":")
	if len(parts) < 2 || len(parts) > 3 {
		return VolumeMountInspection{}, fmt.Errorf("mount string %q is malformed", value)
	}
	source, target := parts[0], parts[1]
	mount := VolumeMountInspection{Source: source, Target: target}
	if strings.HasPrefix(source, "/") || strings.HasPrefix(source, "./") {
		mount.Type = "bind"
	} else {
		mount.Type = "volume"
	}
	return mount, nil
}
