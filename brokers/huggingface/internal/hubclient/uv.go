package hubclient

import (
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"

	"github.com/osolmaz/brokerkit/internal/strictjson"
)

const defaultUVImage = "ghcr.io/astral-sh/uv:python3.12-bookworm"

type uvJobArguments struct {
	Script         string            `json:"script"`
	ScriptArgs     []string          `json:"script_args,omitempty"`
	Dependencies   []string          `json:"dependencies,omitempty"`
	Python         string            `json:"python,omitempty"`
	Image          string            `json:"image,omitempty"`
	Environment    map[string]string `json:"environment,omitempty"`
	Secrets        map[string]string `json:"secrets,omitempty"`
	Flavor         string            `json:"flavor,omitempty"`
	TimeoutSeconds int               `json:"timeout_seconds,omitempty"`
	Labels         map[string]string `json:"labels,omitempty"`
	Volumes        []uvVolume        `json:"volumes,omitempty"`
	Expose         []int             `json:"expose,omitempty"`
	SSH            bool              `json:"ssh,omitempty"`
	Schedule       string            `json:"schedule,omitempty"`
	Suspend        *bool             `json:"suspend,omitempty"`
	Concurrency    *bool             `json:"concurrency,omitempty"`
}

type uvVolume struct {
	Type      string `json:"type"`
	Source    string `json:"source"`
	MountPath string `json:"mount_path"`
	Revision  string `json:"revision,omitempty"`
	ReadOnly  *bool  `json:"read_only,omitempty"`
	Path      string `json:"path,omitempty"`
}

//nolint:cyclop // Fixed transform dispatch is explicit and tracked by the exact HF CRAP baseline.
func transformBoundBody(transform string, raw json.RawMessage) (any, error) {
	var arguments uvJobArguments
	if err := strictjson.Decode(raw, &arguments, true); err != nil || arguments.Script == "" {
		return nil, errors.New("hubclient: UV Job arguments are invalid")
	}
	if localUVInput(arguments.Script) {
		return nil, errors.New("hubclient: UV Job local files require a prior explicit upload operation")
	}
	for _, argument := range arguments.ScriptArgs {
		if localUVInput(argument) {
			return nil, errors.New("hubclient: UV Job local files require a prior explicit upload operation")
		}
	}
	job := uvJobSpec(arguments)
	switch transform {
	case "uv_job":
		if arguments.Schedule != "" || arguments.Suspend != nil || arguments.Concurrency != nil {
			return nil, errors.New("hubclient: UV Job schedule fields are invalid")
		}
		return job, nil
	case "uv_scheduled_job":
		if arguments.Schedule == "" || arguments.SSH {
			return nil, errors.New("hubclient: scheduled UV Job arguments are invalid")
		}
		body := map[string]any{"jobSpec": job, "schedule": arguments.Schedule}
		if arguments.Suspend != nil {
			body["suspend"] = *arguments.Suspend
		}
		if arguments.Concurrency != nil {
			body["concurrency"] = *arguments.Concurrency
		}
		return body, nil
	default:
		return nil, errors.New("hubclient: bound transform is unavailable")
	}
}

//nolint:cyclop // Optional SDK fields are explicit and tracked by the exact HF CRAP baseline.
func uvJobSpec(arguments uvJobArguments) map[string]any {
	command := []string{"uv", "run"}
	for _, dependency := range arguments.Dependencies {
		command = append(command, "--with", dependency)
	}
	if arguments.Python != "" {
		command = append(command, "--python", arguments.Python)
	}
	command = append(command, arguments.Script)
	command = append(command, arguments.ScriptArgs...)
	flavor := arguments.Flavor
	if flavor == "" {
		flavor = "cpu-basic"
	}
	job := map[string]any{"command": command, "arguments": []string{}, "environment": nonNilMap(arguments.Environment), "flavor": flavor}
	image := arguments.Image
	if image == "" {
		image = defaultUVImage
	}
	if space, ok := spaceImageID(image); ok {
		job["spaceId"] = space
	} else {
		job["dockerImage"] = image
	}
	if len(arguments.Secrets) > 0 {
		job["secrets"] = arguments.Secrets
	}
	if arguments.TimeoutSeconds > 0 {
		job["timeoutSeconds"] = arguments.TimeoutSeconds
	}
	if len(arguments.Labels) > 0 {
		job["labels"] = arguments.Labels
	}
	if len(arguments.Volumes) > 0 {
		job["volumes"] = uvVolumes(arguments.Volumes)
	}
	if len(arguments.Expose) > 0 {
		job["expose"] = map[string]any{"ports": arguments.Expose}
	}
	if arguments.SSH {
		job["ssh"] = map[string]any{"enabled": true}
	}
	return job
}

func uvVolumes(values []uvVolume) []map[string]any {
	result := make([]map[string]any, 0, len(values))
	for _, value := range values {
		volume := map[string]any{"type": value.Type, "source": value.Source, "mountPath": value.MountPath}
		if value.Revision != "" {
			volume["revision"] = value.Revision
		}
		if value.ReadOnly != nil {
			volume["readOnly"] = *value.ReadOnly
		}
		if value.Path != "" {
			volume["path"] = value.Path
		}
		result = append(result, volume)
	}
	return result
}

func localUVInput(value string) bool {
	if strings.HasPrefix(value, "https://") || strings.HasPrefix(value, "http://") {
		return false
	}
	switch strings.ToLower(filepath.Ext(value)) {
	case ".py", ".sh", ".yaml", ".yml", ".toml":
		return true
	default:
		return false
	}
}

func spaceImageID(image string) (string, bool) {
	for _, prefix := range []string{"https://huggingface.co/spaces/", "https://hf.co/spaces/", "huggingface.co/spaces/", "hf.co/spaces/"} {
		if strings.HasPrefix(image, prefix) && len(image) > len(prefix) {
			return image[len(prefix):], true
		}
	}
	return "", false
}

func nonNilMap(value map[string]string) map[string]string {
	if len(value) != 0 {
		return value
	}
	return make(map[string]string)
}
