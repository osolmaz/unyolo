package hubclient

import (
	"errors"
	"regexp"
	"strings"
	"unicode/utf8"
)

const (
	SandboxServerPort       = 49983
	SandboxMaxLifetimeSecs  = 24 * 60 * 60
	SandboxMaxCommandOutput = 512 * 1024
)

var sandboxIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)

type SandboxRef struct {
	Namespace string `json:"namespace"`
	JobID     string `json:"job_id"`
	LocalID   string `json:"local_id,omitempty"`
}

func (r SandboxRef) Validate() error {
	if !ValidNamespaceSegment(r.Namespace) || !sandboxIDPattern.MatchString(r.JobID) ||
		r.LocalID != "" && !sandboxIDPattern.MatchString(r.LocalID) {
		return errors.New("hubclient: sandbox reference is invalid")
	}
	return nil
}

func (r SandboxRef) ID() string {
	if r.LocalID == "" {
		return r.JobID
	}
	return r.JobID + "." + r.LocalID
}

type SandboxPoolRef struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
}

func (r SandboxPoolRef) Validate() error {
	return validateNamedResource(r.Namespace, r.Name, "hubclient: sandbox pool reference is invalid")
}

type SandboxVolume struct {
	Type      string `json:"type"`
	Source    string `json:"source"`
	MountPath string `json:"mountPath"`
	Revision  string `json:"revision,omitempty"`
	ReadOnly  *bool  `json:"readOnly,omitempty"`
	Path      string `json:"path,omitempty"`
}

func (v SandboxVolume) validate() error {
	parts := strings.Split(v.Source, "/")
	if !validSandboxVolumeType(v.Type) || !validSandboxVolumeSource(parts) ||
		!validSandboxVolumeMount(v.MountPath) || !validSandboxVolumeSubpath(v.Revision, v.Path) {
		return errors.New("hubclient: sandbox volume is invalid")
	}
	return nil
}

func validSandboxVolumeType(value string) bool {
	return value == "bucket" || value == "model" || value == "dataset" || value == "space"
}

func validSandboxVolumeSource(parts []string) bool {
	return len(parts) == 2 && ValidNamespaceSegment(parts[0]) && ValidNamespaceSegment(parts[1])
}

func validSandboxVolumeMount(value string) bool {
	return validSandboxPath(value) && strings.HasPrefix(value, "/")
}

func validSandboxVolumeSubpath(revision, path string) bool {
	return len(revision) <= 200 && len(path) <= 1024 && !strings.ContainsRune(path, 0)
}

func ValidateSandboxVolume(volume SandboxVolume) error { return volume.validate() }

type SandboxCreateSpec struct {
	Namespace          string
	Name               string
	OperationID        string
	Image              string
	Flavor             string
	IdleTimeoutSeconds *int
	Environment        map[string]string
	Secrets            map[string]string
	Volumes            []SandboxVolume
}

type SandboxPoolSpec struct {
	Ref                SandboxPoolRef
	OperationID        string
	Image              string
	Flavor             string
	SandboxesPerHost   int
	MaxHosts           int
	IdleTimeoutSeconds *int
}

type SandboxState struct {
	Ref                SandboxRef        `json:"ref"`
	Image              string            `json:"image"`
	Flavor             string            `json:"flavor"`
	Stage              string            `json:"stage"`
	Mode               string            `json:"mode"`
	Pool               string            `json:"pool,omitempty"`
	Environment        map[string]string `json:"environment,omitempty"`
	Capacity           int               `json:"capacity,omitempty"`
	MaxHosts           int               `json:"max_hosts,omitempty"`
	IdleTimeoutSeconds *int              `json:"idle_timeout_seconds,omitempty"`
}

type SandboxFileInfo struct {
	Name    string `json:"name"`
	Path    string `json:"path"`
	Type    string `json:"type"`
	Size    int64  `json:"size"`
	MTimeMS *int64 `json:"mtime_ms,omitempty"`
	Mode    string `json:"mode"`
}

type SandboxProcess struct {
	PID         int    `json:"pid"`
	Command     any    `json:"cmd"`
	Tag         string `json:"tag,omitempty"`
	StartedAtMS *int64 `json:"started_at_ms,omitempty"`
	Running     bool   `json:"running"`
	ExitCode    *int   `json:"exit_code,omitempty"`
}

func validSandboxPath(value string) bool {
	return value != "" && len(value) <= 4096 && utf8.ValidString(value) && !strings.ContainsRune(value, 0)
}
