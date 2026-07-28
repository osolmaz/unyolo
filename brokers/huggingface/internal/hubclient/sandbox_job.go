package hubclient

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

const (
	sandboxLabel      = "hf-sandbox"
	sandboxModeLabel  = "hf-sandbox-mode"
	sandboxPoolLabel  = "hf-sandbox-pool"
	sandboxNonceLabel = "hf-sandbox-nonce"
	operationLabel    = "unyolo-operation"
	sandboxNameLabel  = "unyolo-sandbox-name"
	modeDedicated     = "dedicated"
	modePool          = "pool"
	sandboxMountPath  = "/.hf-sbx-server"
)

const sandboxBootstrap = `set -eu
d=/tmp/.sbx-server
cp "$SBX_SERVER_MOUNT/sbx-server" "$d"
chmod +x "$d"
unset SBX_SERVER_MOUNT
exec "$d"`

var environmentKeyPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,127}$`)

var jobHardware = map[string]bool{
	"cpu-basic": true, "cpu-upgrade": true, "cpu-performance": true, "cpu-xl": true,
	"t4-small": true, "t4-medium": true, "l4x1": true, "l4x4": true,
	"l40sx1": true, "l40sx4": true, "l40sx8": true,
	"a10g-small": true, "a10g-large": true, "a10g-largex2": true, "a10g-largex4": true,
	"a100-large": true, "a100x4": true, "a100x8": true,
	"h200": true, "h200x2": true, "h200x4": true, "h200x8": true,
	"rtx-pro-6000": true, "rtx-pro-6000x2": true, "rtx-pro-6000x4": true, "rtx-pro-6000x8": true,
}

type sandboxJobWire struct {
	ID          string            `json:"id"`
	DockerImage string            `json:"dockerImage"`
	SpaceID     string            `json:"spaceId"`
	Environment map[string]any    `json:"environment"`
	Flavor      string            `json:"flavor"`
	Labels      map[string]string `json:"labels"`
	Status      struct {
		Stage      string   `json:"stage"`
		ExposeURLs []string `json:"exposeUrls"`
	} `json:"status"`
	Owner struct {
		Name string `json:"name"`
	} `json:"owner"`
}

type sandboxJobBody struct {
	Command        []string          `json:"command"`
	Arguments      []string          `json:"arguments"`
	Environment    map[string]string `json:"environment"`
	Secrets        map[string]string `json:"secrets"`
	Flavor         string            `json:"flavor"`
	TimeoutSeconds int               `json:"timeoutSeconds"`
	Labels         map[string]string `json:"labels"`
	Volumes        []SandboxVolume   `json:"volumes"`
	Expose         struct {
		Ports []int `json:"ports"`
	} `json:"expose"`
	DockerImage string `json:"dockerImage,omitempty"`
	SpaceID     string `json:"spaceId,omitempty"`
}

func (c *Client) CreateSandbox(ctx context.Context, spec SandboxCreateSpec) (SandboxState, error) {
	if err := validateSandboxCreateSpec(spec); err != nil {
		return SandboxState{}, err
	}
	body, err := c.sandboxJobBody(spec.Image, spec.Flavor, spec.IdleTimeoutSeconds, spec.Environment, spec.Secrets, spec.Volumes,
		map[string]string{sandboxLabel: "1", sandboxModeLabel: modeDedicated, operationLabel: spec.OperationID, sandboxNameLabel: spec.Name}, 0, 0)
	if err != nil {
		return SandboxState{}, err
	}
	return c.createSandboxJob(ctx, spec.Namespace, body)
}

func (c *Client) CreateSandboxPoolHost(ctx context.Context, spec SandboxPoolSpec) (SandboxState, error) {
	if err := validateSandboxPoolSpec(spec); err != nil {
		return SandboxState{}, err
	}
	body, err := c.sandboxJobBody(spec.Image, spec.Flavor, spec.IdleTimeoutSeconds, nil, nil, nil,
		map[string]string{sandboxLabel: "1", sandboxModeLabel: modePool, sandboxPoolLabel: spec.Ref.Name, operationLabel: spec.OperationID},
		spec.SandboxesPerHost, spec.MaxHosts)
	if err != nil {
		return SandboxState{}, err
	}
	return c.createSandboxJob(ctx, spec.Ref.Namespace, body)
}

func (c *Client) createSandboxJob(ctx context.Context, namespace string, body sandboxJobBody) (SandboxState, error) {
	var job sandboxJobWire
	if err := c.call(ctx, callSpec{method: http.MethodPost, path: "/api/jobs/" + url.PathEscape(namespace), body: body, out: &job}); err != nil {
		return SandboxState{}, err
	}
	state, err := sandboxStateFromJob(job, namespace, "")
	if err != nil {
		return SandboxState{}, &Error{Code: CodeResultUnknown, StatusCode: http.StatusOK, Ambiguous: true}
	}
	return state, nil
}

func (c *Client) SandboxState(ctx context.Context, ref SandboxRef) (SandboxState, error) {
	job, err := c.inspectSandboxJob(ctx, ref.Namespace, ref.JobID)
	if err != nil {
		return SandboxState{}, err
	}
	state, err := sandboxStateFromJob(job, ref.Namespace, ref.LocalID)
	if err != nil {
		return SandboxState{}, err
	}
	if ref.LocalID != "" {
		endpoint, endpointErr := c.sandboxEndpoint(job, ref)
		if endpointErr != nil {
			return SandboxState{}, endpointErr
		}
		var sandboxes []struct {
			ID string `json:"id"`
		}
		if endpointErr = c.sandboxServerJSON(ctx, endpoint, http.MethodGet, "/v1/sandboxes", nil, nil, &sandboxes, c.maxResponseBytes); endpointErr != nil {
			return SandboxState{}, endpointErr
		}
		if !slices.ContainsFunc(sandboxes, func(item struct {
			ID string `json:"id"`
		}) bool {
			return item.ID == ref.LocalID
		}) {
			return SandboxState{}, &Error{Code: CodeNotFound, StatusCode: http.StatusNotFound}
		}
	}
	return state, nil
}

func (c *Client) ListSandboxPool(ctx context.Context, ref SandboxPoolRef) ([]SandboxState, error) {
	if err := ref.Validate(); err != nil {
		return nil, err
	}
	query := url.Values{}
	query.Add("stage", "RUNNING")
	query.Add("stage", "SCHEDULING")
	query.Add("label", sandboxLabel+"=1")
	query.Add("label", sandboxModeLabel+"="+modePool)
	query.Add("label", sandboxPoolLabel+"="+ref.Name)
	var jobs []sandboxJobWire
	if err := c.call(ctx, callSpec{method: http.MethodGet, path: "/api/jobs/" + url.PathEscape(ref.Namespace), query: query, out: &jobs}); err != nil {
		return nil, err
	}
	states := make([]SandboxState, 0, len(jobs))
	for _, job := range jobs {
		state, err := sandboxStateFromJob(job, ref.Namespace, "")
		if err != nil || state.Mode != modePool || state.Pool != ref.Name {
			return nil, &Error{Code: CodeResponseInvalid, StatusCode: http.StatusOK}
		}
		states = append(states, state)
	}
	slices.SortFunc(states, func(left, right SandboxState) int { return strings.Compare(left.Ref.JobID, right.Ref.JobID) })
	return states, nil
}

func (c *Client) ListSandboxesByOperation(ctx context.Context, namespace, operationID string) ([]SandboxState, error) {
	if !ValidNamespaceSegment(namespace) || !sandboxIDPattern.MatchString(operationID) {
		return nil, errors.New("hubclient: sandbox operation lookup is invalid")
	}
	query := url.Values{}
	query.Add("label", sandboxLabel+"=1")
	query.Add("label", operationLabel+"="+operationID)
	var jobs []sandboxJobWire
	if err := c.call(ctx, callSpec{method: http.MethodGet, path: "/api/jobs/" + url.PathEscape(namespace), query: query, out: &jobs}); err != nil {
		return nil, err
	}
	return sandboxStatesForOperation(jobs, namespace, operationID)
}

func sandboxStatesForOperation(jobs []sandboxJobWire, namespace, operationID string) ([]SandboxState, error) {
	states := make([]SandboxState, 0, len(jobs))
	for _, job := range jobs {
		state, err := sandboxStateFromJob(job, namespace, "")
		if err != nil || job.Labels[operationLabel] != operationID {
			return nil, &Error{Code: CodeResponseInvalid, StatusCode: http.StatusOK}
		}
		states = append(states, state)
	}
	slices.SortFunc(states, func(left, right SandboxState) int { return strings.Compare(left.Ref.JobID, right.Ref.JobID) })
	return states, nil
}

func (c *Client) CancelSandboxJob(ctx context.Context, ref SandboxRef) error {
	if err := ref.Validate(); err != nil || ref.LocalID != "" {
		return errors.New("hubclient: dedicated sandbox reference is invalid")
	}
	return c.call(ctx, callSpec{method: http.MethodPost, path: "/api/jobs/" + url.PathEscape(ref.Namespace) + "/" + url.PathEscape(ref.JobID) + "/cancel"})
}

func (c *Client) inspectSandboxJob(ctx context.Context, namespace, jobID string) (sandboxJobWire, error) {
	ref := SandboxRef{Namespace: namespace, JobID: jobID}
	if err := ref.Validate(); err != nil {
		return sandboxJobWire{}, err
	}
	var job sandboxJobWire
	path := "/api/jobs/" + url.PathEscape(namespace) + "/" + url.PathEscape(jobID)
	if err := c.call(ctx, callSpec{method: http.MethodGet, path: path, out: &job}); err != nil {
		return sandboxJobWire{}, err
	}
	if job.ID != jobID || job.Owner.Name != namespace {
		return sandboxJobWire{}, &Error{Code: CodeResponseInvalid, StatusCode: http.StatusOK}
	}
	return job, nil
}

func (c *Client) sandboxJobBody(image, flavor string, idle *int, environment, secrets map[string]string, volumes []SandboxVolume, labels map[string]string, capacity, maxHosts int) (sandboxJobBody, error) {
	if err := validateSandboxJobConfig(image, flavor, environment, secrets, volumes); err != nil {
		return sandboxJobBody{}, err
	}
	nonce, err := randomHex(16)
	if err != nil {
		return sandboxJobBody{}, errors.New("hubclient: sandbox nonce generation failed")
	}
	env, secretValues, err := c.sandboxJobEnvironment(environment, secrets, idle, capacity, maxHosts, nonce)
	if err != nil {
		return sandboxJobBody{}, err
	}
	return sandboxJobBodyForImage(image, flavor, env, secretValues, labels, nonce, volumes), nil
}

func validateSandboxJobConfig(image, flavor string, environment, secrets map[string]string, volumes []SandboxVolume) error {
	if !validSandboxJobBasics(image, flavor, volumes) || validateSandboxEnvironment(environment, false) != nil ||
		validateSandboxEnvironment(secrets, true) != nil {
		return errors.New("hubclient: sandbox job configuration is invalid")
	}
	return validateSandboxVolumes(volumes)
}

func validSandboxJobBasics(image, flavor string, volumes []SandboxVolume) bool {
	return validSandboxImage(image) && jobHardware[flavor] && len(volumes) <= 32
}

func validateSandboxVolumes(volumes []SandboxVolume) error {
	for _, volume := range volumes {
		if err := volume.validate(); err != nil {
			return err
		}
	}
	return nil
}

func (c *Client) sandboxJobEnvironment(environment, secrets map[string]string, idle *int, capacity, maxHosts int, nonce string) (map[string]string, map[string]string, error) {
	sandboxToken := c.deriveSandboxToken(nonce)
	env := cloneStrings(environment)
	secretValues := cloneStrings(secrets)
	for _, value := range secretValues {
		if value == c.token {
			return nil, nil, errors.New("hubclient: broker credential cannot be forwarded to a sandbox")
		}
	}
	env["SBX_PORT"] = fmt.Sprint(SandboxServerPort)
	env["SBX_SERVER_MOUNT"] = sandboxMountPath
	if idle != nil {
		env["SBX_IDLE_TIMEOUT"] = fmt.Sprint(*idle)
	}
	if capacity > 0 {
		env["SBX_HOST_MODE"] = "1"
		env["SBX_CAPACITY"] = fmt.Sprint(capacity)
	}
	if maxHosts > 0 {
		env["SBX_MAX_HOSTS"] = fmt.Sprint(maxHosts)
	}
	secretValues["SBX_TOKEN"] = sandboxToken
	return env, secretValues, nil
}

func sandboxJobBodyForImage(image, flavor string, env, secretValues, labels map[string]string, nonce string, volumes []SandboxVolume) sandboxJobBody {
	labels = cloneStrings(labels)
	labels[sandboxNonceLabel] = nonce
	serverVolume := SandboxVolume{Type: "bucket", Source: "huggingface/sbx-server", MountPath: sandboxMountPath}
	readOnly := true
	serverVolume.ReadOnly = &readOnly
	body := sandboxJobBody{Command: []string{"/bin/sh", "-c", sandboxBootstrap}, Arguments: []string{}, Environment: env,
		Secrets: secretValues, Flavor: flavor, TimeoutSeconds: SandboxMaxLifetimeSecs, Labels: labels,
		Volumes: append(slices.Clone(volumes), serverVolume)}
	body.Expose.Ports = []int{SandboxServerPort}
	for _, prefix := range []string{"https://huggingface.co/spaces/", "https://hf.co/spaces/", "huggingface.co/spaces/", "hf.co/spaces/"} {
		if strings.HasPrefix(image, prefix) {
			body.SpaceID = strings.TrimPrefix(image, prefix)
			return body
		}
	}
	body.DockerImage = image
	return body
}

func validateSandboxCreateSpec(spec SandboxCreateSpec) error {
	if !ValidNamespaceSegment(spec.Namespace) || !ValidNamespaceSegment(spec.Name) || !sandboxIDPattern.MatchString(spec.OperationID) ||
		!validIdleTimeout(spec.IdleTimeoutSeconds) {
		return errors.New("hubclient: sandbox create specification is invalid")
	}
	return nil
}

func validateSandboxPoolSpec(spec SandboxPoolSpec) error {
	if err := spec.Ref.Validate(); err != nil {
		return err
	}
	if !validSandboxPoolCapacity(spec) || !sandboxIDPattern.MatchString(spec.OperationID) || !validIdleTimeout(spec.IdleTimeoutSeconds) {
		return errors.New("hubclient: sandbox pool specification is invalid")
	}
	return nil
}

func validSandboxPoolCapacity(spec SandboxPoolSpec) bool {
	return spec.SandboxesPerHost >= 1 &&
		spec.SandboxesPerHost <= 500 &&
		spec.MaxHosts >= 0 &&
		spec.MaxHosts <= 32
}

func validIdleTimeout(value *int) bool {
	return value == nil || *value >= 30 && *value <= SandboxMaxLifetimeSecs
}

func validSandboxImage(value string) bool {
	return value != "" && len(value) <= 512 && !strings.ContainsAny(value, "\x00\r\n\t ")
}

func ValidSandboxImage(value string) bool { return validSandboxImage(value) }

func ValidJobHardware(value string) bool { return jobHardware[value] }

func validateSandboxEnvironment(values map[string]string, secret bool) error {
	if len(values) > 128 {
		return errors.New("hubclient: sandbox environment is too large")
	}
	for key, value := range values {
		if !validSandboxEnvironmentEntry(key, value) {
			return errors.New("hubclient: sandbox environment is invalid")
		}
		if !secret && key == "HF_TOKEN" {
			return errors.New("hubclient: HF_TOKEN must be supplied through sealed secrets")
		}
	}
	return nil
}

func validSandboxEnvironmentEntry(key, value string) bool {
	return environmentKeyPattern.MatchString(key) &&
		!strings.HasPrefix(key, "SBX_") &&
		len(value) <= 64*1024 &&
		!strings.ContainsRune(value, 0)
}

func sandboxStateFromJob(job sandboxJobWire, namespace, localID string) (SandboxState, error) {
	mode := job.Labels[sandboxModeLabel]
	ref := SandboxRef{Namespace: namespace, JobID: job.ID, LocalID: localID}
	if !validSandboxJobState(job, ref, namespace, localID, mode) {
		return SandboxState{}, &Error{Code: CodeResponseInvalid, StatusCode: http.StatusOK}
	}
	capacity, maxHosts, idleValue, err := sandboxStateCapacity(job.Environment, mode)
	if err != nil {
		return SandboxState{}, &Error{Code: CodeResponseInvalid, StatusCode: http.StatusOK}
	}
	var idleTimeout *int
	if _, found := job.Environment["SBX_IDLE_TIMEOUT"]; found {
		idleTimeout = &idleValue
	}
	return SandboxState{Ref: SandboxRef{Namespace: namespace, JobID: job.ID, LocalID: localID}, Image: firstNonempty(job.DockerImage, job.SpaceID),
		Flavor: job.Flavor, Stage: job.Status.Stage, Mode: mode, Pool: job.Labels[sandboxPoolLabel], Environment: sandboxUserEnvironment(job.Environment),
		Capacity: capacity, MaxHosts: maxHosts, IdleTimeoutSeconds: idleTimeout}, nil
}

func validSandboxJobState(job sandboxJobWire, ref SandboxRef, namespace, localID, mode string) bool {
	return validSandboxJobIdentity(job, ref, namespace) &&
		validSandboxJobMode(job, localID, mode) &&
		validSandboxJobRuntime(job, mode)
}

func validSandboxJobIdentity(job sandboxJobWire, ref SandboxRef, namespace string) bool {
	return ref.Validate() == nil &&
		job.Owner.Name == namespace &&
		job.Labels[sandboxLabel] == "1"
}

func validSandboxJobMode(job sandboxJobWire, localID, mode string) bool {
	return (mode == modeDedicated || mode == modePool) &&
		job.Labels[sandboxNonceLabel] != "" &&
		(localID == "" || mode == modePool) &&
		(mode != modePool || ValidNamespaceSegment(job.Labels[sandboxPoolLabel]))
}

func validSandboxJobRuntime(job sandboxJobWire, mode string) bool {
	return validSandboxImage(firstNonempty(job.DockerImage, job.SpaceID)) &&
		jobHardware[job.Flavor] &&
		validSandboxStage(job.Status.Stage) &&
		(mode != modePool || ValidNamespaceSegment(job.Labels[sandboxPoolLabel]))
}

func sandboxUserEnvironment(environment map[string]any) map[string]string {
	result := make(map[string]string)
	for key, value := range environment {
		if text, ok := value.(string); ok && !strings.HasPrefix(key, "SBX_") {
			result[key] = text
		}
	}
	return result
}

func sandboxStateCapacity(environment map[string]any, mode string) (int, int, int, error) {
	capacity, capacityOK := optionalEnvironmentInt(environment, "SBX_CAPACITY", 1, 500)
	maxHosts, maxHostsOK := optionalEnvironmentInt(environment, "SBX_MAX_HOSTS", 1, 32)
	idleValue, idleOK := optionalEnvironmentInt(environment, "SBX_IDLE_TIMEOUT", 30, SandboxMaxLifetimeSecs)
	if mode == modePool && (capacity == 0 || !capacityOK || !maxHostsOK || !idleOK) {
		return 0, 0, 0, errors.New("invalid sandbox capacity")
	}
	return capacity, maxHosts, idleValue, nil
}

func firstNonempty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func validSandboxStage(stage string) bool {
	switch stage {
	case "COMPLETED", "CANCELED", "ERROR", "DELETED", "SCHEDULING", "RUNNING":
		return true
	default:
		return false
	}
}

func optionalEnvironmentInt(environment map[string]any, key string, minimum, maximum int) (int, bool) {
	value, found := environment[key]
	if !found {
		return 0, true
	}
	text, ok := value.(string)
	if !ok {
		return 0, false
	}
	parsed, err := strconv.Atoi(text)
	return parsed, err == nil && parsed >= minimum && parsed <= maximum
}

func cloneStrings(values map[string]string) map[string]string {
	cloned := make(map[string]string, len(values))
	for key, value := range values {
		cloned[key] = value
	}
	return cloned
}
